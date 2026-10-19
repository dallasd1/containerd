/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package unpack

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/containerd/errdefs"
	"github.com/containerd/log"
	"github.com/containerd/platforms"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sync/errgroup"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/diff"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/internal/cleanup"
	"github.com/containerd/containerd/v2/internal/kmutex"
	"github.com/containerd/containerd/v2/pkg/labels"
	"github.com/containerd/containerd/v2/pkg/tracing"
)

const (
	labelSnapshotRef    = "containerd.io/snapshot.ref"
	labelSnapshotParent = "containerd.io/snapshot/parent-chain-id"
	labelSnapshotDiffID = "containerd.io/snapshot/diff-id"
	unpackSpanPrefix    = "pkg.unpack.unpacker"
)

// Result returns information about the unpacks which were completed.
type Result struct {
	Unpacks int
}

type unpackerConfig struct {
	platforms []*Platform

	content content.Store

	limiter               Limiter
	duplicationSuppressor KeyedLocker
	unpackLimiter         Limiter
}

// Platform represents a platform-specific unpack configuration which includes
// the platform matcher as well as snapshotter and applier.
type Platform struct {
	Platform platforms.Matcher

	SnapshotterKey          string
	Snapshotter             snapshots.Snapshotter
	SnapshotOpts            []snapshots.Opt
	SnapshotterExports      map[string]string
	SnapshotterCapabilities []string

	Applier   diff.Applier
	ApplyOpts []diff.ApplyOpt

	// PrepareLayer derives a layer's snapshot key, GC qualifier, labels, and
	// validator from its descriptor, OCI ChainID, and selected parent before locking.
	// A nil callback preserves ordinary unpack behavior.
	PrepareLayer func(context.Context, ocispec.Descriptor, string, string) (snapshots.LayerPreparation, error)

	// ConfigType is the supported config type to be considered for unpacking
	// Defaults to OCI image config
	ConfigType string

	// LayerTypes are the supported types to be considered layers
	// Defaults to OCI image layers
	LayerTypes []string
}

// KeyedLocker is an interface for managing job duplication by
// locking on a given key.
type KeyedLocker interface {
	Lock(ctx context.Context, key string) error
	Unlock(key string)
}

// Limiter interface is used to restrict the number of concurrent operations by
// requiring operations to first acquire from the limiter and release when complete.
type Limiter interface {
	Acquire(context.Context, int64) error
	Release(int64)
}

type UnpackerOpt func(*unpackerConfig) error

func WithUnpackPlatform(u Platform) UnpackerOpt {
	return UnpackerOpt(func(c *unpackerConfig) error {
		if u.Platform == nil {
			u.Platform = platforms.All
		}
		if u.Snapshotter == nil {
			return fmt.Errorf("snapshotter must be provided to unpack")
		}
		if u.SnapshotterKey == "" {
			if s, ok := u.Snapshotter.(fmt.Stringer); ok {
				u.SnapshotterKey = s.String()
			} else {
				u.SnapshotterKey = "unknown"
			}
		}
		if u.Applier == nil {
			return fmt.Errorf("applier must be provided to unpack")
		}

		c.platforms = append(c.platforms, &u)

		return nil
	})
}

func WithLimiter(l Limiter) UnpackerOpt {
	return UnpackerOpt(func(c *unpackerConfig) error {
		c.limiter = l
		return nil
	})
}

func WithDuplicationSuppressor(d KeyedLocker) UnpackerOpt {
	return UnpackerOpt(func(c *unpackerConfig) error {
		c.duplicationSuppressor = d
		return nil
	})
}

func WithUnpackLimiter(l Limiter) UnpackerOpt {
	return UnpackerOpt(func(c *unpackerConfig) error {
		c.unpackLimiter = l
		return nil
	})
}

// Unpacker unpacks images by hooking into the image handler process.
// Unpacks happen in the backgrounds and waited on to complete.
type Unpacker struct {
	unpackerConfig

	unpacks atomic.Int32
	ctx     context.Context
	eg      *errgroup.Group
}

// NewUnpacker creates a new instance of the unpacker which can be used to wrap an
// image handler and unpack in parallel to handling. The unpacker will handle
// calling the block handlers when they are needed by the unpack process.
func NewUnpacker(ctx context.Context, cs content.Store, opts ...UnpackerOpt) (*Unpacker, error) {
	eg, ctx := errgroup.WithContext(ctx)

	u := &Unpacker{
		unpackerConfig: unpackerConfig{
			content:               cs,
			duplicationSuppressor: kmutex.NewNoop(),
		},
		ctx: ctx,
		eg:  eg,
	}
	for _, opt := range opts {
		if err := opt(&u.unpackerConfig); err != nil {
			return nil, err
		}
	}
	if len(u.platforms) == 0 {
		return nil, fmt.Errorf("no unpack platforms defined: %w", errdefs.ErrInvalidArgument)
	}
	return u, nil
}

// Unpack wraps an image handler to filter out blob handling and scheduling them
// during the unpack process. When an image config is encountered, the unpack
// process will be started in a goroutine.
func (u *Unpacker) Unpack(h images.Handler) images.Handler {
	var (
		lock sync.Mutex
		// Maps a config's digest to the layer descriptors of each manifest
		// that names it, one slice per manifest. Layers cannot be unpacked
		// until the diffIDs are known from the config. Manifests can share a
		// config (compression variants of one image have identical diffIDs
		// and so identical configs), which is why one digest can hold the
		// layers of several manifests.
		queuedLayers = map[digest.Digest][][]ocispec.Descriptor{}
		// Maps a config's digest to the first manifest layers scheduled for each
		// unpack identity. Once those layers are also queued for fetch, the value
		// is set to nil to preserve ordinary same-identity dedup while ensuring at
		// least one set of blobs reaches the content store if unpack hits cache.
		unpackedLayers = map[digest.Digest]map[string][]ocispec.Descriptor{}
	)

	var layerTypes map[string]bool
	var configTypes map[string]bool
	for _, p := range u.platforms {
		if p.ConfigType != "" {
			if configTypes == nil {
				configTypes = make(map[string]bool)
			}
			configTypes[p.ConfigType] = true
		}
		if len(p.LayerTypes) > 0 {
			if layerTypes == nil {
				layerTypes = make(map[string]bool)
			}
			for _, t := range p.LayerTypes {
				layerTypes[t] = true
			}
		}
	}

	return images.HandlerFunc(func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		ctx, span := tracing.StartSpan(ctx, tracing.Name(unpackSpanPrefix, "UnpackHandler"))
		defer span.End()
		span.SetAttributes(
			tracing.Attribute("descriptor.media.type", desc.MediaType),
			tracing.Attribute("descriptor.digest", desc.Digest.String()))
		unlock, err := u.lockBlobDescriptor(ctx, desc)
		if err != nil {
			return nil, err
		}
		children, err := h.Handle(ctx, desc)
		unlock()
		if err != nil {
			return children, err
		}

		if images.IsManifestType(desc.MediaType) {
			var nonLayers []ocispec.Descriptor
			var manifestLayers []ocispec.Descriptor
			// Split layers from non-layers, layers will be handled after
			// the config
			for i, child := range children {
				span.SetAttributes(
					tracing.Attribute("descriptor.child."+strconv.Itoa(i), []string{child.MediaType, child.Digest.String()}),
				)
				if images.IsLayerType(child.MediaType) || layerTypes[child.MediaType] {
					manifestLayers = append(manifestLayers, child)
				} else {
					nonLayers = append(nonLayers, child)
				}
			}

			if len(manifestLayers) == 0 {
				return nonLayers, nil
			}

			lock.Lock()
			for _, nl := range nonLayers {
				if images.IsConfigType(nl.MediaType) || configTypes[nl.MediaType] {
					queuedLayers[nl.Digest] = append(queuedLayers[nl.Digest], manifestLayers)
				}
			}
			lock.Unlock()

			children = nonLayers
		} else if images.IsConfigType(desc.MediaType) || configTypes[desc.MediaType] {
			lock.Lock()
			queued := queuedLayers[desc.Digest]
			delete(queuedLayers, desc.Digest)
			lock.Unlock()

			var (
				identities []string
				prepared   [][]snapshots.LayerPreparation
				toUnpack   []int
				toFetch    [][]ocispec.Descriptor
			)

			if len(queued) > 0 {
				cfg, err := u.readUnpackConfig(ctx, desc)
				if err != nil {
					u.eg.Go(func() error { return err })
					return children, nil
				}
				unpack := u.selectPlatform(desc, cfg)
				identities = make([]string, len(queued))
				prepared = make([][]snapshots.LayerPreparation, len(queued))
				// Ordinary images retain config-based dedup. Only a layer
				// policy can select different chains for the same config.
				if unpack != nil && unpack.PrepareLayer != nil {
					for i, layers := range queued {
						_, preparations, err := u.prepareLayers(ctx, unpack, layers, cfg.RootFS.DiffIDs)
						if err != nil {
							u.eg.Go(func() error { return err })
							return children, nil
						}
						prepared[i] = preparations
						identities[i] = layerPreparationIdentity(preparations)
					}
				}
			}

			if len(queued) > 0 {
				lock.Lock()
				byIdentity, ok := unpackedLayers[desc.Digest]
				if !ok {
					byIdentity = make(map[string][]ocispec.Descriptor)
					unpackedLayers[desc.Digest] = byIdentity
				}
				for i, layers := range queued {
					id := identities[i]
					unpacked, ok := byIdentity[id]
					if !ok {
						toUnpack = append(toUnpack, i)
						if len(byIdentity) == 0 {
							byIdentity[id] = layers
						} else {
							// A second manifest needs every set of blobs,
							// even when distinct chains both hit cache.
							toFetch = append(toFetch, layers)
							for priorID, prior := range byIdentity {
								if len(prior) > 0 {
									toFetch = append(toFetch, prior)
									byIdentity[priorID] = nil
								}
							}
							byIdentity[id] = nil
						}
						continue
					}
					toFetch = append(toFetch, layers)
					if len(unpacked) > 0 {
						toFetch = append(toFetch, unpacked)
						byIdentity[id] = nil
					}
				}
				lock.Unlock()
			}

			for _, i := range toUnpack {
				u.eg.Go(func() error {
					return u.unpack(h, desc, queued[i], prepared[i])
				})
			}
			for _, layers := range toFetch {
				layers := layers
				u.eg.Go(func() error {
					return u.fetch(u.ctx, h, layers, nil)
				})
			}
		}
		return children, nil
	})
}

// Wait waits for any ongoing unpack processes to complete then will return
// the result.
func (u *Unpacker) Wait() (Result, error) {
	if err := u.eg.Wait(); err != nil {
		return Result{}, err
	}
	return Result{
		Unpacks: int(u.unpacks.Load()),
	}, nil
}

// unpackConfig is a subset of the OCI config for resolving rootfs and platform,
// any config type which supports the platform and rootfs field can be supported.
type unpackConfig struct {
	// Platform describes the platform which the image in the manifest runs on.
	ocispec.Platform

	// RootFS references the layer content addresses used by the image.
	RootFS ocispec.RootFS `json:"rootfs"`
}

type unpackStatus struct {
	err     error
	desc    ocispec.Descriptor
	bottomF func(bool) error
	span    *tracing.Span
	startAt time.Time
}

// layerSnapshotLabels filters out containerd.io/snapshot/uidmapping and
// .../gidmapping annotations from the (untrusted) image manifest to prevent
// snapshotters from incorrectly chowning the extracted layer to the supplied
// mapped host uid/gid.
func layerSnapshotLabels(annotations map[string]string) map[string]string {
	labels := snapshots.FilterImageInheritedLabels(annotations)
	if labels == nil {
		labels = make(map[string]string)
	}
	delete(labels, snapshots.LabelSnapshotUIDMapping)
	delete(labels, snapshots.LabelSnapshotGIDMapping)
	return labels
}

func (u *Unpacker) readUnpackConfig(ctx context.Context, config ocispec.Descriptor) (unpackConfig, error) {
	var cfg unpackConfig
	p, err := content.ReadBlob(ctx, u.content, config)
	if err != nil {
		return unpackConfig{}, err
	}
	if err := json.Unmarshal(p, &cfg); err != nil {
		return unpackConfig{}, fmt.Errorf("unmarshal image config: %w", err)
	}
	return cfg, nil
}

func (u *Unpacker) selectPlatform(config ocispec.Descriptor, cfg unpackConfig) *Platform {
	imgPlatform := platforms.Normalize(cfg.Platform)
	for _, up := range u.platforms {
		if up.ConfigType != "" && up.ConfigType != config.MediaType {
			continue
		}
		// "layers" is the only supported rootfs value for OCI images.
		if (up.ConfigType == "" || images.IsConfigType(up.ConfigType)) && cfg.RootFS.Type != "" && cfg.RootFS.Type != "layers" {
			continue
		}
		if up.Platform.Match(imgPlatform) {
			return up
		}
	}
	return nil
}

func (u *Unpacker) prepareLayers(ctx context.Context, unpack *Platform, layers []ocispec.Descriptor, diffIDs []digest.Digest) ([]digest.Digest, []snapshots.LayerPreparation, error) {
	if len(layers) != len(diffIDs) {
		return nil, nil, fmt.Errorf("number of layers and diffIDs don't match: %d != %d", len(layers), len(diffIDs))
	}

	chainIDs := make([]digest.Digest, len(diffIDs))
	copy(chainIDs, diffIDs)
	chainIDs = identity.ChainIDs(chainIDs)

	preparations := make([]snapshots.LayerPreparation, len(chainIDs))
	for i, chainID := range chainIDs {
		selected := snapshots.LayerPreparation{Key: chainID.String()}
		if unpack.PrepareLayer != nil {
			var parent string
			if i > 0 {
				parent = preparations[i-1].Key
			}
			var err error
			selected, err = unpack.PrepareLayer(ctx, layers[i], chainID.String(), parent)
			if err != nil {
				return nil, nil, fmt.Errorf("prepare layer policy for %s: %w", layers[i].Digest, err)
			}
			if selected.Key == "" {
				return nil, nil, fmt.Errorf("prepare layer policy for %s returned an empty snapshot key", layers[i].Digest)
			}
			if strings.ContainsAny(selected.GCQualifier, "/\\") || selected.GCQualifier == "." || selected.GCQualifier == ".." {
				return nil, nil, fmt.Errorf("prepare layer policy for %s returned invalid GC label qualifier %q", layers[i].Digest, selected.GCQualifier)
			}
			if selected.Key != chainID.String() && selected.GCQualifier == "" {
				return nil, nil, fmt.Errorf("alternate snapshot key %q for layer %s requires a GC label qualifier", selected.Key, layers[i].Digest)
			}
		}
		preparations[i] = selected
	}

	return chainIDs, preparations, nil
}

func layerPreparationIdentity(preparations []snapshots.LayerPreparation) string {
	var b strings.Builder
	for _, preparation := range preparations {
		b.WriteString(preparation.Key)
		b.WriteByte(0)
	}
	if len(preparations) > 0 {
		b.WriteString(preparations[len(preparations)-1].GCQualifier)
	}
	return b.String()
}

func (u *Unpacker) unpack(
	h images.Handler,
	config ocispec.Descriptor,
	layers []ocispec.Descriptor,
	preparations []snapshots.LayerPreparation,
) error {
	ctx := u.ctx
	ctx, layerSpan := tracing.StartSpan(ctx, tracing.Name(unpackSpanPrefix, "unpack"))
	defer layerSpan.End()
	unpackStart := time.Now()
	cfg, err := u.readUnpackConfig(ctx, config)
	if err != nil {
		return err
	}

	// TODO: Support multiple unpacks rather than just first match
	unpack := u.selectPlatform(config, cfg)

	if unpack == nil {
		imgPlatform := platforms.Normalize(cfg.Platform)
		log.G(ctx).WithField("image", config.Digest).WithField("platform", platforms.Format(imgPlatform)).Debugf("unpacker does not support platform, only fetching layers")
		return u.fetch(ctx, h, layers, nil)
	}

	var chainIDs []digest.Digest
	if preparations == nil {
		chainIDs, preparations, err = u.prepareLayers(ctx, unpack, layers, cfg.RootFS.DiffIDs)
		if err != nil {
			return err
		}
	} else {
		chainIDs = identity.ChainIDs(append([]digest.Digest(nil), cfg.RootFS.DiffIDs...))
	}

	u.unpacks.Add(1)
	diffIDs := cfg.RootFS.DiffIDs

	var (
		sn = unpack.Snapshotter
		a  = unpack.Applier
		cs = u.content

		fetchOffset int
		fetchC      []chan struct{}
		fetchErr    []chan error

		parallel = u.supportParallel(unpack)
	)

	// If there is an early return, ensure any ongoing
	// fetches get their context cancelled
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	topHalf := func(i int, desc ocispec.Descriptor, span *tracing.Span, startAt time.Time) (<-chan *unpackStatus, error) {
		var (
			err     error
			parent  string
			chainID string
		)
		if i > 0 && !parallel {
			parent = preparations[i-1].Key
		}
		chainID = chainIDs[i].String()
		prepared := preparations[i]

		unlock, err := u.lockSnChainID(ctx, prepared.Key, unpack.SnapshotterKey)
		if err != nil {
			return nil, err
		}
		defer func() {
			if err != nil {
				unlock()
			}
		}()

		// inherits a filtered set of annotations which are provided as snapshot labels
		snapshotLabels := layerSnapshotLabels(desc.Annotations)
		snapshotLabels[labelSnapshotRef] = prepared.Key
		snapshotLabels[labelSnapshotDiffID] = diffIDs[i].String()
		if i > 0 {
			snapshotLabels[labelSnapshotParent] = preparations[i-1].Key
		}
		for key, value := range prepared.Labels {
			snapshotLabels[key] = value
		}
		validateExistingSnapshot := prepared.ValidateExisting

		var (
			key    string
			mounts []mount.Mount
			opts   = append(unpack.SnapshotOpts, snapshots.WithLabels(snapshotLabels))
		)

		for try := 1; try <= 3; try++ {
			// Prepare snapshot with from parent, label as root
			key = fmt.Sprintf(snapshots.UnpackKeyFormat, uniquePart(), prepared.Key)
			mounts, err = sn.Prepare(ctx, key, parent, opts...)
			if err != nil {
				if errdefs.IsAlreadyExists(err) {
					if snInfo, err := sn.Stat(ctx, prepared.Key); err != nil {
						if !errdefs.IsNotFound(err) {
							return nil, fmt.Errorf("failed to stat snapshot %s: %w", prepared.Key, err)
						}
						// Try again, this should be rare, log it
						log.G(ctx).WithField("key", key).WithField("chainid", chainID).Debug("extraction snapshot already exists, selected key not found")
					} else {
						if validateExistingSnapshot != nil {
							if err := validateExistingSnapshot(snInfo); err != nil {
								return nil, fmt.Errorf("existing snapshot %s violates layer policy: %w", prepared.Key, err)
							}
						}
						log.G(ctx).Debugf("snapshot %s with chainID %s already exists skip fetch blob %q ", snInfo.Name, chainID, desc.Digest)
						// no need to handle, snapshot now found with chain id
						return nil, nil
					}
				} else {
					return nil, fmt.Errorf("failed to prepare extraction snapshot %q: %w", key, err)
				}
			} else {
				break
			}
		}
		if err != nil {
			return nil, fmt.Errorf("unable to prepare extraction snapshot: %w", err)
		}

		// Abort the snapshot if commit does not happen
		abort := func(ctx context.Context) {
			if err := sn.Remove(ctx, key); err != nil {
				log.G(ctx).WithError(err).Errorf("failed to cleanup %q", key)
			}
		}

		if fetchErr == nil {
			fetchOffset = i
			n := len(layers) - fetchOffset
			fetchErr = make([]chan error, n)
			fetchC = make([]chan struct{}, n)
			for i := range n {
				fetchC[i] = make(chan struct{})
				fetchErr[i] = make(chan error, 1)
			}
			go func(i int) {
				err := u.fetch(ctx, h, layers[i:], fetchC)
				if err != nil {
					for _, fc := range fetchErr {
						fc <- err
						close(fc)
					}
				}
			}(i)
		}

		if err = u.acquire(ctx, u.unpackLimiter); err != nil {
			cleanup.Do(ctx, abort)
			return nil, err
		}

		resCh := make(chan *unpackStatus, 1)
		go func() {
			defer func() {
				u.release(u.unpackLimiter)
				close(resCh)
			}()

			status := &unpackStatus{
				desc:    desc,
				span:    span,
				startAt: startAt,
				bottomF: func(shouldAbort bool) error {
					defer unlock()
					if shouldAbort {
						cleanup.Do(ctx, abort)
						return nil
					}

					if i > 0 && parallel {
						parent = preparations[i-1].Key
						opts = append(opts, snapshots.WithParent(parent))
					}
					if err = sn.Commit(ctx, prepared.Key, key, opts...); err != nil {
						cleanup.Do(ctx, abort)
						if errdefs.IsAlreadyExists(err) {
							if validateExistingSnapshot != nil {
								info, statErr := sn.Stat(ctx, prepared.Key)
								if statErr != nil {
									return fmt.Errorf("failed to stat concurrently committed snapshot %s: %w", prepared.Key, statErr)
								}
								if policyErr := validateExistingSnapshot(info); policyErr != nil {
									return fmt.Errorf("concurrently committed snapshot %s violates layer policy: %w", prepared.Key, policyErr)
								}
							}
							return nil
						}
						return fmt.Errorf("failed to commit snapshot %s: %w", key, err)
					}

					// Set the uncompressed label after the uncompressed
					// digest has been verified through apply.
					cinfo := content.Info{
						Digest: desc.Digest,
						Labels: map[string]string{
							labels.LabelUncompressed: diffIDs[i].String(),
						},
					}
					if _, err := cs.Update(ctx, cinfo, "labels."+labels.LabelUncompressed); err != nil {
						return err
					}
					return nil
				},
			}

			select {
			case <-ctx.Done():
				cleanup.Do(ctx, abort)
				status.err = ctx.Err()
				resCh <- status
				return
			case err := <-fetchErr[i-fetchOffset]:
				if err != nil {
					cleanup.Do(ctx, abort)
					status.err = err
					resCh <- status
					return
				}
			case <-fetchC[i-fetchOffset]:
			}

			// In case of parallel unpack, the parent snapshot isn't provided to the snapshotter.
			// The overlayfs will return bind mounts for all layers, we need to convert them
			// to overlay mounts for the applier to perform whiteout conversion correctly.
			// TODO: this is a temporary workaround until #13053 lands.
			// See: https://github.com/containerd/containerd/issues/13030
			if i > 0 && parallel && unpack.SnapshotterKey == "overlayfs" {
				mounts = bindToOverlay(mounts)
			}

			diff, err := a.Apply(ctx, desc, mounts, unpack.ApplyOpts...)
			if err != nil {
				cleanup.Do(ctx, abort)
				status.err = fmt.Errorf("failed to extract layer (%s %s) to %s as %q: %w", desc.MediaType, desc.Digest, unpack.SnapshotterKey, key, err)
				resCh <- status
				return
			}

			if diff.Digest != diffIDs[i] {
				cleanup.Do(ctx, abort)
				status.err = fmt.Errorf("wrong diff id %q calculated on extraction %q, desc %q", diff.Digest, diffIDs[i], desc.Digest)
				resCh <- status
				return
			}

			resCh <- status
		}()

		return resCh, nil
	}

	bottomHalf := func(s *unpackStatus, prevErrs error) error {
		var err error
		if s.err != nil {
			s.bottomF(true)
			err = s.err
		} else if prevErrs != nil {
			s.bottomF(true)
			err = fmt.Errorf("aborted")
		} else {
			err = s.bottomF(false)
		}

		s.span.SetStatus(err)
		s.span.End()
		if err == nil {
			log.G(ctx).WithFields(log.Fields{
				"layer":    s.desc.Digest,
				"duration": time.Since(s.startAt),
			}).Debug("layer unpacked")
		}
		return err
	}

	var (
		statusChans []<-chan *unpackStatus
		errs        error
	)

	for i, desc := range layers {
		_, layerSpan := tracing.StartSpan(ctx, tracing.Name(unpackSpanPrefix, "unpackLayer"))
		unpackLayerStart := time.Now()
		layerSpan.SetAttributes(
			tracing.Attribute("layer.media.type", desc.MediaType),
			tracing.Attribute("layer.media.size", desc.Size),
			tracing.Attribute("layer.media.digest", desc.Digest.String()),
		)
		statusCh, err := topHalf(i, desc, layerSpan, unpackLayerStart)
		if err != nil {
			if parallel {
				// Report the failure instead of committing a partial chain.
				errs = err
				layerSpan.SetStatus(err)
				layerSpan.End()
				break
			} else {
				layerSpan.SetStatus(err)
				layerSpan.End()
				return err
			}
		}
		if statusCh == nil {
			// nothing to do, already exists
			layerSpan.End()
			continue
		}
		if parallel {
			statusChans = append(statusChans, statusCh)
		} else {
			if err = bottomHalf(<-statusCh, nil); err != nil {
				return err
			}
		}
	}

	// In parallel mode, snapshots still need to be committed and rebased sequentially
	if parallel {
		for _, sc := range statusChans {
			if err := bottomHalf(<-sc, errs); err != nil {
				errs = errors.Join(errs, err)
			}
		}
		if errs != nil {
			return errs
		}
	}

	var chainID string
	gcLabel := ""
	gcSnapshotKey := ""
	if len(chainIDs) > 0 {
		chainID = chainIDs[len(chainIDs)-1].String()
		gcLabel = preparations[len(preparations)-1].GCQualifier
		gcSnapshotKey = preparations[len(preparations)-1].Key
	}
	gcRef := fmt.Sprintf("containerd.io/gc.ref.snapshot.%s", unpack.SnapshotterKey)
	if gcLabel != "" {
		gcRef += "/" + gcLabel
	}
	cinfo := content.Info{
		Digest: config.Digest,
		Labels: map[string]string{
			gcRef: gcSnapshotKey,
		},
	}
	if _, err := cs.Update(ctx, cinfo, "labels."+gcRef); err != nil {
		return err
	}
	log.G(ctx).WithFields(log.Fields{
		"config":   config.Digest,
		"chainID":  chainID,
		"snapshot": gcSnapshotKey,
		"parallel": parallel,
		"duration": time.Since(unpackStart),
	}).Debug("image unpacked")

	return nil
}

func (u *Unpacker) fetch(ctx context.Context, h images.Handler, layers []ocispec.Descriptor, done []chan struct{}) error {
	eg, ctx2 := errgroup.WithContext(ctx)
	for i, desc := range layers {
		ctx2, layerSpan := tracing.StartSpan(ctx2, tracing.Name(unpackSpanPrefix, "fetchLayer"))
		layerSpan.SetAttributes(
			tracing.Attribute("layer.media.type", desc.MediaType),
			tracing.Attribute("layer.media.size", desc.Size),
			tracing.Attribute("layer.media.digest", desc.Digest.String()),
		)
		var ch chan struct{}
		if done != nil {
			ch = done[i]
		}

		if err := u.acquire(ctx, u.limiter); err != nil {
			return err
		}

		eg.Go(func() error {
			defer layerSpan.End()

			unlock, err := u.lockBlobDescriptor(ctx2, desc)
			if err != nil {
				u.release(u.limiter)
				return err
			}

			_, err = h.Handle(ctx2, desc)

			unlock()
			u.release(u.limiter)

			if err != nil && !errors.Is(err, images.ErrSkipDesc) {
				return err
			}
			if ch != nil {
				close(ch)
			}

			return nil
		})
	}

	return eg.Wait()
}

func (u *Unpacker) acquire(ctx context.Context, l Limiter) error {
	if l == nil {
		return nil
	}
	return l.Acquire(ctx, 1)
}

func (u *Unpacker) release(l Limiter) {
	if l == nil {
		return
	}
	l.Release(1)
}

func (u *Unpacker) lockSnChainID(ctx context.Context, chainID, snapshotter string) (func(), error) {
	key := u.makeChainIDKeyWithSnapshotter(chainID, snapshotter)

	if err := u.duplicationSuppressor.Lock(ctx, key); err != nil {
		return nil, err
	}
	return func() {
		u.duplicationSuppressor.Unlock(key)
	}, nil
}

func (u *Unpacker) lockBlobDescriptor(ctx context.Context, desc ocispec.Descriptor) (func(), error) {
	key := u.makeBlobDescriptorKey(desc)

	if err := u.duplicationSuppressor.Lock(ctx, key); err != nil {
		return nil, err
	}
	return func() {
		u.duplicationSuppressor.Unlock(key)
	}, nil
}

func (u *Unpacker) makeChainIDKeyWithSnapshotter(chainID, snapshotter string) string {
	return fmt.Sprintf("sn://%s/%v", snapshotter, chainID)
}

func (u *Unpacker) makeBlobDescriptorKey(desc ocispec.Descriptor) string {
	return fmt.Sprintf("blob://%v", desc.Digest)
}

func (u *Unpacker) supportParallel(unpack *Platform) bool {
	if u.unpackLimiter == nil {
		return false
	}
	if !slices.Contains(unpack.SnapshotterCapabilities, "rebase") {
		log.L.Infof("snapshotter does not support rebase capability, unpacking will be sequential")
		return false
	}
	return true
}

func uniquePart() string {
	t := time.Now()
	var b [3]byte
	// Ignore read failures, just decreases uniqueness
	rand.Read(b[:])
	return fmt.Sprintf("%d-%s", t.Nanosecond(), base64.URLEncoding.EncodeToString(b[:]))
}

// TODO: this is a temporary workaround until #13053 lands.
func bindToOverlay(mounts []mount.Mount) []mount.Mount {
	if len(mounts) != 1 || mounts[0].Type != "bind" {
		return mounts
	}

	m := mount.Mount{
		Type:   "overlay",
		Source: "overlay",
	}
	for _, o := range mounts[0].Options {
		if o != "rbind" {
			m.Options = append(m.Options, o)
		}
	}
	m.Options = append(m.Options, "upperdir="+mounts[0].Source)

	return []mount.Mount{m}
}
