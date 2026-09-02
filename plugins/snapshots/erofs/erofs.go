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

package erofs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/containerd/continuity/fs"
	"github.com/containerd/errdefs"
	"github.com/containerd/log"

	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/core/snapshots/storage"
	"github.com/containerd/containerd/v2/internal/dmverity"
	"github.com/containerd/containerd/v2/internal/fsverity"
	snpkg "github.com/containerd/containerd/v2/pkg/snapshotters"
	"github.com/opencontainers/go-digest"
)

// SnapshotterConfig is used to configure the erofs snapshotter instance
type SnapshotterConfig struct {
	// ovlOptions are the base options added to the overlayfs mount (defaults to [""])
	ovlOptions []string
	// enableFsverity enables fsverity for EROFS layers
	enableFsverity bool
	// setImmutable enables IMMUTABLE_FL file attribute for EROFS layers
	setImmutable bool
	// defaultSize creates a default size writable layer for active snapshots
	defaultSize int64
	// dmverityMode controls dm-verity behavior: "auto" (use if .dmverity exists), "on" (require .dmverity), "off" (disable)
	dmverityMode string
}

// Opt is an option to configure the erofs snapshotter
type Opt func(config *SnapshotterConfig)

// WithOvlOptions defines the extra mount options for overlayfs
func WithOvlOptions(options []string) Opt {
	return func(config *SnapshotterConfig) {
		config.ovlOptions = options
	}
}

// WithFsverity enables fsverity for EROFS layers
func WithFsverity() Opt {
	return func(config *SnapshotterConfig) {
		config.enableFsverity = true
	}
}

// WithImmutable enables IMMUTABLE_FL file attribute for EROFS layers
func WithImmutable() Opt {
	return func(config *SnapshotterConfig) {
		config.setImmutable = true
	}
}

// WithDmverityMode sets the dm-verity mode: "auto" (default), "on" (required), or "off" (disabled)
func WithDmverityMode(mode string) Opt {
	return func(config *SnapshotterConfig) {
		config.dmverityMode = mode
	}
}

// WithDefaultSize creates a default size writable layer for active snapshots
func WithDefaultSize(size int64) Opt {
	return func(config *SnapshotterConfig) {
		config.defaultSize = size
	}
}

type MetaStore interface {
	TransactionContext(ctx context.Context, writable bool) (context.Context, storage.Transactor, error)
	WithTransaction(ctx context.Context, writable bool, fn storage.TransactionCallback) error
	Close() error
}

type snapshotter struct {
	root            string
	ms              *storage.MetaStore
	ovlOptions      []string
	enableFsverity  bool
	setImmutable    bool
	defaultWritable int64
	blockMode       bool
	dmverityMode    string
}

// NewSnapshotter returns a Snapshotter which uses EROFS+OverlayFS. The layers
// are stored under the provided root. A metadata file is stored under the root.
func NewSnapshotter(root string, opts ...Opt) (snapshots.Snapshotter, error) {
	config := SnapshotterConfig{
		defaultSize: defaultWritableSize,
	}
	for _, opt := range opts {
		opt(&config)
	}

	if config.dmverityMode == "" {
		config.dmverityMode = "auto"
	}

	if config.dmverityMode != "auto" && config.dmverityMode != "on" && config.dmverityMode != "off" {
		return nil, fmt.Errorf("invalid dmverity_mode %q: must be \"auto\", \"on\", or \"off\"", config.dmverityMode)
	}

	if config.dmverityMode == "on" {
		if err := dmverity.CheckSignatureSupport(); err != nil {
			return nil, fmt.Errorf("dmverity_mode is 'on' but signed dm-verity mappings are unavailable: %w", err)
		}
	}

	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}

	if config.defaultSize == 0 {
		// If not block mode, check root compatibility
		if err := checkCompatibility(root); err != nil {
			return nil, err
		}
	}

	// Check fsverity support if enabled
	if config.enableFsverity {
		// TODO: Call specific function here
		supported, err := fsverity.IsSupported(root)
		if err != nil {
			return nil, fmt.Errorf("failed to check fsverity support on %q: %w", root, err)
		}
		if !supported {
			return nil, fmt.Errorf("fsverity is not supported on the filesystem of %q", root)
		}
	}

	if config.setImmutable && runtime.GOOS != "linux" {
		return nil, fmt.Errorf("setting IMMUTABLE_FL is only supported on Linux")
	}

	ms, err := storage.NewMetaStore(filepath.Join(root, "metadata.db"))
	if err != nil {
		return nil, err
	}

	if err := os.Mkdir(filepath.Join(root, "snapshots"), 0700); err != nil && !os.IsExist(err) {
		return nil, err
	}

	return &snapshotter{
		root:            root,
		ms:              ms,
		ovlOptions:      config.ovlOptions,
		enableFsverity:  config.enableFsverity,
		setImmutable:    config.setImmutable,
		defaultWritable: config.defaultSize,
		blockMode:       config.defaultSize > 0,
		dmverityMode:    config.dmverityMode,
	}, nil
}

// Close closes the snapshotter
func (s *snapshotter) Close() error {
	return s.ms.Close()
}

func (s *snapshotter) upperPath(id string) string {
	return filepath.Join(s.root, "snapshots", id, "fs")
}

func (s *snapshotter) workPath(id string) string {
	return filepath.Join(s.root, "snapshots", id, "work")
}

func (s *snapshotter) writablePath(id string) string {
	return filepath.Join(s.root, "snapshots", id, "rwlayer.img")
}

// A committed layer blob generated by the EROFS differ
func (s *snapshotter) layerBlobPath(id string) string {
	return filepath.Join(s.root, "snapshots", id, "layer.erofs")
}

func (s *snapshotter) lowerPath(id string) (string, error) {
	layerBlob := s.layerBlobPath(id)
	if _, err := os.Stat(layerBlob); err != nil {
		return "", fmt.Errorf("failed to find valid erofs layer blob: %w", err)
	}

	return layerBlob, nil
}

func (s *snapshotter) prepareDirectory(ctx context.Context, snapshotDir string, kind snapshots.Kind) (string, error) {
	td, err := os.MkdirTemp(snapshotDir, "new-")
	if err != nil {
		return "", fmt.Errorf("failed to create temp dir: %w", err)
	}

	if err := os.Mkdir(filepath.Join(td, "fs"), 0755); err != nil {
		return td, err
	}
	if kind == snapshots.KindActive {
		if !s.blockMode {
			if err := os.Mkdir(filepath.Join(td, "work"), 0711); err != nil {
				return td, err
			}
		}
		// Create a special file for the EROFS differ to indicate it will be
		// prepared as an EROFS layer by the EROFS snapshotter.
		if err := os.WriteFile(filepath.Join(td, ".erofslayer"), []byte{}, 0644); err != nil {
			return td, err
		}
	}

	return td, nil
}

// applyDmverityPolicy validates and applies dm-verity policy for a layer.
// Returns the X-containerd.dmverity option if needed, or empty string otherwise.
func (s *snapshotter) applyDmverityPolicy(layerBlob string, labels map[string]string) (string, error) {
	if s.dmverityMode == "off" {
		return dmverity.MountOptionModePrefix + "off", nil
	}

	signedMaterialization, err := requiresSignedMaterialization(labels)
	if err != nil {
		return "", fmt.Errorf("invalid dm-verity materialization labels for layer %s: %w", layerBlob, err)
	}

	signaturePath := dmverity.SignaturePath(layerBlob)
	signatureInfo, signatureErr := os.Stat(signaturePath)
	switch {
	case signatureErr == nil && (!signatureInfo.Mode().IsRegular() || signatureInfo.Size() == 0):
		return "", fmt.Errorf("layer %s has dm-verity signature %s that is not a non-empty regular file", layerBlob, signaturePath)
	case signatureErr != nil && !errors.Is(signatureErr, os.ErrNotExist):
		return "", fmt.Errorf("failed to inspect dm-verity signature for layer %s: %w", layerBlob, signatureErr)
	}
	signatureExists := signatureErr == nil

	requiredPath := dmverity.SignatureRequiredPath(layerBlob)
	requiredInfo, requiredErr := os.Stat(requiredPath)
	switch {
	case requiredErr == nil && (!requiredInfo.Mode().IsRegular() || requiredInfo.Size() == 0):
		return "", fmt.Errorf("layer %s has invalid signature-required marker %s", layerBlob, requiredPath)
	case requiredErr != nil && !errors.Is(requiredErr, os.ErrNotExist):
		return "", fmt.Errorf("failed to inspect signature-required marker for layer %s: %w", layerBlob, requiredErr)
	}
	signatureRequired := requiredErr == nil

	metadata, metadataErr := dmverity.ReadMetadata(layerBlob)
	switch {
	case metadataErr == nil:
		if signatureExists {
			if signedMaterialization {
				if err := validateSignedMaterialization(layerBlob, metadata, labels); err != nil {
					return "", err
				}
				return dmverity.MountOptionModePrefix + "on", nil
			}
			if s.dmverityMode == "on" {
				return dmverity.MountOptionModePrefix + "on", nil
			}
			return "", nil
		}
		if signedMaterialization || signatureRequired || s.dmverityMode == "on" {
			return "", fmt.Errorf("layer %s has dm-verity metadata but no usable signature", layerBlob)
		}
		// Before signature-gated materialization, optional mode formatted every
		// layer and left metadata without a signature. Mount those legacy
		// unsigned layers as plain EROFS during upgrade.
		return dmverity.MountOptionModePrefix + "off", nil
	case errors.Is(metadataErr, os.ErrNotExist):
		if signatureExists || signatureRequired || signedMaterialization {
			return "", fmt.Errorf("layer %s has dm-verity signature state but no metadata", layerBlob)
		}
		if s.dmverityMode == "on" {
			return "", fmt.Errorf("dm-verity mode is 'on' but .dmverity metadata not found for layer %s", layerBlob)
		}
		return "", nil
	default:
		if signatureExists || signatureRequired || signedMaterialization || s.dmverityMode == "on" {
			return "", fmt.Errorf("layer %s has unusable dm-verity metadata: %w", layerBlob, metadataErr)
		}
		// A malformed unsigned legacy sidecar cannot drive a mapper, but it is
		// safe to ignore when optional policy explicitly falls back to plain
		// EROFS.
		return dmverity.MountOptionModePrefix + "off", nil
	}
}

func requiresSignedMaterialization(labels map[string]string) (bool, error) {
	version := labels[snpkg.DmverityMaterializationVersionLabel]
	state := labels[snpkg.DmverityMaterializationStateLabel]
	rootHash := labels[snpkg.DmverityMaterializationRootHashLabel]
	signatureDigest := labels[snpkg.DmverityMaterializationSignatureDigestLabel]
	if version == "" && state == "" && rootHash == "" && signatureDigest == "" {
		return false, nil
	}
	if version != snpkg.DmverityMaterializationVersion {
		return false, fmt.Errorf("unsupported version %q", version)
	}
	switch state {
	case snpkg.DmverityMaterializationStatePlain:
		if rootHash != "" || signatureDigest != "" {
			return false, fmt.Errorf("plain materialization carries signed metadata")
		}
		return false, nil
	case snpkg.DmverityMaterializationStateSigned:
		if err := snpkg.ValidateDmveritySnapshot(labels, labels); err != nil {
			return false, err
		}
		return true, nil
	default:
		return false, fmt.Errorf("unknown state %q", state)
	}
}

func validateSignedMaterialization(layerBlob string, metadata *dmverity.DmverityMetadata, labels map[string]string) error {
	expectedRootHash := labels[snpkg.DmverityMaterializationRootHashLabel]
	if metadata.RootHash != expectedRootHash {
		return fmt.Errorf(
			"layer %s dm-verity root hash %q does not match recorded root hash %q",
			layerBlob,
			metadata.RootHash,
			expectedRootHash,
		)
	}
	signature, err := os.ReadFile(dmverity.SignaturePath(layerBlob))
	if err != nil {
		return fmt.Errorf("failed to read dm-verity signature for layer %s: %w", layerBlob, err)
	}
	actualDigest := digest.FromBytes(signature).String()
	expectedDigest := labels[snpkg.DmverityMaterializationSignatureDigestLabel]
	if actualDigest != expectedDigest {
		return fmt.Errorf(
			"layer %s dm-verity signature digest %q does not match recorded digest %q",
			layerBlob,
			actualDigest,
			expectedDigest,
		)
	}
	return nil
}

// createErofsMount creates a mount specification for an EROFS layer.
// Applies dmverityMode policy and passes it to the mount handler.
func (s *snapshotter) createErofsMount(layerBlob string, labels map[string]string) (mount.Mount, error) {
	options := []string{"ro", "loop"}

	if dmverityOpt, err := s.applyDmverityPolicy(layerBlob, labels); err != nil {
		return mount.Mount{}, err
	} else if dmverityOpt != "" {
		options = append(options, dmverityOpt)
		if dmverityOpt == dmverity.MountOptionModePrefix+"on" &&
			labels[snpkg.DmverityMaterializationStateLabel] == snpkg.DmverityMaterializationStateSigned {
			options = append(options,
				dmverity.MountOptionRootHashPrefix+labels[snpkg.DmverityMaterializationRootHashLabel],
				dmverity.MountOptionSignatureDigestPrefix+labels[snpkg.DmverityMaterializationSignatureDigestLabel],
			)
		}
	}

	return mount.Mount{
		Source:  layerBlob,
		Type:    "erofs",
		Options: options,
	}, nil
}

func (s *snapshotter) parentSnapshotInfos(ctx context.Context, info snapshots.Info, parentIDs []string) ([]snapshots.Info, error) {
	infos := make([]snapshots.Info, len(parentIDs))
	err := s.ms.WithTransaction(ctx, false, func(ctx context.Context) error {
		parent := info.Parent
		for i, expectedID := range parentIDs {
			if parent == "" {
				return fmt.Errorf("snapshot parent chain ended before parent ID %s", expectedID)
			}
			id, parentInfo, _, err := storage.GetInfo(ctx, parent)
			if err != nil {
				return fmt.Errorf("get parent snapshot %q: %w", parent, err)
			}
			if id != expectedID {
				return fmt.Errorf("snapshot parent %q has ID %s, expected %s", parent, id, expectedID)
			}
			infos[i] = parentInfo
			parent = parentInfo.Parent
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return infos, nil
}

func (s *snapshotter) mounts(ctx context.Context, snap storage.Snapshot, info snapshots.Info) ([]mount.Mount, error) {
	var options []string

	if len(snap.ParentIDs) == 0 {
		if layerBlob, err := s.lowerPath(snap.ID); err == nil {
			if snap.Kind != snapshots.KindView {
				return nil, fmt.Errorf("only works for snapshots.KindView on a committed snapshot: %w", err)
			}
			if s.enableFsverity {
				if err := s.verifyFsverity(layerBlob); err != nil {
					return nil, err
				}
			}
			m, err := s.createErofsMount(layerBlob, info.Labels)
			if err != nil {
				return nil, fmt.Errorf("failed to create erofs mount: %w", err)
			}
			return []mount.Mount{m}, nil
		}
		// if we only have one layer/no parents then just return a bind mount as overlay
		// will not work
		roFlag := "rw"
		if snap.Kind == snapshots.KindView {
			roFlag = "ro"
		}
		if s.blockMode {
			return []mount.Mount{
				{
					Source: s.writablePath(snap.ID),
					Type:   "mkfs/ext4",
					Options: []string{
						"X-containerd.mkfs.fs=ext4",
						// TODO: Get size from snapshot labels
						fmt.Sprintf("X-containerd.mkfs.size=%d", s.defaultWritable),
						// TODO: Add UUID
						roFlag,
						"loop",
					},
				},
				{
					Source: "{{ mount 0 }}/upper",
					Type:   "format/mkdir/bind",
					Options: append(options,
						"X-containerd.mkdir.path={{ mount 0 }}/upper:0755",
						roFlag,
						"rbind",
					),
				},
			}, nil
		} else {
			return []mount.Mount{
				{
					Source: s.upperPath(snap.ID),
					Type:   "bind",
					Options: append(options,
						roFlag,
						"rbind",
					),
				},
			}, nil
		}
	}

	parentInfos, err := s.parentSnapshotInfos(ctx, info, snap.ParentIDs)
	if err != nil {
		return nil, fmt.Errorf("resolve parent snapshot materialization: %w", err)
	}

	var mounts []mount.Mount
	if snap.Kind == snapshots.KindActive {
		if s.blockMode {
			mounts = append(mounts, mount.Mount{
				Source: s.writablePath(snap.ID),
				Type:   "mkfs/ext4",
				Options: []string{
					"X-containerd.mkfs.fs=ext4",
					// TODO: Get size from snapshot labels
					fmt.Sprintf("X-containerd.mkfs.size=%d", s.defaultWritable),
					// TODO: Add UUID
					"rw",
					"loop",
				},
			})
			options = append(options,
				"X-containerd.mkdir.path={{ mount 0 }}/upper:0755",
				"X-containerd.mkdir.path={{ mount 0 }}/work:0755",
				"workdir={{ mount 0 }}/work",
				"upperdir={{ mount 0 }}/upper",
			)
		} else {
			options = append(options,
				fmt.Sprintf("workdir=%s", s.workPath(snap.ID)),
				fmt.Sprintf("upperdir=%s", s.upperPath(snap.ID)),
			)
		}
	} else if len(snap.ParentIDs) == 1 {
		layerBlob, err := s.lowerPath(snap.ParentIDs[0])
		if err != nil {
			return nil, err
		}

		m, err := s.createErofsMount(layerBlob, parentInfos[0].Labels)
		if err != nil {
			return nil, fmt.Errorf("failed to create erofs mount: %w", err)
		}
		return []mount.Mount{m}, nil
	}

	first := len(mounts)
	for i := range snap.ParentIDs {
		layerBlob, err := s.lowerPath(snap.ParentIDs[i])
		if err != nil {
			return nil, err
		}

		m, err := s.createErofsMount(layerBlob, parentInfos[i].Labels)
		if err != nil {
			return nil, fmt.Errorf("failed to create erofs mount for parent %s: %w", snap.ParentIDs[i], err)
		}

		mounts = append(mounts, m)
	}
	if (len(mounts) - first) == 1 {
		options = append(options, fmt.Sprintf("lowerdir={{ mount %d }}", first))
	} else {
		options = append(options, fmt.Sprintf("lowerdir={{ overlay %d %d }}", first, len(mounts)-1))
	}
	options = append(options, s.ovlOptions...)

	return append(mounts, mount.Mount{
		Type:    "format/mkdir/overlay",
		Source:  "overlay",
		Options: options,
	}), nil
}

func (s *snapshotter) createSnapshot(ctx context.Context, kind snapshots.Kind, key, parent string, opts []snapshots.Opt) (_ []mount.Mount, err error) {
	var (
		snap     storage.Snapshot
		td, path string
		info     snapshots.Info
	)

	defer func() {
		if err != nil {
			if td != "" {
				if err1 := os.RemoveAll(td); err1 != nil {
					log.G(ctx).WithError(err1).Warn("failed to cleanup temp snapshot directory")
				}
			}
			if path != "" {
				if err1 := os.RemoveAll(path); err1 != nil {
					log.G(ctx).WithError(err1).WithField("path", path).Error("failed to reclaim snapshot directory, directory may need removal")
					err = fmt.Errorf("failed to remove path: %v: %w", err1, err)
				}
			}
		}
	}()

	snapshotDir := filepath.Join(s.root, "snapshots")
	td, err = s.prepareDirectory(ctx, snapshotDir, kind)
	if err != nil {
		return nil, fmt.Errorf("failed to create prepare snapshot dir: %w", err)
	}

	if err := s.ms.WithTransaction(ctx, true, func(ctx context.Context) (err error) {

		snap, err = storage.CreateSnapshot(ctx, kind, key, parent, opts...)
		if err != nil {
			return fmt.Errorf("failed to create snapshot: %w", err)
		}

		_, info, _, err = storage.GetInfo(ctx, key)
		if err != nil {
			return fmt.Errorf("failed to get snapshot info: %w", err)
		}

		if len(snap.ParentIDs) > 0 {
			if err := upperDirectoryPermission(filepath.Join(td, "fs"), s.upperPath(snap.ParentIDs[0])); err != nil {
				return err
			}
		}

		path = filepath.Join(snapshotDir, snap.ID)
		if err = os.Rename(td, path); err != nil {
			return fmt.Errorf("failed to rename: %w", err)
		}
		td = ""

		return nil
	}); err != nil {
		return nil, err
	}
	return s.mounts(ctx, snap, info)
}

func (s *snapshotter) Prepare(ctx context.Context, key, parent string, opts ...snapshots.Opt) ([]mount.Mount, error) {
	return s.createSnapshot(ctx, snapshots.KindActive, key, parent, opts)
}

func (s *snapshotter) View(ctx context.Context, key, parent string, opts ...snapshots.Opt) ([]mount.Mount, error) {
	return s.createSnapshot(ctx, snapshots.KindView, key, parent, opts)
}

func (s *snapshotter) commitBlock(ctx context.Context, layerBlob string, id string) error {
	layer := s.writablePath(id)
	if _, err := os.Stat(layer); err != nil {
		if os.IsNotExist(err) {
			if cerr := convertDirToErofs(ctx, layerBlob, s.upperPath(id)); cerr != nil {
				return fmt.Errorf("failed to convert upper to erofs layer: %w", cerr)
			}
			// TODO: Cleanup method?
			return nil
		}
		return fmt.Errorf("failed to access writable layer %s: %w", layer, err)
	}
	m := mount.Mount{
		Source:  layer,
		Type:    "ext4",
		Options: []string{"ro", "loop", "noload"},
	}
	if err := m.Mount(s.upperPath(id)); err != nil {
		return fmt.Errorf("failed to mount writable layer %s: %w", layer, err)
	}
	log.G(ctx).WithField("target", s.upperPath(id)).Debug("Mounted writable layer for conversion")
	upperDir := filepath.Join(s.upperPath(id), "upper")
	if _, err := os.Stat(upperDir); os.IsNotExist(err) {
		mount.Unmount(s.upperPath(id), 0)
		// upper is empty, just convert the empty directory
		upperDir = s.upperPath(id)
	} else {
		defer func() {
			mount.Unmount(s.upperPath(id), 0)
		}()
	}
	if cerr := convertDirToErofs(ctx, layerBlob, upperDir); cerr != nil {
		return fmt.Errorf("failed to convert upper block to erofs layer: %w", cerr)
	}
	return nil
}

func (s *snapshotter) Commit(ctx context.Context, name, key string, opts ...snapshots.Opt) error {
	var layerBlob string
	var id string

	// Apply the overlayfs upperdir (generated by non-EROFS differs) into a EROFS blob
	// in a read transaction first since conversion could be slow.
	err := s.ms.WithTransaction(ctx, false, func(ctx context.Context) error {
		sid, _, _, err := storage.GetInfo(ctx, key)
		if err != nil {
			return err
		}
		id = sid
		return err
	})
	if err != nil {
		return err
	}

	// If the layer blob doesn't exist, which means this layer wasn't applied by
	// the EROFS differ (possibly the walking differ), convert the upperdir instead.
	layerBlob = s.layerBlobPath(id)
	if _, err := os.Stat(layerBlob); err != nil {
		if cerr := s.commitBlock(ctx, layerBlob, id); cerr != nil {
			if errdefs.IsNotImplemented(cerr) {
				return err
			}
			return cerr
		}
	}

	// Enable fsverity on the EROFS layer if configured
	if s.enableFsverity {
		if err := fsverity.Enable(layerBlob); err != nil {
			return fmt.Errorf("failed to enable fsverity: %w", err)
		}
	}

	// Set IMMUTABLE_FL on the EROFS layer to avoid artificial data loss
	if s.setImmutable {
		if err := setImmutable(layerBlob, true); err != nil {
			log.G(ctx).WithError(err).Warnf("failed to set IMMUTABLE_FL for %s", layerBlob)
		}
	}

	// Note: dm-verity formatting is handled by the EROFS differ, not here

	return s.ms.WithTransaction(ctx, true, func(ctx context.Context) error {
		if _, err := os.Stat(layerBlob); err != nil {
			return fmt.Errorf("failed to get the converted erofs blob: %w", err)
		}

		usage, err := fs.DiskUsage(ctx, layerBlob)
		if err != nil {
			return err
		}
		if _, err = storage.CommitActive(ctx, key, name, snapshots.Usage(usage), opts...); err != nil {
			return fmt.Errorf("failed to commit snapshot %s: %w", key, err)
		}
		return nil
	})
}

func (s *snapshotter) Mounts(ctx context.Context, key string) (_ []mount.Mount, err error) {
	var snap storage.Snapshot
	var info snapshots.Info
	if err := s.ms.WithTransaction(ctx, false, func(ctx context.Context) error {
		snap, err = storage.GetSnapshot(ctx, key)
		if err != nil {
			return fmt.Errorf("failed to get active mount: %w", err)
		}

		_, info, _, err = storage.GetInfo(ctx, key)
		if err != nil {
			return fmt.Errorf("failed to get snapshot info: %w", err)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return s.mounts(ctx, snap, info)
}

func (s *snapshotter) getCleanupDirectories(ctx context.Context) ([]string, error) {
	ids, err := storage.IDMap(ctx)
	if err != nil {
		return nil, err
	}

	snapshotDir := filepath.Join(s.root, "snapshots")
	fd, err := os.Open(snapshotDir)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	dirs, err := fd.Readdirnames(0)
	if err != nil {
		return nil, err
	}

	cleanup := []string{}
	for _, d := range dirs {
		if _, ok := ids[d]; ok {
			continue
		}
		cleanup = append(cleanup, filepath.Join(snapshotDir, d))
	}

	return cleanup, nil
}

// Remove abandons the snapshot identified by key. The snapshot will
// immediately become unavailable and unrecoverable. Disk space will
// be freed up on the next call to `Cleanup`.
func (s *snapshotter) Remove(ctx context.Context, key string) (err error) {
	var removals []string
	var id string
	var kind snapshots.Kind
	// Remove directories after the transaction is closed, failures must not
	// return error since the transaction is committed with the removal
	// key no longer available.
	defer func() {
		if err == nil {
			if kind == snapshots.KindCommitted {
				releaseDmverityDevice(ctx, s.layerBlobPath(id))
			}

			if err := cleanupUpper(s.upperPath(id)); err != nil {
				log.G(ctx).WithError(err).WithField("id", id).Warnf("failed to cleanup upperdir")
			}

			for _, dir := range removals {
				if err := os.RemoveAll(dir); err != nil {
					log.G(ctx).WithError(err).WithField("path", dir).Warn("failed to remove directory")
				}
			}
		}
	}()
	return s.ms.WithTransaction(ctx, true, func(ctx context.Context) error {
		id, kind, err = storage.Remove(ctx, key)
		if err != nil {
			return fmt.Errorf("failed to remove snapshot %s: %w", key, err)
		}

		removals, err = s.getCleanupDirectories(ctx)
		if err != nil {
			return fmt.Errorf("unable to get directories for removal: %w", err)
		}
		// The layer blob is only persisted for committed snapshots.
		if kind == snapshots.KindCommitted {
			// Clear IMMUTABLE_FL before removal, since this flag avoids it.
			err = setImmutable(s.layerBlobPath(id), false)
			if err != nil && !errdefs.IsNotImplemented(err) {
				return fmt.Errorf("failed to clear IMMUTABLE_FL: %w", err)
			}
		}
		return nil
	})
}

func (s *snapshotter) Stat(ctx context.Context, key string) (info snapshots.Info, err error) {
	err = s.ms.WithTransaction(ctx, false, func(ctx context.Context) error {
		_, info, _, err = storage.GetInfo(ctx, key)
		return err
	})
	if err != nil {
		return snapshots.Info{}, err
	}

	return info, nil
}

func (s *snapshotter) Update(ctx context.Context, info snapshots.Info, fieldpaths ...string) (_ snapshots.Info, err error) {
	err = s.ms.WithTransaction(ctx, true, func(ctx context.Context) error {
		info, err = storage.UpdateInfo(ctx, info, fieldpaths...)
		return err
	})
	if err != nil {
		return snapshots.Info{}, err
	}

	return info, nil
}

func (s *snapshotter) Walk(ctx context.Context, fn snapshots.WalkFunc, fs ...string) error {
	return s.ms.WithTransaction(ctx, false, func(ctx context.Context) error {
		return storage.WalkInfo(ctx, fn, fs...)
	})
}

// Usage returns the resources taken by the snapshot identified by key.
//
// For active snapshots, this will scan the usage of the overlay "diff" (aka
// "upper") directory and may take some time.
//
// For committed snapshots, the value is returned from the metadata database.
func (s *snapshotter) Usage(ctx context.Context, key string) (_ snapshots.Usage, err error) {
	var (
		usage snapshots.Usage
		info  snapshots.Info
		id    string
	)
	if err := s.ms.WithTransaction(ctx, false, func(ctx context.Context) error {
		id, info, usage, err = storage.GetInfo(ctx, key)
		return err
	}); err != nil {
		return usage, err
	}

	if info.Kind == snapshots.KindActive {
		upperPath := s.upperPath(id)
		du, err := fs.DiskUsage(ctx, upperPath)
		if err != nil {
			// TODO(stevvooe): Consider not reporting an error in this case.
			return snapshots.Usage{}, err
		}
		usage = snapshots.Usage(du)
	}
	return usage, nil
}

// Add a method to verify fsverity
func (s *snapshotter) verifyFsverity(path string) error {
	if !s.enableFsverity {
		return nil
	}
	enabled, err := fsverity.IsEnabled(path)
	if err != nil {
		return fmt.Errorf("failed to check fsverity status: %w", err)
	}
	if !enabled {
		return fmt.Errorf("fsverity is not enabled on %s", path)
	}
	return nil
}
