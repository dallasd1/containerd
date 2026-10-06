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

package snapshotters

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"strings"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/internal/kmutex"
	"github.com/containerd/errdefs"
	"github.com/containerd/log"
	"github.com/containerd/platforms"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	sourceLayerDigestAnnotation = erofsAnnotationPrefix + "dmverity.source-layer-digest"
	layerRootHashAnnotation     = erofsAnnotationPrefix + "dmverity.root-hash"

	signatureArtifactType          = "application/vnd.containerd.erofs.dmverity.v1"
	erofsMetadataArtifactMediaType = "application/vnd.containerd.erofs.metadata.v1"
	merkleTreeArtifactMediaType    = "application/vnd.containerd.erofs.dmverity.merkle-tree.v1"
	layerSignatureMediaType        = "application/vnd.containerd.erofs.dmverity.layer-signature.v1+pkcs7"
	dmverityBundleContentLabel     = "containerd.io/gc.ref.content.dmverity"
	dmverityNoReferrerLabel        = "containerd.io/snapshot/erofs.dmverity.no-referrer"
)

var dmverityObservationLocks = kmutex.New()

// PrepareDmverityLayer selects the snapshot key and identity policy for a layer.
func PrepareDmverityLayer(_ context.Context, desc ocispec.Descriptor, chainID string) (snapshots.LayerPreparation, error) {
	labels, err := DmveritySnapshotLabels(desc)
	if err != nil {
		return snapshots.LayerPreparation{}, err
	}
	expectedRootHash := labels[dmverityReferrerRootHashLabel]
	expectedSigned := len(labels) > 0
	preparation := snapshots.LayerPreparation{
		Key:    chainID,
		Labels: labels,
		ValidateExisting: func(info snapshots.Info) error {
			return validateDmveritySnapshot(info.Labels, expectedRootHash, expectedSigned)
		},
	}
	if len(labels) > 0 {
		preparation.Key, err = DmveritySnapshotKey(chainID)
		if err != nil {
			return snapshots.LayerPreparation{}, err
		}
		preparation.GCQualifier = "dmverity"
	}
	return preparation, nil
}

type dmverityBundle struct {
	desc   ocispec.Descriptor
	layers map[string]*DmverityTarget
}

func fetchSignatures(
	ctx context.Context,
	fetcher remotes.Fetcher,
	store content.Store,
	subject ocispec.Descriptor,
	imageLayers map[string]struct{},
) (*dmverityBundle, bool, error) {
	refFetcher, ok := fetcher.(remotes.ReferrersFetcher)
	if !ok {
		log.G(ctx).Debug("Fetcher does not support referrers API, skipping signature fetch")
		return nil, false, nil
	}

	referrers, err := refFetcher.FetchReferrers(
		ctx,
		subject.Digest,
		remotes.WithReferrerArtifactTypes(signatureArtifactType),
	)
	if err != nil {
		return nil, false, fmt.Errorf("fetch dm-verity referrers for %s: %w", subject.Digest, err)
	}
	var selected ocispec.Descriptor
	for _, referrer := range referrers {
		if referrer.ArtifactType != signatureArtifactType {
			continue
		}
		if referrer.MediaType != ocispec.MediaTypeImageManifest {
			return nil, true, fmt.Errorf(
				"dm-verity referrer %s has unexpected media type %q",
				referrer.Digest,
				referrer.MediaType,
			)
		}
		if selected.Digest == referrer.Digest {
			continue
		}
		if selected.Digest != "" {
			return nil, true, fmt.Errorf(
				"manifest %s has multiple dm-verity referrers; the publisher contract allows one bundle per manifest",
				subject.Digest,
			)
		}
		selected = referrer
	}
	if selected.Digest == "" {
		return nil, true, nil
	}

	if err := remotes.Fetch(ctx, store, fetcher, selected); err != nil && !errdefs.IsAlreadyExists(err) {
		return nil, true, fmt.Errorf("fetch dm-verity referrer manifest %s: %w", selected.Digest, err)
	}
	info, err := readDmverityBundle(ctx, store, selected, subject, imageLayers)
	if err != nil {
		return nil, true, err
	}
	log.G(ctx).WithFields(log.Fields{
		"bundle":   selected.Digest,
		"manifest": subject.Digest,
		"layers":   len(info),
	}).Info("Validated signed EROFS dm-verity materialization bundle")
	return &dmverityBundle{
		desc:   selected,
		layers: info,
	}, true, nil
}

// readDmverityBundle validates a bundle and maps source layer digests to targets.
func readDmverityBundle(
	ctx context.Context,
	store content.Store,
	referrer, subject ocispec.Descriptor,
	imageLayers map[string]struct{},
) (map[string]*DmverityTarget, error) {
	data, err := content.ReadBlob(ctx, store, referrer)
	if err != nil {
		return nil, fmt.Errorf("read dm-verity referrer %s: %w", referrer.Digest, err)
	}
	var manifest ocispec.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parse dm-verity referrer %s: %w", referrer.Digest, err)
	}
	return readDmverityBundleManifest(manifest, referrer, subject, imageLayers)
}

func readDmverityBundleManifest(
	manifest ocispec.Manifest,
	referrer, subject ocispec.Descriptor,
	imageLayers map[string]struct{},
) (map[string]*DmverityTarget, error) {
	// Check the bundle's type and image binding before accepting its payload descriptors.
	if manifest.ArtifactType != signatureArtifactType {
		return nil, fmt.Errorf("dm-verity referrer %s has unexpected artifact type %q", referrer.Digest, manifest.ArtifactType)
	}
	if manifest.Subject == nil || manifest.Subject.Digest != subject.Digest {
		return nil, fmt.Errorf("dm-verity referrer %s subject does not match image manifest %s", referrer.Digest, subject.Digest)
	}

	// Group the bundle's payloads by the image layer they materialize.
	infoMap := make(map[string]*DmverityTarget)
	for _, layer := range manifest.Layers {
		switch layer.MediaType {
		case erofsMetadataArtifactMediaType, merkleTreeArtifactMediaType, layerSignatureMediaType:
		default:
			continue
		}

		sourceDigest := layer.Annotations[sourceLayerDigestAnnotation]
		if sourceDigest == "" {
			return nil, fmt.Errorf("bundle descriptor %s is missing its source layer digest", layer.Digest)
		}
		if _, ok := imageLayers[sourceDigest]; !ok {
			continue
		}
		if layer.Size <= 0 {
			return nil, fmt.Errorf("bundle descriptor %s has invalid payload size %d", layer.Digest, layer.Size)
		}

		info := infoMap[sourceDigest]
		if info == nil {
			info = &DmverityTarget{}
			infoMap[sourceDigest] = info
		}
		switch layer.MediaType {
		case erofsMetadataArtifactMediaType:
			if info.Metadata.Digest != "" {
				return nil, fmt.Errorf("duplicate EROFS metadata descriptor for layer %s", sourceDigest)
			}
			info.Metadata = layer
		case merkleTreeArtifactMediaType:
			if info.Tree.Digest != "" {
				return nil, fmt.Errorf("duplicate Merkle-tree descriptor for layer %s", sourceDigest)
			}
			info.Tree = layer
		case layerSignatureMediaType:
			rootHash := layer.Annotations[layerRootHashAnnotation]
			if err := validateRootHash(rootHash); err != nil {
				return nil, fmt.Errorf("signature descriptor for layer %s: %w", sourceDigest, err)
			}
			if info.Signature.Digest != "" {
				return nil, fmt.Errorf("duplicate signature descriptor for layer %s", sourceDigest)
			}
			info.RootHash = rootHash
			info.Signature = layer
		}
	}

	// Require all three payloads for every selected image layer before using the bundle.
	for sourceDigest := range imageLayers {
		info := infoMap[sourceDigest]
		if info == nil ||
			info.Metadata.Digest == "" ||
			info.Tree.Digest == "" ||
			info.Signature.Digest == "" {
			return nil, fmt.Errorf("incomplete dm-verity artifacts for layer %s", sourceDigest)
		}
	}
	return infoMap, nil
}

// AppendSignatureHandlerWrapper fetches, validates, and retains the dm-verity referrer for an image manifest.
func AppendSignatureHandlerWrapper(fetcher remotes.Fetcher, store content.Store) func(images.Handler) images.Handler {
	return func(handler images.Handler) images.Handler {
		return &dmverityHandler{handler: handler, fetcher: fetcher, store: store}
	}
}

type dmverityHandler struct {
	handler images.Handler
	fetcher remotes.Fetcher
	store   content.Store
}

// AppendCachedSignatureHandlerWrapper restores validated targets from retained referrers.
func AppendCachedSignatureHandlerWrapper(store content.Store) func(images.Handler) images.Handler {
	return func(handler images.Handler) images.Handler {
		return &dmverityHandler{handler: handler, store: store}
	}
}

// Handle processes an image manifest, fetching and validating dm-verity referrers as needed.
func (h *dmverityHandler) Handle(
	ctx context.Context,
	desc ocispec.Descriptor,
) ([]ocispec.Descriptor, error) {
	children, err := h.handler.Handle(ctx, desc)
	if err != nil {
		return nil, err
	}
	if !images.IsManifestType(desc.MediaType) {
		return children, nil
	}

	// Strip registry-supplied targets so only those validated here reach unpack.
	imageLayers := sanitizeDmverityImageLayers(children)
	requireSigned := false
	if h.fetcher != nil {
		selected, discovered, err := fetchSignatures(ctx, h.fetcher, h.store, desc, imageLayers)
		if err != nil {
			return nil, err
		}
		if discovered && selected == nil {
			signed, err := recordDmverityObservation(ctx, h.store, desc.Digest, "", imageLayers)
			if err != nil {
				return nil, fmt.Errorf("record absence of dm-verity referrer for %s: %w", desc.Digest, err)
			}
			if !signed {
				return children, nil
			}
			requireSigned = true
		}
		if selected != nil {
			// Retain the payloads before exposing their descriptors to unpack.
			if err := persistSignatureReferrer(ctx, h.handler, h.store, selected); err != nil {
				return nil, err
			}
			_, err := recordDmverityObservation(ctx, h.store, desc.Digest, selected.desc.Digest, imageLayers)
			if err != nil {
				return nil, fmt.Errorf("record dm-verity referrer for %s: %w", desc.Digest, err)
			}
			requireSigned = true
		}
	}

	info, observed, err := loadRetainedDmverityBundle(ctx, h.store, desc, imageLayers)
	if err != nil {
		return nil, err
	}
	if !observed || info == nil {
		if requireSigned {
			return nil, fmt.Errorf("manifest %s retained a signed observation without a usable bundle", desc.Digest)
		}
		return children, nil
	}
	return annotateDmverityTargets(children, info)
}

func recordDmverityObservation(
	ctx context.Context,
	store content.Store,
	subject, referrer digest.Digest,
	imageLayers map[string]struct{},
) (bool, error) {
	if err := dmverityObservationLocks.Lock(ctx, subject.String()); err != nil {
		return false, err
	}
	defer dmverityObservationLocks.Unlock(subject.String())

	info, err := store.Info(ctx, subject)
	if err != nil {
		return false, fmt.Errorf("read current dm-verity observation for manifest %s: %w", subject, err)
	}
	currentDigest, currentSigned, currentNoReferrer, err := parseDmverityObservation(info)
	if err != nil {
		return false, err
	}
	if referrer == "" {
		if currentSigned {
			return true, nil
		}
		if currentNoReferrer {
			return false, nil
		}
		err := updateDmverityObservation(ctx, store, subject, "", "true")
		return false, err
	}

	if currentSigned {
		if currentDigest == referrer {
			return true, nil
		}
		subjectDesc := ocispec.Descriptor{Digest: subject}
		retained, _, err := loadRetainedDmverityBundle(ctx, store, subjectDesc, imageLayers)
		if err != nil {
			return false, err
		}
		replacement, err := readDmverityBundle(ctx, store, ocispec.Descriptor{Digest: referrer}, subjectDesc, imageLayers)
		if err != nil {
			return false, err
		}
		for layerDigest, target := range retained {
			next := replacement[layerDigest]
			if next == nil || !strings.EqualFold(target.RootHash, next.RootHash) {
				return false, fmt.Errorf("dm-verity referrer replacement for manifest %s changes root hash for layer %s", subject, layerDigest)
			}
		}
	}

	if err := updateDmverityObservation(ctx, store, subject, referrer.String(), ""); err != nil {
		return false, err
	}
	return true, nil
}

func parseDmverityObservation(info content.Info) (digest.Digest, bool, bool, error) {
	referrerValue, hasReferrer := info.Labels[dmverityBundleContentLabel]
	noReferrerValue, hasNoReferrer := info.Labels[dmverityNoReferrerLabel]
	if hasReferrer && hasNoReferrer {
		return "", false, false, fmt.Errorf("manifest %s has conflicting dm-verity observations", info.Digest)
	}
	if hasNoReferrer {
		if noReferrerValue != "true" {
			return "", false, false, fmt.Errorf("manifest %s has an invalid no-referrer observation", info.Digest)
		}
		return "", false, true, nil
	}
	if !hasReferrer {
		return "", false, false, nil
	}
	referrer, err := digest.Parse(referrerValue)
	if err != nil {
		return "", false, false, fmt.Errorf("manifest %s has invalid retained dm-verity referrer %q: %w", info.Digest, referrerValue, err)
	}
	return referrer, true, false, nil
}

func updateDmverityObservation(
	ctx context.Context,
	store content.Store,
	subject digest.Digest,
	referrerValue, noReferrerValue string,
) error {
	_, err := store.Update(ctx, content.Info{
		Digest: subject,
		Labels: map[string]string{
			dmverityBundleContentLabel: referrerValue,
			dmverityNoReferrerLabel:    noReferrerValue,
		},
	}, "labels."+dmverityBundleContentLabel, "labels."+dmverityNoReferrerLabel)
	return err
}

func loadRetainedDmverityBundle(
	ctx context.Context,
	store content.Store,
	subject ocispec.Descriptor,
	imageLayers map[string]struct{},
) (map[string]*DmverityTarget, bool, error) {
	info, err := store.Info(ctx, subject.Digest)
	if err != nil {
		return nil, false, fmt.Errorf("read dm-verity observation for manifest %s: %w", subject.Digest, err)
	}
	referrerDigest, signed, noReferrer, err := parseDmverityObservation(info)
	if err != nil {
		return nil, false, err
	}
	if !signed && !noReferrer {
		return nil, false, nil
	}
	if noReferrer {
		return nil, true, nil
	}
	targets, err := readDmverityBundle(ctx, store, ocispec.Descriptor{Digest: referrerDigest}, subject, imageLayers)
	if err != nil {
		return nil, true, fmt.Errorf("read retained signed dm-verity bundle for manifest %s: %w", subject.Digest, err)
	}
	for layerDigest, target := range targets {
		for _, payload := range []ocispec.Descriptor{target.Metadata, target.Tree, target.Signature} {
			payloadInfo, err := store.Info(ctx, payload.Digest)
			if err != nil {
				return nil, true, fmt.Errorf(
					"read retained dm-verity payload %s for layer %s: %w",
					payload.Digest,
					layerDigest,
					err,
				)
			}
			if payloadInfo.Size != payload.Size {
				return nil, true, fmt.Errorf(
					"retained dm-verity payload %s for layer %s has size %d, expected %d",
					payload.Digest,
					layerDigest,
					payloadInfo.Size,
					payload.Size,
				)
			}
		}
	}
	return targets, true, nil
}

// DmverityManifestHasSignedReferrer reports whether discovery retained a
// validated signed bundle for the image manifest.
func DmverityManifestHasSignedReferrer(ctx context.Context, store content.Store, subject digest.Digest) (bool, error) {
	info, err := store.Info(ctx, subject)
	if err != nil {
		return false, fmt.Errorf("read dm-verity observation for manifest %s: %w", subject, err)
	}
	_, signed, _, err := parseDmverityObservation(info)
	if err != nil {
		return false, err
	}
	return signed, nil
}

// ImageHasDmverityReferrer reports whether the manifest selected for a platform
// has a retained signed dm-verity referrer observation.
func ImageHasDmverityReferrer(
	ctx context.Context,
	store content.Store,
	target ocispec.Descriptor,
	platform platforms.MatchComparer,
) (bool, error) {
	children := images.ChildrenHandler(store)
	children = images.FilterPlatforms(children, platform)
	children = images.LimitManifests(children, platform, 1)
	signed := false
	handler := images.HandlerFunc(func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		if images.IsManifestType(desc.MediaType) {
			knownSigned, err := DmverityManifestHasSignedReferrer(ctx, store, desc.Digest)
			if err != nil {
				return nil, err
			}
			signed = signed || knownSigned
		}
		return children.Handle(ctx, desc)
	})
	if err := images.Dispatch(ctx, handler, nil, target); err != nil {
		return false, err
	}
	return signed, nil
}

func sanitizeDmverityImageLayers(children []ocispec.Descriptor) map[string]struct{} {
	imageLayers := make(map[string]struct{})
	for i := range children {
		if _, ok := children[i].Annotations[TargetLayerDmverityLabel]; ok {
			children[i].Annotations = maps.Clone(children[i].Annotations)
			delete(children[i].Annotations, TargetLayerDmverityLabel)
		}
		if images.IsLayerType(children[i].MediaType) {
			imageLayers[children[i].Digest.String()] = struct{}{}
		}
	}
	return imageLayers
}

func annotateDmverityTargets(
	children []ocispec.Descriptor,
	infoMap map[string]*DmverityTarget,
) ([]ocispec.Descriptor, error) {
	for i := range children {
		child := &children[i]
		if !images.IsLayerType(child.MediaType) {
			continue
		}
		info := infoMap[child.Digest.String()]
		target, err := targetAnnotation(info)
		if err != nil {
			return nil, err
		}
		if child.Annotations == nil {
			child.Annotations = make(map[string]string)
		}
		child.Annotations[TargetLayerDmverityLabel] = target
	}
	return children, nil
}

// persistSignatureReferrer fetches and retains the selected referrer's payloads.
func persistSignatureReferrer(
	ctx context.Context,
	handler images.Handler,
	store content.Store,
	referrer *dmverityBundle,
) error {
	// Fetch the selected layers' metadata, Merkle trees, and signatures through the existing handler.
	children := make([]ocispec.Descriptor, 0, len(referrer.layers)*3)
	for _, target := range referrer.layers {
		for _, child := range []ocispec.Descriptor{target.Metadata, target.Tree, target.Signature} {
			if _, err := handler.Handle(ctx, child); err != nil {
				return fmt.Errorf("fetch dm-verity referrer content %s: %w", child.Digest, err)
			}
			children = append(children, child)
		}
	}

	// Keep the selected payloads reachable while the referrer is retained.
	labelChildren := images.SetChildrenLabels(store, images.HandlerFunc(
		func(context.Context, ocispec.Descriptor) ([]ocispec.Descriptor, error) {
			return children, nil
		},
	))
	if _, err := labelChildren.Handle(ctx, referrer.desc); err != nil {
		return fmt.Errorf("retain dm-verity referrer children for %s: %w", referrer.desc.Digest, err)
	}
	return nil
}
