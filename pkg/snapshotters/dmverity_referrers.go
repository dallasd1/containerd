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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/errdefs"
	"github.com/containerd/log"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	erofsAnnotationPrefix = "io.containerd.erofs.v1/"

	// TargetLayerDmverityLabel carries the identity of the selected referrer and this layer's signed root hash.
	TargetLayerDmverityLabel = erofsAnnotationPrefix + "dmverity.target"

	sourceLayerDigestAnnotation = erofsAnnotationPrefix + "dmverity.source-layer-digest"
	layerRootHashAnnotation     = erofsAnnotationPrefix + "dmverity.root-hash"

	signatureArtifactType          = "application/vnd.containerd.erofs.dmverity.v1"
	erofsMetadataArtifactMediaType = "application/vnd.containerd.erofs.metadata.v1"
	merkleTreeArtifactMediaType    = "application/vnd.containerd.erofs.dmverity.merkle-tree.v1"
	layerSignatureMediaType        = "application/vnd.containerd.erofs.dmverity.layer-signature.v1+pkcs7"
)

// DmverityTarget is the trusted layer annotation. Payload descriptors are
// resolved from the selected referrer in the local content store.
type DmverityTarget struct {
	RootHash  string             `json:"rootHash"`
	Metadata  ocispec.Descriptor `json:"metadata"`
	Tree      ocispec.Descriptor `json:"tree"`
	Signature ocispec.Descriptor `json:"signature"`
}

type dmverityBundle struct {
	desc   ocispec.Descriptor
	layers map[string]*DmverityTarget
}

// ParseDmverityTarget parses a target injected by a validated referrer handler.
func ParseDmverityTarget(value string) (DmverityTarget, error) {
	var target DmverityTarget
	if err := json.Unmarshal([]byte(value), &target); err != nil {
		return DmverityTarget{}, fmt.Errorf("parse dm-verity target: %w", err)
	}
	if target.RootHash == "" ||
		target.Metadata.Digest == "" ||
		target.Tree.Digest == "" ||
		target.Signature.Digest == "" {
		return DmverityTarget{}, fmt.Errorf("incomplete dm-verity target")
	}
	return target, nil
}

func targetAnnotation(info *DmverityTarget) (string, error) {
	// Carry only the fields needed to identify and read the selected payloads.
	target := DmverityTarget{
		RootHash:  info.RootHash,
		Metadata:  compactDescriptor(info.Metadata),
		Tree:      compactDescriptor(info.Tree),
		Signature: compactDescriptor(info.Signature),
	}
	data, err := json.Marshal(target)
	if err != nil {
		return "", fmt.Errorf("marshal dm-verity target: %w", err)
	}
	return string(data), nil
}

func compactDescriptor(desc ocispec.Descriptor) ocispec.Descriptor {
	return ocispec.Descriptor{
		MediaType: desc.MediaType,
		Digest:    desc.Digest,
		Size:      desc.Size,
	}
}

// fetchSignatures also reports whether the fetcher supports referrer discovery.
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
	// Reject ambiguous results instead of choosing a bundle by registry order.
	switch len(referrers) {
	case 0:
		return nil, true, nil
	case 1:
	default:
		return nil, true, fmt.Errorf(
			"manifest %s has multiple %s referrers",
			subject.Digest,
			signatureArtifactType,
		)
	}

	if referrers[0].MediaType != ocispec.MediaTypeImageManifest {
		return nil, true, fmt.Errorf(
			"dm-verity referrer %s has unexpected media type %q",
			referrers[0].Digest,
			referrers[0].MediaType,
		)
	}
	refDesc := referrers[0]
	if err := remotes.Fetch(ctx, store, fetcher, refDesc); err != nil && !errdefs.IsAlreadyExists(err) {
		return nil, true, fmt.Errorf("fetch dm-verity referrer manifest %s: %w", refDesc.Digest, err)
	}
	infos, err := readDmverityBundle(ctx, store, refDesc, subject, imageLayers)
	if err != nil {
		return nil, true, err
	}
	log.G(ctx).WithFields(log.Fields{
		"bundle":   refDesc.Digest,
		"manifest": subject.Digest,
		"layers":   len(infos),
	}).Info("Using signed EROFS dm-verity materialization bundle")
	return &dmverityBundle{desc: refDesc, layers: infos}, true, nil
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
	// Check the bundle's type and image binding before accepting its payload descriptors.
	if manifest.ArtifactType != signatureArtifactType {
		return nil, fmt.Errorf("dm-verity referrer %s has unexpected artifact type %q", referrer.Digest, manifest.ArtifactType)
	}
	if manifest.Subject == nil || manifest.Subject.Digest != subject.Digest {
		return nil, fmt.Errorf("dm-verity referrer %s subject does not match image manifest %s", referrer.Digest, subject.Digest)
	}

	// Group the bundle's payloads by the image layer they materialize.
	infos := make(map[string]*DmverityTarget)
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

		info := infos[sourceDigest]
		if info == nil {
			info = &DmverityTarget{}
			infos[sourceDigest] = info
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
		info := infos[sourceDigest]
		if info == nil ||
			info.Metadata.Digest == "" ||
			info.Tree.Digest == "" ||
			info.Signature.Digest == "" {
			return nil, fmt.Errorf("incomplete dm-verity artifacts for layer %s", sourceDigest)
		}
	}
	return infos, nil
}

func validateRootHash(rootHash string) error {
	rootDigest, err := hex.DecodeString(rootHash)
	if err != nil || len(rootDigest) != sha256.Size {
		return fmt.Errorf("invalid SHA-256 dm-verity root hash %q", rootHash)
	}
	return nil
}

// AppendSignatureHandlerWrapper fetches, validates, and retains the dm-verity referrer for an image manifest.
func AppendSignatureHandlerWrapper(fetcher remotes.Fetcher, store content.Store, selections *DmveritySelections) func(images.Handler) images.Handler {
	return func(handler images.Handler) images.Handler {
		return &dmverityHandler{handler: handler, fetcher: fetcher, store: store, selections: selections}
	}
}

type dmverityHandler struct {
	handler     images.Handler
	fetcher     remotes.Fetcher
	store       content.Store
	imageLabels map[string]string
	selections  *DmveritySelections
}

// AppendCachedSignatureHandlerWrapper restores validated targets from retained referrers.
func AppendCachedSignatureHandlerWrapper(store content.Store, imageLabels map[string]string) func(images.Handler) images.Handler {
	return func(handler images.Handler) images.Handler {
		return &dmverityHandler{handler: handler, store: store, imageLabels: imageLabels}
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
	if h.fetcher != nil {
		selected, discovered, err := fetchSignatures(ctx, h.fetcher, h.store, desc, imageLayers)
		if err != nil {
			return nil, err
		}
		if discovered && selected == nil {
			if h.selections != nil {
				h.selections.Record(desc.Digest, "")
			}
			return children, nil
		}
		if selected != nil {
			// Retain the payloads before exposing their descriptors to unpack.
			if err := persistSignatureReferrer(ctx, h.handler, h.store, selected); err != nil {
				return nil, err
			}
			if h.selections != nil {
				h.selections.Record(desc.Digest, selected.desc.Digest)
			}
			return annotateDmverityTargets(children, selected.layers)
		}
	}

	// Reuse local selections only when discovery is unsupported or not requested, not on errors.
	infos, referrer, observed, err := loadRetainedDmverityBundle(ctx, h.store, desc, imageLayers, h.imageLabels)
	if err != nil {
		return children, err
	}
	if observed && h.selections != nil {
		h.selections.Record(desc.Digest, referrer)
	}
	if infos == nil {
		return children, nil
	}
	return annotateDmverityTargets(children, infos)
}

func sanitizeDmverityImageLayers(children []ocispec.Descriptor) map[string]struct{} {
	imageLayers := make(map[string]struct{})
	for i := range children {
		children[i].Annotations = WithoutDmverityTargetAnnotation(children[i].Annotations)
		if images.IsLayerType(children[i].MediaType) {
			imageLayers[children[i].Digest.String()] = struct{}{}
		}
	}
	return imageLayers
}

func annotateDmverityTargets(
	children []ocispec.Descriptor,
	infos map[string]*DmverityTarget,
) ([]ocispec.Descriptor, error) {
	for i := range children {
		child := &children[i]
		if !images.IsLayerType(child.MediaType) {
			continue
		}
		info := infos[child.Digest.String()]
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

// WithoutDmverityTargetAnnotation returns a copy of annotations without the target.
func WithoutDmverityTargetAnnotation(annotations map[string]string) map[string]string {
	if len(annotations) == 0 {
		return nil
	}
	if _, ok := annotations[TargetLayerDmverityLabel]; !ok {
		return annotations
	}
	if len(annotations) == 1 {
		return nil
	}
	sanitized := maps.Clone(annotations)
	delete(sanitized, TargetLayerDmverityLabel)
	return sanitized
}
