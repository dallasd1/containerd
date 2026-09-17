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

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/errdefs"
	"github.com/containerd/log"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	erofsAnnotationPrefix = "io.containerd.erofs.v1/"

	// TargetLayerDmverityLabel carries the compact, validated identity of the
	// selected referrer and this layer's signed root hash.
	TargetLayerDmverityLabel = erofsAnnotationPrefix + "dmverity.target"

	sourceLayerDigestAnnotation = erofsAnnotationPrefix + "dmverity.source-layer-digest"
	layerRootHashAnnotation     = erofsAnnotationPrefix + "dmverity.root-hash"

	signatureArtifactType          = "application/vnd.containerd.erofs.dmverity.v1"
	erofsMetadataArtifactMediaType = "application/vnd.containerd.erofs.metadata.v1"
	merkleTreeArtifactMediaType    = "application/vnd.containerd.erofs.dmverity.merkle-tree.v1"
	layerSignatureMediaType        = "application/vnd.containerd.erofs.dmverity.layer-signature.v1+pkcs7"
)

// DmverityTarget is the only trusted transport annotation needed by the
// snapshot policy and EROFS differ. Payload descriptors are resolved from the
// selected referrer in the local content store.
type DmverityTarget struct {
	RootHash  string             `json:"rootHash"`
	Metadata  ocispec.Descriptor `json:"metadata"`
	Tree      ocispec.Descriptor `json:"tree"`
	Signature ocispec.Descriptor `json:"signature"`
}

type dmverityBundle struct {
	desc     ocispec.Descriptor
	manifest ocispec.Manifest
	layers   map[string]*DmverityTarget
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

func validateDmverityManifest(manifest *ocispec.Manifest, subject ocispec.Descriptor) error {
	if manifest.ArtifactType != signatureArtifactType {
		return fmt.Errorf("unexpected artifact type %q", manifest.ArtifactType)
	}
	if manifest.Subject == nil ||
		manifest.Subject.Digest != subject.Digest {
		return fmt.Errorf("subject does not match image manifest %s", subject.Digest)
	}
	return nil
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
		if errdefs.IsNotFound(err) {
			return nil, true, nil
		}
		return nil, false, fmt.Errorf("fetch dm-verity referrers for %s: %w", subject.Digest, err)
	}
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
	manifestData, err := content.ReadBlob(ctx, store, refDesc)
	if err != nil {
		return nil, true, fmt.Errorf("read dm-verity manifest %s: %w", refDesc.Digest, err)
	}
	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return nil, true, fmt.Errorf("parse dm-verity manifest %s: %w", refDesc.Digest, err)
	}
	if err := validateDmverityManifest(&manifest, subject); err != nil {
		return nil, true, fmt.Errorf("invalid dm-verity manifest %s: %w", refDesc.Digest, err)
	}

	infos, err := parseDmverityBundle(&manifest, imageLayers)
	if err != nil {
		return nil, true, fmt.Errorf("parse dm-verity bundle %s: %w", refDesc.Digest, err)
	}
	log.G(ctx).WithFields(log.Fields{
		"bundle":   refDesc.Digest,
		"manifest": subject.Digest,
		"layers":   len(infos),
	}).Info("Using signed EROFS dm-verity materialization bundle")
	return &dmverityBundle{desc: refDesc, manifest: manifest, layers: infos}, true, nil
}

func parseDmverityBundle(
	manifest *ocispec.Manifest,
	imageLayers map[string]struct{},
) (map[string]*DmverityTarget, error) {
	infos := make(map[string]*DmverityTarget)
	for i := range manifest.Layers {
		layer := manifest.Layers[i]
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

		info := getLayerInfo(infos, sourceDigest)
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

	for sourceDigest := range imageLayers {
		info := infos[sourceDigest]
		if info == nil ||
			info.Metadata.Digest == "" ||
			info.Tree.Digest == "" ||
			info.Signature.Digest == "" ||
			info.RootHash == "" {
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

func getLayerInfo(
	infos map[string]*DmverityTarget,
	sourceDigest string,
) *DmverityTarget {
	info := infos[sourceDigest]
	if info == nil {
		info = &DmverityTarget{}
		infos[sourceDigest] = info
	}
	return info
}

// AppendSignatureHandlerWrapper fetches, validates, and retains the sole v1
// dm-verity referrer for an image manifest.
func AppendSignatureHandlerWrapper(fetcher remotes.Fetcher, store content.Store) func(images.Handler) images.Handler {
	return func(handler images.Handler) images.Handler {
		return &dmverityHandler{handler: handler, fetcher: fetcher, store: store}
	}
}

type validatedDmverityReferrerHandler interface {
	images.Handler
	validatedDmverityReferrers()
}

type dmverityHandler struct {
	handler images.Handler
	fetcher remotes.Fetcher
	store   content.Store
}

func (*dmverityHandler) validatedDmverityReferrers() {}

// HasValidatedDmverityReferrers reports whether a handler validates and injects
// dm-verity targets from OCI referrers.
func HasValidatedDmverityReferrers(handler images.Handler) bool {
	_, ok := handler.(validatedDmverityReferrerHandler)
	return ok
}

// AppendCachedSignatureHandlerWrapper restores validated targets from retained referrers.
func AppendCachedSignatureHandlerWrapper(store content.Store) func(images.Handler) images.Handler {
	return func(handler images.Handler) images.Handler {
		return &dmverityHandler{handler: handler, store: store}
	}
}

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

	imageLayers := dmverityImageLayers(children)
	if h.fetcher == nil {
		infos, err := loadRetainedDmverityBundle(ctx, h.store, desc, imageLayers)
		if err != nil || infos == nil {
			return children, err
		}
		return annotateDmverityTargets(children, infos)
	}

	selected, discovered, err := fetchSignatures(ctx, h.fetcher, h.store, desc, imageLayers)
	if err != nil {
		return nil, err
	}
	if selected == nil {
		if discovered {
			if err := clearRetainedDmverityReferrer(ctx, h.store, desc.Digest); err != nil {
				return nil, fmt.Errorf("clear retained dm-verity referrer for %s: %w", desc.Digest, err)
			}
		}
		return children, nil
	}
	if err := persistSignatureReferrer(ctx, h.handler, h.store, desc, selected); err != nil {
		return nil, err
	}
	return annotateDmverityTargets(children, selected.layers)
}

func dmverityImageLayers(children []ocispec.Descriptor) map[string]struct{} {
	imageLayers := make(map[string]struct{})
	for i := range children {
		children[i].Annotations = WithoutDmverityAnnotations(children[i].Annotations)
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

func persistSignatureReferrer(
	ctx context.Context,
	handler images.Handler,
	store content.Store,
	subject ocispec.Descriptor,
	referrer *dmverityBundle,
) error {
	selected := make(map[string]struct{}, len(referrer.layers)*3)
	for _, target := range referrer.layers {
		for _, desc := range []ocispec.Descriptor{target.Metadata, target.Tree, target.Signature} {
			selected[desc.MediaType+"\x00"+desc.Digest.String()] = struct{}{}
		}
	}

	children := make([]ocispec.Descriptor, 0, len(selected))
	for _, desc := range referrer.manifest.Layers {
		if _, ok := selected[desc.MediaType+"\x00"+desc.Digest.String()]; ok {
			children = append(children, desc)
		}
	}
	for _, child := range children {
		if _, err := handler.Handle(ctx, child); err != nil {
			return fmt.Errorf("fetch dm-verity referrer content %s: %w", child.Digest, err)
		}
	}

	labelChildren := images.SetChildrenLabels(store, images.HandlerFunc(
		func(context.Context, ocispec.Descriptor) ([]ocispec.Descriptor, error) {
			return children, nil
		},
	))
	if _, err := labelChildren.Handle(ctx, referrer.desc); err != nil {
		return fmt.Errorf("retain dm-verity referrer children for %s: %w", referrer.desc.Digest, err)
	}

	if err := updateRetainedDmverityReferrer(ctx, store, subject.Digest, referrer.desc.Digest); err != nil {
		return fmt.Errorf(
			"retain dm-verity referrer %s for image manifest %s: %w",
			referrer.desc.Digest,
			subject.Digest,
			err,
		)
	}
	return nil
}

// WithoutDmverityAnnotations removes the target annotation that is trusted
// only when injected by a validated OCI referrer handler.
func WithoutDmverityAnnotations(annotations map[string]string) map[string]string {
	if len(annotations) == 0 {
		return nil
	}
	if _, ok := annotations[TargetLayerDmverityLabel]; !ok {
		return annotations
	}
	sanitized := make(map[string]string, len(annotations))
	for key, value := range annotations {
		if key != TargetLayerDmverityLabel {
			sanitized[key] = value
		}
	}
	if len(sanitized) == 0 {
		return nil
	}
	return sanitized
}
