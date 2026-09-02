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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/errdefs"
	"github.com/containerd/log"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	// TargetLayerSignatureLabel carries the base64-encoded PKCS#7 signature for dm-verity
	// verification as a *descriptor annotation* between the signature handler and the
	// erofs differ. It MUST NOT use the "containerd.io/snapshot/" prefix: that prefix is
	// matched by snapshots.FilterInheritedLabels and would auto-promote the value into a
	// snapshotter Info.Labels entry, where boltdb enforces a 4096-byte per-label cap.
	// Full enterprise PKCS#7 envelopes (RSA-4096 leaf + intermediates + root + RFC3161
	// timestamp counter-signature) routinely exceed 4 KiB; auto-promotion would reject
	// the pull with InvalidArgument.
	TargetLayerSignatureLabel = "containerd.io/dmverity/layer-signature"

	// TargetLayerRootHashLabel carries the dm-verity root hash as a descriptor annotation.
	// Kept under the same "containerd.io/dmverity/" prefix as the signature for symmetry,
	// so neither value is auto-promoted into snapshot labels.
	TargetLayerRootHashLabel = "containerd.io/dmverity/layer-roothash"
	// TargetLayerTarIndexDescriptorLabel contains the JSON descriptor for a precomputed EROFS tar index.
	TargetLayerTarIndexDescriptorLabel = "containerd.io/dmverity/tar-index-descriptor"
	// TargetLayerMerkleTreeDescriptorLabel contains the JSON descriptor for a precomputed Merkle-tree blob.
	TargetLayerMerkleTreeDescriptorLabel = "containerd.io/dmverity/merkle-tree-descriptor"

	// DmverityReferrerLabel roots the selected dm-verity referrer from its
	// subject manifest and marks that manifest for deferred local discovery.
	// The content GC recognizes the containerd.io/gc.ref.content prefix.
	DmverityReferrerLabel = "containerd.io/gc.ref.content.dmverity"

	sigLayerDigestAnnotation    = "io.cncf.notary.dmverity.layer-digest"
	sigLayerRootHashAnnotation  = "io.cncf.notary.dmverity.layer-roothash"
	sigLayerSignatureAnnotation = "io.cncf.notary.dmverity.layer-signature"

	precomputedSourceLayerAnnotation = "io.cncf.notary.dmverity.source-layer-digest"

	// SignatureArtifactType is the artifact type for OCI referrers containing
	// dm-verity signatures, EROFS tar indexes, and Merkle trees.
	SignatureArtifactType = "application/vnd.cncf.notary.dmverity.tar-index.v1"
	// TarIndexArtifactMediaType identifies a precomputed EROFS tar index.
	TarIndexArtifactMediaType = "application/vnd.cncf.containerd.erofs.tar-index.v1"
	// MerkleTreeArtifactMediaType identifies a separate dm-verity hash device.
	MerkleTreeArtifactMediaType = "application/vnd.cncf.dmverity.merkle-tree.v1"
	// LayerSignatureMediaType identifies a per-layer PKCS#7 root-hash signature.
	LayerSignatureMediaType = "application/vnd.cncf.notary.dmverity.layer-signature+pkcs7"

	ociAnnotationCreated = "org.opencontainers.image.created"
	tarIndexAlignment    = int64(512)
)

// LayerSignatureInfo contains the signed tar-index artifacts for a layer.
type LayerSignatureInfo struct {
	RootHash   string
	Signature  string
	TarIndex   *ocispec.Descriptor
	MerkleTree *ocispec.Descriptor
}

type referrerWithManifest struct {
	desc      ocispec.Descriptor
	manifest  ocispec.Manifest
	createdAt time.Time
}

// ParseTargetDescriptor parses a descriptor propagated through a layer annotation.
func ParseTargetDescriptor(value string) (ocispec.Descriptor, error) {
	var desc ocispec.Descriptor
	if err := json.Unmarshal([]byte(value), &desc); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("parse precomputed descriptor: %w", err)
	}
	if desc.Digest == "" || desc.Size <= 0 || desc.MediaType == "" {
		return ocispec.Descriptor{}, fmt.Errorf("invalid precomputed descriptor: %+v", desc)
	}
	if err := desc.Digest.Validate(); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("invalid precomputed descriptor digest: %w", err)
	}
	return desc, nil
}

func fetchSignatures(ctx context.Context, fetcher remotes.Fetcher, manifestDigest digest.Digest, imageLayers map[string]struct{}) (map[string]*LayerSignatureInfo, []ocispec.Descriptor, *referrerWithManifest, error) {
	signatures := make(map[string]*LayerSignatureInfo)
	refFetcher, ok := fetcher.(remotes.ReferrersFetcher)
	if !ok {
		log.G(ctx).Debug("Fetcher does not support referrers API, skipping signature fetch")
		return signatures, nil, nil, nil
	}

	referrers, err := refFetcher.FetchReferrers(ctx, manifestDigest,
		remotes.WithReferrerArtifactTypes(SignatureArtifactType))
	if err != nil {
		if errdefs.IsNotFound(err) {
			return signatures, nil, nil, nil
		}
		return nil, nil, nil, fmt.Errorf("fetch dm-verity referrers for %s: %w", manifestDigest, err)
	}
	if len(referrers) == 0 {
		return signatures, nil, nil, nil
	}

	parsed := make([]referrerWithManifest, 0, len(referrers))
	for _, refDesc := range referrers {
		manifestData, err := fetchDescriptor(ctx, fetcher, refDesc)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("fetch dm-verity manifest %s: %w", refDesc.Digest, err)
		}
		var manifest ocispec.Manifest
		if err := json.Unmarshal(manifestData, &manifest); err != nil {
			return nil, nil, nil, fmt.Errorf("parse dm-verity manifest %s: %w", refDesc.Digest, err)
		}
		if manifest.ArtifactType != SignatureArtifactType {
			return nil, nil, nil, fmt.Errorf(
				"dm-verity manifest %s has unexpected artifact type %q",
				refDesc.Digest,
				manifest.ArtifactType,
			)
		}
		if manifest.Subject == nil || manifest.Subject.Digest != manifestDigest {
			return nil, nil, nil, fmt.Errorf("dm-verity manifest %s subject does not match image manifest %s", refDesc.Digest, manifestDigest)
		}
		var createdAt time.Time
		if created := manifest.Annotations[ociAnnotationCreated]; created != "" {
			createdAt, err = time.Parse(time.RFC3339, created)
			if err != nil {
				return nil, nil, nil, fmt.Errorf(
					"dm-verity manifest %s has invalid creation time %q: %w",
					refDesc.Digest,
					created,
					err,
				)
			}
		}
		parsed = append(parsed, referrerWithManifest{
			desc:      refDesc,
			manifest:  manifest,
			createdAt: createdAt,
		})
	}

	candidateIndex := newestReferrerIndex(parsed)
	var selectedInfos map[string]*LayerSignatureInfo
	var selectedArtifacts []ocispec.Descriptor
	for i := range parsed {
		infos, artifactDescs, err := parsePrecomputedBundle(&parsed[i].manifest, imageLayers)
		if err != nil {
			return nil, nil, nil, fmt.Errorf(
				"parse precomputed dm-verity bundle %s: %w",
				parsed[i].desc.Digest,
				err,
			)
		}
		if i == candidateIndex {
			selectedInfos = infos
			selectedArtifacts = artifactDescs
		}
	}
	candidate := parsed[candidateIndex]
	if selectedInfos == nil {
		return nil, nil, nil, fmt.Errorf("selected dm-verity bundle %s was not parsed", candidate.desc.Digest)
	}
	log.G(ctx).WithFields(log.Fields{
		"bundle":   candidate.desc.Digest,
		"manifest": manifestDigest,
		"layers":   len(selectedInfos),
	}).Info("Using precomputed EROFS tar-index dm-verity bundle")
	return selectedInfos, selectedArtifacts, &candidate, nil
}

func newestReferrerIndex(candidates []referrerWithManifest) int {
	newest := 0
	for i := 1; i < len(candidates); i++ {
		if candidates[i].createdAt.After(candidates[newest].createdAt) {
			newest = i
		}
	}
	return newest
}

func parsePrecomputedBundle(manifest *ocispec.Manifest, imageLayers map[string]struct{}) (map[string]*LayerSignatureInfo, []ocispec.Descriptor, error) {
	infos := make(map[string]*LayerSignatureInfo)
	var artifactDescs []ocispec.Descriptor
	for i := range manifest.Layers {
		layer := &manifest.Layers[i]
		if layer.Annotations == nil {
			return nil, nil, fmt.Errorf("bundle layer %s has no annotations", layer.Digest)
		}
		switch layer.MediaType {
		case LayerSignatureMediaType:
			sourceDigest := layer.Annotations[sigLayerDigestAnnotation]
			rootHash := layer.Annotations[sigLayerRootHashAnnotation]
			encodedSignature := layer.Annotations[sigLayerSignatureAnnotation]
			if sourceDigest == "" || rootHash == "" || encodedSignature == "" {
				return nil, nil, fmt.Errorf("signature descriptor %s is missing required annotations", layer.Digest)
			}
			rootDigest, err := hex.DecodeString(rootHash)
			if err != nil {
				return nil, nil, fmt.Errorf(
					"decode SHA-256 root hash for layer %s: %w",
					sourceDigest,
					err,
				)
			}
			if len(rootDigest) != sha256.Size {
				return nil, nil, fmt.Errorf(
					"invalid SHA-256 root hash size for layer %s: got %d bytes, expected %d",
					sourceDigest,
					len(rootDigest),
					sha256.Size,
				)
			}
			signatureBytes, err := base64.StdEncoding.DecodeString(encodedSignature)
			if err != nil {
				return nil, nil, fmt.Errorf("decode signature for layer %s: %w", sourceDigest, err)
			}
			if len(layer.Data) > 0 {
				if err := verifyDescriptorPayload(*layer, layer.Data); err != nil {
					return nil, nil, fmt.Errorf("validate embedded signature descriptor for layer %s: %w", sourceDigest, err)
				}
				if !bytes.Equal(layer.Data, signatureBytes) {
					return nil, nil, fmt.Errorf("embedded signature data does not match signed annotation for layer %s", sourceDigest)
				}
			} else {
				if err := verifyDescriptorPayload(*layer, signatureBytes); err != nil {
					return nil, nil, fmt.Errorf("validate signature descriptor for layer %s: %w", sourceDigest, err)
				}
				// Route the verified inline signature through the normal content
				// handler without another registry fetch.
				layer.Data = signatureBytes
			}
			info := getLayerInfo(infos, sourceDigest)
			if info.Signature != "" {
				return nil, nil, fmt.Errorf("duplicate signature descriptor for layer %s", sourceDigest)
			}
			info.RootHash = rootHash
			info.Signature = encodedSignature
			artifactDescs = append(artifactDescs, *layer)
		case TarIndexArtifactMediaType, MerkleTreeArtifactMediaType:
			sourceDigest := layer.Annotations[precomputedSourceLayerAnnotation]
			if sourceDigest == "" {
				return nil, nil, fmt.Errorf("precomputed descriptor %s has invalid annotations", layer.Digest)
			}
			if err := validatePrecomputedDescriptor(*layer); err != nil {
				return nil, nil, err
			}
			info := getLayerInfo(infos, sourceDigest)
			desc := *layer
			if layer.MediaType == TarIndexArtifactMediaType {
				if info.TarIndex != nil {
					return nil, nil, fmt.Errorf("duplicate EROFS tar-index descriptor for layer %s", sourceDigest)
				}
				info.TarIndex = &desc
			} else {
				if info.MerkleTree != nil {
					return nil, nil, fmt.Errorf("duplicate Merkle-tree descriptor for layer %s", sourceDigest)
				}
				info.MerkleTree = &desc
			}
			artifactDescs = append(artifactDescs, *layer)
		default:
			return nil, nil, fmt.Errorf("unexpected bundle layer media type %q", layer.MediaType)
		}
	}
	for sourceDigest, info := range infos {
		if _, err := digest.Parse(sourceDigest); err != nil {
			return nil, nil, fmt.Errorf("invalid source layer digest %q: %w", sourceDigest, err)
		}
		if info.Signature == "" || info.RootHash == "" || info.TarIndex == nil || info.MerkleTree == nil {
			return nil, nil, fmt.Errorf("incomplete precomputed artifacts for layer %s", sourceDigest)
		}
	}
	if len(infos) == 0 {
		return nil, nil, fmt.Errorf("precomputed bundle contains no layer artifacts")
	}
	for sourceDigest := range imageLayers {
		if _, ok := infos[sourceDigest]; !ok {
			return nil, nil, fmt.Errorf("precomputed bundle does not contain source layer %s", sourceDigest)
		}
	}
	for sourceDigest := range infos {
		if _, ok := imageLayers[sourceDigest]; !ok {
			return nil, nil, fmt.Errorf("precomputed bundle contains unknown source layer %s", sourceDigest)
		}
	}
	return infos, artifactDescs, nil
}

func validatePrecomputedDescriptor(desc ocispec.Descriptor) error {
	if err := desc.Digest.Validate(); err != nil {
		return fmt.Errorf("precomputed descriptor has invalid digest %q: %w", desc.Digest, err)
	}
	if desc.Size <= 0 {
		return fmt.Errorf("precomputed descriptor %s has invalid size %d", desc.Digest, desc.Size)
	}
	if desc.MediaType == TarIndexArtifactMediaType && desc.Size%tarIndexAlignment != 0 {
		return fmt.Errorf(
			"EROFS tar-index descriptor %s has unaligned size %d",
			desc.Digest,
			desc.Size,
		)
	}
	return nil
}

func getLayerInfo(infos map[string]*LayerSignatureInfo, sourceDigest string) *LayerSignatureInfo {
	info := infos[sourceDigest]
	if info == nil {
		info = &LayerSignatureInfo{}
		infos[sourceDigest] = info
	}
	return info
}

func fetchDescriptor(ctx context.Context, fetcher remotes.Fetcher, desc ocispec.Descriptor) ([]byte, error) {
	// Referrer descriptors arrive verbatim from the registry and have not been
	// validated by the fetcher, so validate before anything touches
	// Digest.Verifier(): go-digest panics on a digest with no algorithm
	// separator or with an algorithm that is not linked into the binary.
	if err := desc.Digest.Validate(); err != nil {
		return nil, fmt.Errorf("invalid descriptor digest %q: %w", string(desc.Digest), err)
	}
	// desc.Size is likewise attacker-controlled; bound it before io.ReadAll
	// allocates on the strength of it.
	if desc.Size < 0 || desc.Size > maxManifestSize {
		return nil, fmt.Errorf("descriptor %s size %d out of range (max %d)", desc.Digest, desc.Size, maxManifestSize)
	}
	rc, err := fetcher.Fetch(ctx, desc)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	verifier := desc.Digest.Verifier()
	data, err := io.ReadAll(io.TeeReader(io.LimitReader(rc, desc.Size+1), verifier))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != desc.Size {
		return nil, fmt.Errorf("descriptor %s size mismatch: got %d, expected %d", desc.Digest, len(data), desc.Size)
	}
	if !verifier.Verified() {
		return nil, fmt.Errorf("descriptor %s digest verification failed", desc.Digest)
	}
	return data, nil
}

func verifyDescriptorPayload(desc ocispec.Descriptor, payload []byte) error {
	if err := desc.Digest.Validate(); err != nil {
		return fmt.Errorf("invalid descriptor digest %q: %w", string(desc.Digest), err)
	}
	if int64(len(payload)) != desc.Size {
		return fmt.Errorf("descriptor %s size mismatch: got %d, expected %d", desc.Digest, len(payload), desc.Size)
	}
	verifier := desc.Digest.Verifier()
	if _, err := verifier.Write(payload); err != nil {
		return fmt.Errorf("hash descriptor %s payload: %w", desc.Digest, err)
	}
	if !verifier.Verified() {
		return fmt.Errorf("descriptor %s digest verification failed", desc.Digest)
	}
	return nil
}

// AppendSignatureHandlerWrapper creates a handler that fetches signatures and
// precomputed EROFS tar-index artifacts when processing an image manifest.
func AppendSignatureHandlerWrapper(fetcher remotes.Fetcher) func(f images.Handler) images.Handler {
	return func(f images.Handler) images.Handler {
		return signatureHandler(f, fetcher, nil, false)
	}
}

// AppendRetainedSignatureHandlerWrapper additionally persists and GC-roots the
// selected referrer graph for a later deferred unpack.
func AppendRetainedSignatureHandlerWrapper(fetcher remotes.Fetcher, store content.Store) func(f images.Handler) images.Handler {
	return func(f images.Handler) images.Handler {
		return signatureHandler(f, fetcher, store, false)
	}
}

// AppendSignatureHandlerWrapperFromResolver lazily creates a fetcher from a resolver.
func AppendSignatureHandlerWrapperFromResolver(resolver remotes.Resolver, ref string) func(f images.Handler) images.Handler {
	var (
		fetcher     remotes.Fetcher
		fetcherOnce sync.Once
		fetcherErr  error
	)
	return func(f images.Handler) images.Handler {
		return images.HandlerFunc(func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
			fetcherOnce.Do(func() {
				fetcher, fetcherErr = resolver.Fetcher(ctx, ref)
			})
			if fetcherErr != nil {
				return nil, fmt.Errorf("create fetcher for dm-verity artifact lookup: %w", fetcherErr)
			}
			return signatureHandler(f, fetcher, nil, false).Handle(ctx, desc)
		})
	}
}

// AppendCachedSignatureHandlerWrapper restores dm-verity layer annotations
// from a referrer graph retained by an earlier fetch-only pull. Manifests
// without DmverityReferrerLabel are left untouched.
func AppendCachedSignatureHandlerWrapper(store content.Store) func(f images.Handler) images.Handler {
	return func(f images.Handler) images.Handler {
		return signatureHandler(f, newCachedContentStoreFetcher(store), store, true)
	}
}

// CachedSignatureAnnotations resolves the retained dm-verity bundle for an
// already-selected image manifest and returns the annotations needed to apply
// each signed layer. It performs no remote access and leaves unmarked images
// unchanged.
func CachedSignatureAnnotations(ctx context.Context, store content.Store, manifest ocispec.Descriptor) (map[digest.Digest]map[string]string, error) {
	children := AppendCachedSignatureHandlerWrapper(store)(images.ChildrenHandler(store))
	resolved, err := children.Handle(ctx, manifest)
	if err != nil {
		return nil, fmt.Errorf("resolve cached dm-verity annotations: %w", err)
	}
	annotations := map[digest.Digest]map[string]string{}
	for _, child := range resolved {
		if child.Annotations[TargetLayerSignatureLabel] != "" {
			annotations[child.Digest] = child.Annotations
		}
	}
	return annotations, nil
}

func signatureHandler(f images.Handler, fetcher remotes.Fetcher, store content.Store, cachedOnly bool) images.Handler {
	return images.HandlerFunc(func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		children, err := f.Handle(ctx, desc)
		if err != nil {
			return nil, err
		}
		if !images.IsManifestType(desc.MediaType) {
			return children, nil
		}

		if cachedOnly {
			info, err := store.Info(ctx, desc.Digest)
			if err != nil {
				return nil, fmt.Errorf("inspect cached image manifest %s: %w", desc.Digest, err)
			}
			if info.Labels[DmverityReferrerLabel] == "" {
				return children, nil
			}
		}

		imageLayers := make(map[string]struct{})
		for _, child := range children {
			if images.IsLayerType(child.MediaType) {
				imageLayers[child.Digest.String()] = struct{}{}
			}
		}

		signatures, artifacts, referrer, err := fetchSignatures(
			ctx,
			fetcher,
			desc.Digest,
			imageLayers,
		)
		if err != nil {
			return nil, err
		}
		if len(signatures) == 0 {
			return children, nil
		}

		if !cachedOnly && store != nil {
			if referrer == nil {
				return nil, fmt.Errorf("dm-verity signatures for %s have no source referrer", desc.Digest)
			}
			if err := persistSignatureReferrer(ctx, f, store, desc, *referrer); err != nil {
				return nil, err
			}
		} else if store == nil {
			for _, artifact := range artifacts {
				if _, err := f.Handle(ctx, artifact); err != nil {
					return nil, fmt.Errorf("fetch precomputed artifact %s: %w", artifact.Digest, err)
				}
			}
		}

		for i := range children {
			child := &children[i]
			if !images.IsLayerType(child.MediaType) {
				continue
			}
			info, ok := signatures[child.Digest.String()]
			if !ok {
				if len(artifacts) > 0 {
					return nil, fmt.Errorf("verified precomputed bundle does not contain layer %s", child.Digest)
				}
				continue
			}
			if child.Annotations == nil {
				child.Annotations = make(map[string]string)
			}
			child.Annotations[TargetLayerSignatureLabel] = info.Signature
			child.Annotations[TargetLayerRootHashLabel] = info.RootHash
			if info.TarIndex != nil && info.MerkleTree != nil {
				indexDesc, err := json.Marshal(info.TarIndex)
				if err != nil {
					return nil, err
				}
				treeDesc, err := json.Marshal(info.MerkleTree)
				if err != nil {
					return nil, err
				}
				child.Annotations[TargetLayerTarIndexDescriptorLabel] = string(indexDesc)
				child.Annotations[TargetLayerMerkleTreeDescriptorLabel] = string(treeDesc)
			}
		}
		if len(artifacts) > 0 {
			for sourceDigest := range signatures {
				if _, ok := imageLayers[sourceDigest]; !ok {
					return nil, fmt.Errorf("verified precomputed bundle contains unknown source layer %s", sourceDigest)
				}
			}
		}
		return children, nil
	})
}

func persistSignatureReferrer(ctx context.Context, handler images.Handler, store content.Store, subject ocispec.Descriptor, referrer referrerWithManifest) error {
	if _, err := handler.Handle(ctx, referrer.desc); err != nil {
		return fmt.Errorf("fetch dm-verity referrer manifest %s: %w", referrer.desc.Digest, err)
	}
	if err := verifyRetainedContent(ctx, store, referrer.desc); err != nil {
		return err
	}
	children := append([]ocispec.Descriptor(nil), referrer.manifest.Layers...)
	if referrer.manifest.Config.Digest != "" {
		children = append([]ocispec.Descriptor{referrer.manifest.Config}, children...)
	}
	for _, child := range children {
		if _, err := handler.Handle(ctx, child); err != nil {
			return fmt.Errorf("fetch dm-verity referrer content %s: %w", child.Digest, err)
		}
		if err := verifyRetainedContent(ctx, store, child); err != nil {
			return err
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

	_, err := store.Update(ctx, content.Info{
		Digest: subject.Digest,
		Labels: map[string]string{
			DmverityReferrerLabel: referrer.desc.Digest.String(),
		},
	}, "labels."+DmverityReferrerLabel)
	if err != nil {
		return fmt.Errorf("retain dm-verity referrer %s for image manifest %s: %w", referrer.desc.Digest, subject.Digest, err)
	}
	return nil
}

func verifyRetainedContent(ctx context.Context, store content.Store, desc ocispec.Descriptor) error {
	info, err := store.Info(ctx, desc.Digest)
	if err != nil {
		return fmt.Errorf("verify retained dm-verity content %s: %w", desc.Digest, err)
	}
	if info.Size != desc.Size {
		return fmt.Errorf(
			"verify retained dm-verity content %s: descriptor size %d does not match stored size %d",
			desc.Digest,
			desc.Size,
			info.Size,
		)
	}
	return nil
}
