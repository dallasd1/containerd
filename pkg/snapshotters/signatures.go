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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/errdefs"
	"github.com/containerd/log"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	// TargetLayerSignatureLabel contains the base64-encoded signature for dm-verity verification.
	TargetLayerSignatureLabel = "containerd.io/snapshot/dmverity.layer-signature"
	// TargetLayerRootHashLabel contains the dm-verity root hash for the layer.
	TargetLayerRootHashLabel = "containerd.io/snapshot/dmverity.layer-roothash"
	// TargetLayerEROFSDescriptorLabel contains the JSON descriptor for a precomputed EROFS blob.
	TargetLayerEROFSDescriptorLabel = "containerd.io/snapshot/dmverity.erofs-descriptor"
	// TargetLayerMerkleTreeDescriptorLabel contains the JSON descriptor for a precomputed Merkle-tree blob.
	TargetLayerMerkleTreeDescriptorLabel = "containerd.io/snapshot/dmverity.merkle-tree-descriptor"

	sigLayerDigestAnnotation    = "io.cncf.notary.dmverity.layer-digest"
	sigLayerRootHashAnnotation  = "io.cncf.notary.dmverity.layer-roothash"
	sigLayerSignatureAnnotation = "io.cncf.notary.dmverity.layer-signature"

	precomputedSourceLayerAnnotation = "io.cncf.notary.dmverity.source-layer-digest"

	// SignatureArtifactType is the artifact type for OCI referrers containing dm-verity signatures.
	SignatureArtifactType = "application/vnd.cncf.notary.dmverity.v1"
	// EROFSArtifactMediaType identifies a precomputed EROFS layer blob.
	EROFSArtifactMediaType = "application/vnd.cncf.containerd.erofs.layer.v1"
	// MerkleTreeArtifactMediaType identifies a separate dm-verity hash device.
	MerkleTreeArtifactMediaType = "application/vnd.cncf.dmverity.merkle-tree.v1"
	// LayerSignatureMediaType identifies a per-layer PKCS#7 root-hash signature.
	LayerSignatureMediaType = "application/vnd.cncf.notary.dmverity.layer-signature+pkcs7"

	ociAnnotationCreated = "org.opencontainers.image.created"
)

// LayerSignatureInfo contains signature and optional precomputed artifact information for a layer.
type LayerSignatureInfo struct {
	RootHash   string
	Signature  string
	EROFS      *ocispec.Descriptor
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

func fetchSignatures(ctx context.Context, fetcher remotes.Fetcher, manifestDigest digest.Digest) (map[string]*LayerSignatureInfo, []ocispec.Descriptor, error) {
	signatures := make(map[string]*LayerSignatureInfo)
	refFetcher, ok := fetcher.(remotes.ReferrersFetcher)
	if !ok {
		log.G(ctx).Debug("Fetcher does not support referrers API, skipping signature fetch")
		return signatures, nil, nil
	}

	referrers, err := refFetcher.FetchReferrers(ctx, manifestDigest,
		remotes.WithReferrerArtifactTypes(SignatureArtifactType))
	if err != nil {
		if errdefs.IsNotFound(err) {
			return signatures, nil, nil
		}
		return nil, nil, fmt.Errorf("fetch dm-verity referrers for %s: %w", manifestDigest, err)
	}
	if len(referrers) == 0 {
		return signatures, nil, nil
	}

	parsed := make([]referrerWithManifest, 0, len(referrers))
	for _, refDesc := range referrers {
		manifestData, err := fetchDescriptor(ctx, fetcher, refDesc)
		if err != nil {
			return nil, nil, fmt.Errorf("fetch dm-verity manifest %s: %w", refDesc.Digest, err)
		}
		var manifest ocispec.Manifest
		if err := json.Unmarshal(manifestData, &manifest); err != nil {
			return nil, nil, fmt.Errorf("parse dm-verity manifest %s: %w", refDesc.Digest, err)
		}
		if manifest.Subject == nil || manifest.Subject.Digest != manifestDigest {
			return nil, nil, fmt.Errorf("dm-verity manifest %s subject does not match image manifest %s", refDesc.Digest, manifestDigest)
		}
		var createdAt time.Time
		if created := manifest.Annotations[ociAnnotationCreated]; created != "" {
			createdAt, _ = time.Parse(time.RFC3339, created)
		}
		parsed = append(parsed, referrerWithManifest{
			desc:      refDesc,
			manifest:  manifest,
			createdAt: createdAt,
		})
	}

	var precomputed []referrerWithManifest
	var legacy []referrerWithManifest
	for _, candidate := range parsed {
		if containsPrecomputedArtifacts(candidate.manifest) {
			precomputed = append(precomputed, candidate)
		} else {
			legacy = append(legacy, candidate)
		}
	}
	if len(precomputed) > 1 {
		return nil, nil, fmt.Errorf("multiple precomputed dm-verity bundles found for %s", manifestDigest)
	}
	if len(precomputed) == 1 {
		candidate := precomputed[0]
		infos, artifactDescs, err := parsePrecomputedBundle(ctx, fetcher, candidate.manifest)
		if err != nil {
			return nil, nil, fmt.Errorf("parse precomputed dm-verity bundle %s: %w", candidate.desc.Digest, err)
		}
		log.G(ctx).WithFields(log.Fields{
			"bundle":   candidate.desc.Digest,
			"manifest": manifestDigest,
			"layers":   len(infos),
		}).Info("Using precomputed EROFS dm-verity bundle")
		return infos, artifactDescs, nil
	}

	if len(legacy) == 0 {
		return signatures, nil, nil
	}
	newest := legacy[0]
	for _, candidate := range legacy[1:] {
		if candidate.createdAt.After(newest.createdAt) {
			newest = candidate
		}
	}
	for _, layer := range newest.manifest.Layers {
		if layer.Annotations == nil {
			continue
		}
		layerDigest := layer.Annotations[sigLayerDigestAnnotation]
		rootHash := layer.Annotations[sigLayerRootHashAnnotation]
		sig := layer.Annotations[sigLayerSignatureAnnotation]
		if layerDigest != "" && rootHash != "" && sig != "" {
			signatures[layerDigest] = &LayerSignatureInfo{RootHash: rootHash, Signature: sig}
		}
	}
	return signatures, nil, nil
}

func containsPrecomputedArtifacts(manifest ocispec.Manifest) bool {
	for _, layer := range manifest.Layers {
		if layer.MediaType == EROFSArtifactMediaType || layer.MediaType == MerkleTreeArtifactMediaType {
			return true
		}
	}
	return false
}

func parsePrecomputedBundle(ctx context.Context, fetcher remotes.Fetcher, manifest ocispec.Manifest) (map[string]*LayerSignatureInfo, []ocispec.Descriptor, error) {
	infos := make(map[string]*LayerSignatureInfo)
	var artifactDescs []ocispec.Descriptor
	for _, layer := range manifest.Layers {
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
			signatureBytes, err := base64.StdEncoding.DecodeString(encodedSignature)
			if err != nil {
				return nil, nil, fmt.Errorf("decode signature for layer %s: %w", sourceDigest, err)
			}
			blob, err := fetchDescriptor(ctx, fetcher, layer)
			if err != nil {
				return nil, nil, fmt.Errorf("fetch signature blob for layer %s: %w", sourceDigest, err)
			}
			if !bytes.Equal(blob, signatureBytes) {
				return nil, nil, fmt.Errorf("signature blob does not match signed annotation for layer %s", sourceDigest)
			}
			info := getLayerInfo(infos, sourceDigest)
			if info.Signature != "" {
				return nil, nil, fmt.Errorf("duplicate signature descriptor for layer %s", sourceDigest)
			}
			info.RootHash = rootHash
			info.Signature = encodedSignature
		case EROFSArtifactMediaType, MerkleTreeArtifactMediaType:
			sourceDigest := layer.Annotations[precomputedSourceLayerAnnotation]
			if sourceDigest == "" {
				return nil, nil, fmt.Errorf("precomputed descriptor %s has invalid annotations", layer.Digest)
			}
			info := getLayerInfo(infos, sourceDigest)
			desc := layer
			if layer.MediaType == EROFSArtifactMediaType {
				if info.EROFS != nil {
					return nil, nil, fmt.Errorf("duplicate EROFS descriptor for layer %s", sourceDigest)
				}
				info.EROFS = &desc
			} else {
				if info.MerkleTree != nil {
					return nil, nil, fmt.Errorf("duplicate Merkle-tree descriptor for layer %s", sourceDigest)
				}
				info.MerkleTree = &desc
			}
			artifactDescs = append(artifactDescs, desc)
		default:
			return nil, nil, fmt.Errorf("unexpected bundle layer media type %q", layer.MediaType)
		}
	}
	for sourceDigest, info := range infos {
		if _, err := digest.Parse(sourceDigest); err != nil {
			return nil, nil, fmt.Errorf("invalid source layer digest %q: %w", sourceDigest, err)
		}
		if info.Signature == "" || info.RootHash == "" || info.EROFS == nil || info.MerkleTree == nil {
			return nil, nil, fmt.Errorf("incomplete precomputed artifacts for layer %s", sourceDigest)
		}
	}
	return infos, artifactDescs, nil
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

// AppendSignatureHandlerWrapper creates a handler that fetches signatures and
// precomputed EROFS artifacts when processing an image manifest.
func AppendSignatureHandlerWrapper(fetcher remotes.Fetcher) func(f images.Handler) images.Handler {
	return func(f images.Handler) images.Handler {
		return signatureHandler(f, fetcher)
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
			return signatureHandler(f, fetcher).Handle(ctx, desc)
		})
	}
}

func signatureHandler(f images.Handler, fetcher remotes.Fetcher) images.Handler {
	return images.HandlerFunc(func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		children, err := f.Handle(ctx, desc)
		if err != nil {
			return nil, err
		}
		if !images.IsManifestType(desc.MediaType) {
			return children, nil
		}

		signatures, artifacts, err := fetchSignatures(ctx, fetcher, desc.Digest)
		if err != nil {
			return nil, err
		}
		if len(signatures) == 0 {
			return children, nil
		}
		for _, artifact := range artifacts {
			if _, err := f.Handle(ctx, artifact); err != nil {
				return nil, fmt.Errorf("fetch precomputed artifact %s: %w", artifact.Digest, err)
			}
		}

		imageLayers := make(map[string]struct{})
		for i := range children {
			child := &children[i]
			if !images.IsLayerType(child.MediaType) {
				continue
			}
			imageLayers[child.Digest.String()] = struct{}{}
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
			if info.EROFS != nil && info.MerkleTree != nil {
				erofsDesc, err := json.Marshal(info.EROFS)
				if err != nil {
					return nil, err
				}
				treeDesc, err := json.Marshal(info.MerkleTree)
				if err != nil {
					return nil, err
				}
				child.Annotations[TargetLayerEROFSDescriptorLabel] = string(erofsDesc)
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
