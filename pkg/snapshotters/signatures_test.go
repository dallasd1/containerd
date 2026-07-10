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
	"errors"
	"io"
	"testing"

	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type artifactFetcher struct {
	blobs map[digest.Digest][]byte
	refs  map[digest.Digest][]ocispec.Descriptor
}

func (f *artifactFetcher) Fetch(_ context.Context, desc ocispec.Descriptor) (io.ReadCloser, error) {
	data, ok := f.blobs[desc.Digest]
	if !ok {
		return nil, errors.New("blob not found")
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (f *artifactFetcher) FetchReferrers(_ context.Context, dgst digest.Digest, opts ...remotes.FetchReferrersOpt) ([]ocispec.Descriptor, error) {
	var cfg remotes.FetchReferrersConfig
	for _, opt := range opts {
		if err := opt(context.Background(), &cfg); err != nil {
			return nil, err
		}
	}
	allowed := map[string]bool{}
	for _, artifactType := range cfg.ArtifactTypes {
		allowed[artifactType] = true
	}
	var result []ocispec.Descriptor
	for _, desc := range f.refs[dgst] {
		if len(allowed) == 0 || allowed[desc.ArtifactType] {
			result = append(result, desc)
		}
	}
	return result, nil
}

func TestSignatureHandlerPrecomputedBundle(t *testing.T) {
	sourceManifest := descriptorFor([]byte("source manifest"), ocispec.MediaTypeImageManifest)
	sourceLayer := descriptorFor([]byte("source layer"), ocispec.MediaTypeImageLayerGzip)
	config := descriptorFor([]byte("{}"), ocispec.MediaTypeImageConfig)
	signatureBytes := []byte{0x30, 0x03, 0x01, 0x02, 0x03}
	signatureDesc := descriptorFor(signatureBytes, LayerSignatureMediaType)
	signatureDesc.Annotations = map[string]string{
		sigLayerDigestAnnotation:    sourceLayer.Digest.String(),
		sigLayerRootHashAnnotation:  "abcd",
		sigLayerSignatureAnnotation: base64.StdEncoding.EncodeToString(signatureBytes),
	}
	erofsDesc := descriptorFor([]byte("precomputed erofs"), EROFSArtifactMediaType)
	erofsDesc.Annotations = precomputedAnnotations(sourceLayer.Digest.String(), "abcd")
	treeDesc := descriptorFor([]byte("precomputed tree"), MerkleTreeArtifactMediaType)
	treeDesc.Annotations = precomputedAnnotations(sourceLayer.Digest.String(), "abcd")
	bundle := ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: SignatureArtifactType,
		Subject:      &sourceManifest,
		Layers:       []ocispec.Descriptor{signatureDesc, erofsDesc, treeDesc},
	}
	bundleBytes, err := json.Marshal(bundle)
	require.NoError(t, err)
	bundleDesc := descriptorFor(bundleBytes, ocispec.MediaTypeImageManifest)
	bundleDesc.ArtifactType = SignatureArtifactType

	fetcher := &artifactFetcher{
		blobs: map[digest.Digest][]byte{
			bundleDesc.Digest:    bundleBytes,
			signatureDesc.Digest: signatureBytes,
			erofsDesc.Digest:     []byte("precomputed erofs"),
			treeDesc.Digest:      []byte("precomputed tree"),
		},
		refs: map[digest.Digest][]ocispec.Descriptor{
			sourceManifest.Digest: {bundleDesc},
		},
	}

	originalVerifier := verifyBundleSignatureFn
	verifyBundleSignatureFn = func(context.Context, remotes.Fetcher, remotes.ReferrersFetcher, ocispec.Descriptor) error {
		return nil
	}
	t.Cleanup(func() { verifyBundleSignatureFn = originalVerifier })

	var fetched []digest.Digest
	base := images.HandlerFunc(func(_ context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		switch desc.Digest {
		case sourceManifest.Digest:
			return []ocispec.Descriptor{config, sourceLayer, sourceLayer}, nil
		default:
			fetched = append(fetched, desc.Digest)
			return nil, nil
		}
	})
	children, err := signatureHandler(base, fetcher).Handle(context.Background(), sourceManifest)
	require.NoError(t, err)
	require.Len(t, children, 3)
	layer := children[1]
	assert.Equal(t, "abcd", layer.Annotations[TargetLayerRootHashLabel])
	assert.Equal(t, base64.StdEncoding.EncodeToString(signatureBytes), layer.Annotations[TargetLayerSignatureLabel])

	gotEROFS, err := ParseTargetDescriptor(layer.Annotations[TargetLayerEROFSDescriptorLabel])
	require.NoError(t, err)
	assert.Equal(t, erofsDesc.Digest, gotEROFS.Digest)
	gotTree, err := ParseTargetDescriptor(layer.Annotations[TargetLayerMerkleTreeDescriptorLabel])
	require.NoError(t, err)
	assert.Equal(t, treeDesc.Digest, gotTree.Digest)
	assert.Equal(t, layer.Annotations, children[2].Annotations)
	assert.ElementsMatch(t, []digest.Digest{erofsDesc.Digest, treeDesc.Digest}, fetched)
}

func TestSignatureHandlerRejectsInvalidPrecomputedBundle(t *testing.T) {
	sourceManifest := descriptorFor([]byte("source manifest"), ocispec.MediaTypeImageManifest)
	bundle := ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: SignatureArtifactType,
		Subject:      &sourceManifest,
		Layers: []ocispec.Descriptor{{
			MediaType: EROFSArtifactMediaType,
			Digest:    digest.FromString("orphan erofs"),
			Size:      12,
			Annotations: precomputedAnnotations(
				digest.FromString("source layer").String(),
				"abcd",
			),
		}},
	}
	bundleBytes, err := json.Marshal(bundle)
	require.NoError(t, err)
	bundleDesc := descriptorFor(bundleBytes, ocispec.MediaTypeImageManifest)
	bundleDesc.ArtifactType = SignatureArtifactType
	fetcher := &artifactFetcher{
		blobs: map[digest.Digest][]byte{bundleDesc.Digest: bundleBytes},
		refs: map[digest.Digest][]ocispec.Descriptor{
			sourceManifest.Digest: {bundleDesc},
		},
	}
	originalVerifier := verifyBundleSignatureFn
	verifyBundleSignatureFn = func(context.Context, remotes.Fetcher, remotes.ReferrersFetcher, ocispec.Descriptor) error {
		return nil
	}
	t.Cleanup(func() { verifyBundleSignatureFn = originalVerifier })

	base := images.HandlerFunc(func(context.Context, ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		return nil, nil
	})
	_, err = signatureHandler(base, fetcher).Handle(context.Background(), sourceManifest)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "incomplete precomputed artifacts")
}

func TestSignatureHandlerRejectsUntrustedPrecomputedBundle(t *testing.T) {
	sourceManifest := descriptorFor([]byte("source manifest"), ocispec.MediaTypeImageManifest)
	bundle := ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: SignatureArtifactType,
		Subject:      &sourceManifest,
		Layers: []ocispec.Descriptor{{
			MediaType: EROFSArtifactMediaType,
			Digest:    digest.FromString("erofs"),
			Size:      5,
			Annotations: precomputedAnnotations(
				digest.FromString("source layer").String(),
				"abcd",
			),
		}},
	}
	bundleBytes, err := json.Marshal(bundle)
	require.NoError(t, err)
	bundleDesc := descriptorFor(bundleBytes, ocispec.MediaTypeImageManifest)
	bundleDesc.ArtifactType = SignatureArtifactType
	fetcher := &artifactFetcher{
		blobs: map[digest.Digest][]byte{bundleDesc.Digest: bundleBytes},
		refs: map[digest.Digest][]ocispec.Descriptor{
			sourceManifest.Digest: {bundleDesc},
		},
	}
	originalVerifier := verifyBundleSignatureFn
	verifyBundleSignatureFn = func(context.Context, remotes.Fetcher, remotes.ReferrersFetcher, ocispec.Descriptor) error {
		return errors.New("untrusted signer")
	}
	t.Cleanup(func() { verifyBundleSignatureFn = originalVerifier })

	base := images.HandlerFunc(func(context.Context, ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		return nil, nil
	})
	_, err = signatureHandler(base, fetcher).Handle(context.Background(), sourceManifest)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "untrusted signer")
}

func descriptorFor(data []byte, mediaType string) ocispec.Descriptor {
	return ocispec.Descriptor{
		MediaType: mediaType,
		Digest:    digest.FromBytes(data),
		Size:      int64(len(data)),
	}
}

func precomputedAnnotations(sourceDigest, rootHash string) map[string]string {
	return map[string]string{
		precomputedSourceLayerAnnotation: sourceDigest,
		precomputedRootHashAnnotation:    rootHash,
		precomputedLayoutAnnotation:      precomputedSeparateLayout,
	}
}
