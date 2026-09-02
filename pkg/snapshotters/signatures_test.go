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
	"strings"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/containerd/platforms"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type artifactFetcher struct {
	blobs              map[digest.Digest][]byte
	refs               map[digest.Digest][]ocispec.Descriptor
	rejectExternalURLs bool
}

var (
	testRootHashA = digest.FromString("test root hash A").Encoded()
	testRootHashB = digest.FromString("test root hash B").Encoded()
)

func (f *artifactFetcher) Fetch(_ context.Context, desc ocispec.Descriptor) (io.ReadCloser, error) {
	if f.rejectExternalURLs && len(desc.URLs) > 0 {
		return nil, errors.New("external descriptor URL was not removed")
	}
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
		sigLayerRootHashAnnotation:  testRootHashA,
		sigLayerSignatureAnnotation: base64.StdEncoding.EncodeToString(signatureBytes),
	}
	indexBytes := make([]byte, tarIndexAlignment)
	copy(indexBytes, "precomputed tar index")
	indexDesc := descriptorFor(indexBytes, TarIndexArtifactMediaType)
	indexDesc.Annotations = precomputedAnnotations(sourceLayer.Digest.String())
	treeDesc := descriptorFor([]byte("precomputed tree"), MerkleTreeArtifactMediaType)
	treeDesc.Annotations = precomputedAnnotations(sourceLayer.Digest.String())
	bundle := ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: SignatureArtifactType,
		Subject:      &sourceManifest,
		Layers:       []ocispec.Descriptor{signatureDesc, indexDesc, treeDesc},
	}
	bundleBytes, err := json.Marshal(bundle)
	require.NoError(t, err)
	bundleDesc := descriptorFor(bundleBytes, ocispec.MediaTypeImageManifest)
	bundleDesc.ArtifactType = SignatureArtifactType

	fetcher := &artifactFetcher{
		blobs: map[digest.Digest][]byte{
			bundleDesc.Digest: bundleBytes,
			indexDesc.Digest:  indexBytes,
			treeDesc.Digest:   []byte("precomputed tree"),
		},
		refs: map[digest.Digest][]ocispec.Descriptor{
			sourceManifest.Digest: {bundleDesc},
		},
	}

	var fetched []digest.Digest
	var inlineSignature []byte
	base := images.HandlerFunc(func(_ context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		switch desc.Digest {
		case sourceManifest.Digest:
			return []ocispec.Descriptor{config, sourceLayer, sourceLayer}, nil
		default:
			fetched = append(fetched, desc.Digest)
			if desc.MediaType == LayerSignatureMediaType {
				inlineSignature = append([]byte(nil), desc.Data...)
			}
			return nil, nil
		}
	})
	children, err := signatureHandler(base, fetcher, nil, false).Handle(context.Background(), sourceManifest)
	require.NoError(t, err)
	require.Len(t, children, 3)
	layer := children[1]
	assert.Equal(t, testRootHashA, layer.Annotations[TargetLayerRootHashLabel])
	assert.Equal(t, base64.StdEncoding.EncodeToString(signatureBytes), layer.Annotations[TargetLayerSignatureLabel])

	gotIndex, err := ParseTargetDescriptor(layer.Annotations[TargetLayerTarIndexDescriptorLabel])
	require.NoError(t, err)
	assert.Equal(t, indexDesc.Digest, gotIndex.Digest)
	gotTree, err := ParseTargetDescriptor(layer.Annotations[TargetLayerMerkleTreeDescriptorLabel])
	require.NoError(t, err)
	assert.Equal(t, treeDesc.Digest, gotTree.Digest)
	assert.Equal(t, layer.Annotations, children[2].Annotations)
	assert.ElementsMatch(t, []digest.Digest{signatureDesc.Digest, indexDesc.Digest, treeDesc.Digest}, fetched)
	assert.Equal(t, signatureBytes, inlineSignature)
}

func TestVerifyDescriptorPayload(t *testing.T) {
	payload := []byte("inline signature")
	valid := descriptorFor(payload, LayerSignatureMediaType)

	tests := []struct {
		name    string
		desc    ocispec.Descriptor
		payload []byte
		wantErr string
	}{
		{
			name:    "valid",
			desc:    valid,
			payload: payload,
		},
		{
			name: "invalid digest",
			desc: ocispec.Descriptor{
				Digest: digest.Digest("invalid"),
				Size:   int64(len(payload)),
			},
			payload: payload,
			wantErr: "invalid descriptor digest",
		},
		{
			name: "size mismatch",
			desc: ocispec.Descriptor{
				Digest: valid.Digest,
				Size:   valid.Size + 1,
			},
			payload: payload,
			wantErr: "size mismatch",
		},
		{
			name: "digest mismatch",
			desc: ocispec.Descriptor{
				Digest: digest.FromString("different payload"),
				Size:   int64(len(payload)),
			},
			payload: payload,
			wantErr: "digest verification failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyDescriptorPayload(tt.desc, tt.payload)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestSignatureHandlerPersistsBundleForDeferredUnpack(t *testing.T) {
	ctx := context.Background()
	configBytes := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}`)
	config := descriptorFor(configBytes, ocispec.MediaTypeImageConfig)
	layerBytes := []byte("source layer")
	sourceLayer := descriptorFor(layerBytes, ocispec.MediaTypeImageLayerGzip)
	sourceManifestBytes, err := json.Marshal(ocispec.Manifest{
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    config,
		Layers:    []ocispec.Descriptor{sourceLayer},
	})
	require.NoError(t, err)
	sourceManifest := descriptorFor(sourceManifestBytes, ocispec.MediaTypeImageManifest)
	bundle := newPrecomputedBundle(t, sourceManifest, sourceLayer, "selected", testRootHashA, time.Now().UTC())

	remoteBlobs := mergeBlobMaps(bundle.blobs, map[digest.Digest][]byte{
		sourceManifest.Digest: sourceManifestBytes,
		config.Digest:         configBytes,
		sourceLayer.Digest:    layerBytes,
	})
	delete(remoteBlobs, bundle.signature.Digest)
	fetcher := &artifactFetcher{
		blobs: remoteBlobs,
		refs: map[digest.Digest][]ocispec.Descriptor{
			sourceManifest.Digest: {bundle.descriptor},
		},
	}
	cs, err := local.NewLabeledStore(t.TempDir(), newMemoryLabelStore())
	require.NoError(t, err)
	base := images.Handlers(
		remotes.FetchHandler(cs, fetcher),
		images.SetChildrenLabels(cs, images.ChildrenHandler(cs)),
	)

	children, err := signatureHandler(base, fetcher, cs, false).Handle(ctx, sourceManifest)
	require.NoError(t, err)
	require.Len(t, children, 2)
	assert.Equal(t, testRootHashA, children[1].Annotations[TargetLayerRootHashLabel])

	subjectInfo, err := cs.Info(ctx, sourceManifest.Digest)
	require.NoError(t, err)
	assert.Equal(t, bundle.descriptor.Digest.String(), subjectInfo.Labels[DmverityReferrerLabel])

	referrerInfo, err := cs.Info(ctx, bundle.descriptor.Digest)
	require.NoError(t, err)
	var retained []string
	for key, value := range referrerInfo.Labels {
		if strings.HasPrefix(key, "containerd.io/gc.ref.content") {
			retained = append(retained, value)
		}
	}
	assert.Len(t, retained, 4)
	for dgst := range bundle.blobs {
		_, err := cs.Info(ctx, dgst)
		require.NoError(t, err, "bundle content %s was not persisted", dgst)
	}

	deferred := AppendCachedSignatureHandlerWrapper(cs)(images.ChildrenHandler(cs))
	deferredChildren, err := deferred.Handle(ctx, sourceManifest)
	require.NoError(t, err)
	require.Len(t, deferredChildren, 2)
	assert.Equal(t, testRootHashA, deferredChildren[1].Annotations[TargetLayerRootHashLabel])
	assert.NotEmpty(t, deferredChildren[1].Annotations[TargetLayerTarIndexDescriptorLabel])

	annotations, err := CachedSignatureAnnotations(ctx, cs, sourceManifest)
	require.NoError(t, err)
	require.Contains(t, annotations, sourceLayer.Digest)
	assert.Equal(t, testRootHashA, annotations[sourceLayer.Digest][TargetLayerRootHashLabel])

	require.NoError(t, content.WriteBlob(ctx, cs, "source config", bytes.NewReader(configBytes), config))
	require.NoError(t, content.WriteBlob(ctx, cs, "source layer", bytes.NewReader(layerBytes), sourceLayer))
	otherConfigBytes := []byte(`{"architecture":"arm64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}`)
	otherConfig := descriptorFor(otherConfigBytes, ocispec.MediaTypeImageConfig)
	otherLayerBytes := []byte("other source layer")
	otherLayer := descriptorFor(otherLayerBytes, ocispec.MediaTypeImageLayerGzip)
	otherManifestBytes, err := json.Marshal(ocispec.Manifest{
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    otherConfig,
		Layers:    []ocispec.Descriptor{otherLayer},
	})
	require.NoError(t, err)
	otherManifest := descriptorFor(otherManifestBytes, ocispec.MediaTypeImageManifest)
	require.NoError(t, content.WriteBlob(ctx, cs, "other config", bytes.NewReader(otherConfigBytes), otherConfig))
	require.NoError(t, content.WriteBlob(ctx, cs, "other layer", bytes.NewReader(otherLayerBytes), otherLayer))
	require.NoError(t, content.WriteBlob(ctx, cs, "other manifest", bytes.NewReader(otherManifestBytes), otherManifest))

	sourceForIndex := sourceManifest
	sourceForIndex.Platform = &ocispec.Platform{OS: "linux", Architecture: "amd64"}
	indexBytes, err := json.Marshal(ocispec.Index{
		MediaType: ocispec.MediaTypeImageIndex,
		// A platform-less entry precedes the selected manifest. Deferred
		// reconstruction must use the exact descriptor chosen for unpack.
		Manifests: []ocispec.Descriptor{otherManifest, sourceForIndex},
	})
	require.NoError(t, err)
	index := descriptorFor(indexBytes, ocispec.MediaTypeImageIndex)
	require.NoError(t, content.WriteBlob(ctx, cs, "index", bytes.NewReader(indexBytes), index))
	selected, _, err := images.ManifestWithDescriptor(ctx, cs, index, platforms.Only(ocispec.Platform{
		OS:           "linux",
		Architecture: "amd64",
	}))
	require.NoError(t, err)
	assert.Equal(t, sourceManifest.Digest, selected.Digest)
	indexAnnotations, err := CachedSignatureAnnotations(ctx, cs, selected)
	require.NoError(t, err)
	assert.Equal(t, testRootHashA, indexAnnotations[sourceLayer.Digest][TargetLayerRootHashLabel])

	_, err = cs.Update(ctx, content.Info{
		Digest: sourceManifest.Digest,
		Labels: map[string]string{DmverityReferrerLabel: ""},
	}, "labels."+DmverityReferrerLabel)
	require.NoError(t, err)
	unmarkedChildren, err := deferred.Handle(ctx, sourceManifest)
	require.NoError(t, err)
	require.Len(t, unmarkedChildren, 2)
	assert.Empty(t, unmarkedChildren[1].Annotations[TargetLayerSignatureLabel])
}

func TestPersistSignatureReferrerAllowsOmittedConfig(t *testing.T) {
	ctx := context.Background()
	subjectBytes := []byte("subject manifest")
	subject := descriptorFor(subjectBytes, ocispec.MediaTypeImageManifest)
	layerBytes := []byte("artifact layer")
	layer := descriptorFor(layerBytes, LayerSignatureMediaType)
	manifest := ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: SignatureArtifactType,
		Subject:      &subject,
		Layers:       []ocispec.Descriptor{layer},
	}
	manifestBytes, err := json.Marshal(manifest)
	require.NoError(t, err)
	referrer := descriptorFor(manifestBytes, ocispec.MediaTypeImageManifest)
	referrer.ArtifactType = SignatureArtifactType

	fetcher := &artifactFetcher{blobs: map[digest.Digest][]byte{
		referrer.Digest: manifestBytes,
		layer.Digest:    layerBytes,
	}}
	cs, err := local.NewLabeledStore(t.TempDir(), newMemoryLabelStore())
	require.NoError(t, err)
	require.NoError(t, content.WriteBlob(ctx, cs, "subject", bytes.NewReader(subjectBytes), subject))

	err = persistSignatureReferrer(
		ctx,
		remotes.FetchHandler(cs, fetcher),
		cs,
		subject,
		referrerWithManifest{desc: referrer, manifest: manifest},
	)
	require.NoError(t, err)
	info, err := cs.Info(ctx, subject.Digest)
	require.NoError(t, err)
	assert.Equal(t, referrer.Digest.String(), info.Labels[DmverityReferrerLabel])
}

func TestPersistSignatureReferrerRejectsMissingArtifactContent(t *testing.T) {
	ctx := context.Background()
	subjectBytes := []byte("subject manifest")
	subject := descriptorFor(subjectBytes, ocispec.MediaTypeImageManifest)
	layer := descriptorFor([]byte("missing artifact layer"), TarIndexArtifactMediaType)
	manifest := ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: SignatureArtifactType,
		Subject:      &subject,
		Layers:       []ocispec.Descriptor{layer},
	}
	manifestBytes, err := json.Marshal(manifest)
	require.NoError(t, err)
	referrer := descriptorFor(manifestBytes, ocispec.MediaTypeImageManifest)
	referrer.ArtifactType = SignatureArtifactType

	cs, err := local.NewLabeledStore(t.TempDir(), newMemoryLabelStore())
	require.NoError(t, err)
	require.NoError(t, content.WriteBlob(ctx, cs, "subject", bytes.NewReader(subjectBytes), subject))
	require.NoError(t, content.WriteBlob(ctx, cs, "referrer", bytes.NewReader(manifestBytes), referrer))

	err = persistSignatureReferrer(
		ctx,
		images.HandlerFunc(func(context.Context, ocispec.Descriptor) ([]ocispec.Descriptor, error) {
			return nil, nil
		}),
		cs,
		subject,
		referrerWithManifest{desc: referrer, manifest: manifest},
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verify retained dm-verity content")
	info, err := cs.Info(ctx, subject.Digest)
	require.NoError(t, err)
	assert.Empty(t, info.Labels[DmverityReferrerLabel])
}

func TestPersistSignatureReferrerMaterializesEmbeddedContent(t *testing.T) {
	ctx := context.Background()
	subjectBytes := []byte("subject manifest")
	subject := descriptorFor(subjectBytes, ocispec.MediaTypeImageManifest)
	layerBytes := []byte("embedded artifact layer")
	layer := descriptorFor(layerBytes, LayerSignatureMediaType)
	layer.Data = layerBytes
	manifest := ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: SignatureArtifactType,
		Subject:      &subject,
		Layers:       []ocispec.Descriptor{layer},
	}
	manifestBytes, err := json.Marshal(manifest)
	require.NoError(t, err)
	referrer := descriptorFor(manifestBytes, ocispec.MediaTypeImageManifest)
	referrer.ArtifactType = SignatureArtifactType

	cs, err := local.NewLabeledStore(t.TempDir(), newMemoryLabelStore())
	require.NoError(t, err)
	require.NoError(t, content.WriteBlob(ctx, cs, "subject", bytes.NewReader(subjectBytes), subject))
	require.NoError(t, content.WriteBlob(ctx, cs, "referrer", bytes.NewReader(manifestBytes), referrer))

	err = persistSignatureReferrer(
		ctx,
		images.HandlerFunc(func(context.Context, ocispec.Descriptor) ([]ocispec.Descriptor, error) {
			return nil, nil
		}),
		cs,
		subject,
		referrerWithManifest{desc: referrer, manifest: manifest},
	)
	require.NoError(t, err)
	_, err = cs.Info(ctx, layer.Digest)
	require.NoError(t, err)
	info, err := cs.Info(ctx, subject.Digest)
	require.NoError(t, err)
	assert.Equal(t, referrer.Digest.String(), info.Labels[DmverityReferrerLabel])
}

func TestSignatureHandlerRejectsInvalidPrecomputedBundle(t *testing.T) {
	sourceManifest := descriptorFor([]byte("source manifest"), ocispec.MediaTypeImageManifest)
	bundle := ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: SignatureArtifactType,
		Subject:      &sourceManifest,
		Layers: []ocispec.Descriptor{{
			MediaType:   TarIndexArtifactMediaType,
			Digest:      digest.FromString("orphan tar index"),
			Size:        tarIndexAlignment,
			Annotations: precomputedAnnotations(digest.FromString("source layer").String()),
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
	base := images.HandlerFunc(func(context.Context, ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		return nil, nil
	})
	_, err = signatureHandler(base, fetcher, nil, false).Handle(context.Background(), sourceManifest)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "incomplete precomputed artifacts")
}

func TestFetchSignaturesSelectsNewestPrecomputedBundle(t *testing.T) {
	sourceManifest := descriptorFor([]byte("source manifest"), ocispec.MediaTypeImageManifest)
	sourceLayer := descriptorFor([]byte("source layer"), ocispec.MediaTypeImageLayerGzip)
	older := newPrecomputedBundle(t, sourceManifest, sourceLayer, "older", testRootHashA, time.Date(2026, 7, 20, 1, 0, 0, 0, time.UTC))
	newer := newPrecomputedBundle(t, sourceManifest, sourceLayer, "newer", testRootHashB, time.Date(2026, 7, 20, 2, 0, 0, 0, time.UTC))

	fetcher := &artifactFetcher{
		blobs: mergeBlobMaps(older.blobs, newer.blobs),
		refs: map[digest.Digest][]ocispec.Descriptor{
			sourceManifest.Digest: {older.descriptor, newer.descriptor},
		},
	}

	signatures, artifacts, selected, err := fetchSignatures(
		context.Background(),
		fetcher,
		sourceManifest.Digest,
		layerDigestSet(sourceLayer),
	)
	require.NoError(t, err)
	require.Contains(t, signatures, sourceLayer.Digest.String())
	assert.Equal(t, testRootHashB, signatures[sourceLayer.Digest.String()].RootHash)
	expectedSignature := newer.signature
	expectedSignature.Data = newer.blobs[newer.signature.Digest]
	assert.ElementsMatch(t, []ocispec.Descriptor{expectedSignature, newer.tarIndex, newer.tree}, artifacts)
	require.NotNil(t, selected)
	assert.Equal(t, newer.descriptor.Digest, selected.desc.Digest)
}

func TestFetchSignaturesRejectsResourceAmplification(t *testing.T) {
	sourceManifest := descriptorFor([]byte("source manifest"), ocispec.MediaTypeImageManifest)

	t.Run("candidate count", func(t *testing.T) {
		refs := make([]ocispec.Descriptor, maxSignatureReferrers+1)
		for i := range refs {
			refs[i] = descriptorFor([]byte{byte(i)}, ocispec.MediaTypeImageManifest)
			refs[i].ArtifactType = SignatureArtifactType
		}
		fetcher := &artifactFetcher{
			refs: map[digest.Digest][]ocispec.Descriptor{
				sourceManifest.Digest: refs,
			},
		}

		_, _, _, err := fetchSignatures(
			context.Background(),
			fetcher,
			sourceManifest.Digest,
			map[string]struct{}{},
		)
		require.ErrorContains(t, err, "too many dm-verity referrers")
	})

	t.Run("aggregate manifest size", func(t *testing.T) {
		refs := make([]ocispec.Descriptor, maxSignatureManifestBytes/maxManifestSize+1)
		for i := range refs {
			refs[i] = ocispec.Descriptor{
				MediaType:    ocispec.MediaTypeImageManifest,
				Digest:       digest.FromString(string(rune('a' + i))),
				Size:         maxManifestSize,
				ArtifactType: SignatureArtifactType,
			}
		}
		fetcher := &artifactFetcher{
			refs: map[digest.Digest][]ocispec.Descriptor{
				sourceManifest.Digest: refs,
			},
		}

		_, _, _, err := fetchSignatures(
			context.Background(),
			fetcher,
			sourceManifest.Digest,
			map[string]struct{}{},
		)
		require.ErrorContains(t, err, "aggregate dm-verity manifest size")
	})
}

func TestFetchSignaturesUsesRepositoryDescriptors(t *testing.T) {
	sourceManifest := descriptorFor([]byte("source manifest"), ocispec.MediaTypeImageManifest)
	sourceLayer := descriptorFor([]byte("source layer"), ocispec.MediaTypeImageLayerGzip)
	bundle := newPrecomputedBundle(t, sourceManifest, sourceLayer, "urls", testRootHashA, time.Now().UTC())

	var manifest ocispec.Manifest
	require.NoError(t, json.Unmarshal(bundle.blobs[bundle.descriptor.Digest], &manifest))
	manifest.Config.URLs = []string{"http://config.invalid/content"}
	for i := range manifest.Layers {
		manifest.Layers[i].URLs = []string{"http://artifact.invalid/content"}
	}
	manifestBytes, err := json.Marshal(manifest)
	require.NoError(t, err)
	bundle.descriptor = descriptorFor(manifestBytes, ocispec.MediaTypeImageManifest)
	bundle.descriptor.ArtifactType = SignatureArtifactType
	bundle.descriptor.URLs = []string{"http://manifest.invalid/content"}

	fetcher := &artifactFetcher{
		blobs: mergeBlobMaps(bundle.blobs, map[digest.Digest][]byte{
			bundle.descriptor.Digest: manifestBytes,
		}),
		refs: map[digest.Digest][]ocispec.Descriptor{
			sourceManifest.Digest: {bundle.descriptor},
		},
		rejectExternalURLs: true,
	}

	_, artifacts, selected, err := fetchSignatures(
		context.Background(),
		fetcher,
		sourceManifest.Digest,
		layerDigestSet(sourceLayer),
	)
	require.NoError(t, err)
	require.NotNil(t, selected)
	assert.Empty(t, selected.desc.URLs)
	assert.Empty(t, selected.manifest.Config.URLs)
	for _, artifact := range artifacts {
		assert.Empty(t, artifact.URLs)
	}
}

func TestFetchSignaturesFailsClosedOnInvalidNewestPrecomputedBundle(t *testing.T) {
	sourceManifest := descriptorFor([]byte("source manifest"), ocispec.MediaTypeImageManifest)
	sourceLayer := descriptorFor([]byte("source layer"), ocispec.MediaTypeImageLayerGzip)
	older := newPrecomputedBundle(t, sourceManifest, sourceLayer, "older", testRootHashA, time.Date(2026, 7, 20, 1, 0, 0, 0, time.UTC))

	signatureBytes := []byte("orphan signature")
	orphanSignature := descriptorFor(signatureBytes, LayerSignatureMediaType)
	orphanSignature.Annotations = map[string]string{
		sigLayerDigestAnnotation:    sourceLayer.Digest.String(),
		sigLayerRootHashAnnotation:  testRootHashB,
		sigLayerSignatureAnnotation: base64.StdEncoding.EncodeToString(signatureBytes),
	}
	invalidManifest := ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: SignatureArtifactType,
		Subject:      &sourceManifest,
		Layers:       []ocispec.Descriptor{orphanSignature},
		Annotations: map[string]string{
			ociAnnotationCreated: time.Date(2026, 7, 20, 2, 0, 0, 0, time.UTC).Format(time.RFC3339),
		},
	}
	invalidBytes, err := json.Marshal(invalidManifest)
	require.NoError(t, err)
	invalidDescriptor := descriptorFor(invalidBytes, ocispec.MediaTypeImageManifest)
	invalidDescriptor.ArtifactType = SignatureArtifactType

	fetcher := &artifactFetcher{
		blobs: mergeBlobMaps(older.blobs, map[digest.Digest][]byte{
			invalidDescriptor.Digest: invalidBytes,
			orphanSignature.Digest:   signatureBytes,
		}),
		refs: map[digest.Digest][]ocispec.Descriptor{
			sourceManifest.Digest: {older.descriptor, invalidDescriptor},
		},
	}

	_, _, _, err = fetchSignatures(
		context.Background(),
		fetcher,
		sourceManifest.Digest,
		layerDigestSet(sourceLayer),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), invalidDescriptor.Digest.String())
	assert.Contains(t, err.Error(), "incomplete precomputed artifacts")
}

func TestFetchSignaturesRejectsUnexpectedManifestArtifactType(t *testing.T) {
	sourceManifest := descriptorFor([]byte("source manifest"), ocispec.MediaTypeImageManifest)
	bundle := ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: "application/vnd.example.unexpected",
		Subject:      &sourceManifest,
	}
	bundleBytes, err := json.Marshal(bundle)
	require.NoError(t, err)
	bundleDesc := descriptorFor(bundleBytes, ocispec.MediaTypeImageManifest)
	// The registry descriptor passes the artifact-type filter, but the fetched
	// manifest is authoritative and must agree.
	bundleDesc.ArtifactType = SignatureArtifactType
	fetcher := &artifactFetcher{
		blobs: map[digest.Digest][]byte{bundleDesc.Digest: bundleBytes},
		refs: map[digest.Digest][]ocispec.Descriptor{
			sourceManifest.Digest: {bundleDesc},
		},
	}

	_, _, _, err = fetchSignatures(
		context.Background(),
		fetcher,
		sourceManifest.Digest,
		map[string]struct{}{},
	)
	require.ErrorContains(t, err, "unexpected artifact type")
}

func TestFetchSignaturesRejectsMalformedOlderPrecomputedBundle(t *testing.T) {
	sourceManifest := descriptorFor([]byte("source manifest"), ocispec.MediaTypeImageManifest)
	sourceLayer := descriptorFor([]byte("source layer"), ocispec.MediaTypeImageLayerGzip)
	older := newPrecomputedBundle(t, sourceManifest, sourceLayer, "older", testRootHashA, time.Date(2026, 7, 20, 1, 0, 0, 0, time.UTC))
	newer := newPrecomputedBundle(t, sourceManifest, sourceLayer, "newer", testRootHashB, time.Date(2026, 7, 20, 2, 0, 0, 0, time.UTC))

	var olderManifest ocispec.Manifest
	require.NoError(t, json.Unmarshal(older.blobs[older.descriptor.Digest], &olderManifest))
	for i := range olderManifest.Layers {
		if olderManifest.Layers[i].MediaType == TarIndexArtifactMediaType {
			olderManifest.Layers[i].Size++
		}
	}
	olderManifestBytes, err := json.Marshal(olderManifest)
	require.NoError(t, err)
	older.descriptor = descriptorFor(olderManifestBytes, ocispec.MediaTypeImageManifest)
	older.descriptor.ArtifactType = SignatureArtifactType
	older.blobs[older.descriptor.Digest] = olderManifestBytes

	fetcher := &artifactFetcher{
		blobs: mergeBlobMaps(older.blobs, newer.blobs),
		refs: map[digest.Digest][]ocispec.Descriptor{
			sourceManifest.Digest: {older.descriptor, newer.descriptor},
		},
	}

	_, _, _, err = fetchSignatures(
		context.Background(),
		fetcher,
		sourceManifest.Digest,
		layerDigestSet(sourceLayer),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), older.descriptor.Digest.String())
	assert.Contains(t, err.Error(), "unaligned size")
}

func TestFetchSignaturesRejectsInvalidRootHashInOlderBundle(t *testing.T) {
	sourceManifest := descriptorFor([]byte("source manifest"), ocispec.MediaTypeImageManifest)
	sourceLayer := descriptorFor([]byte("source layer"), ocispec.MediaTypeImageLayerGzip)
	older := newPrecomputedBundle(t, sourceManifest, sourceLayer, "older", "abcd", time.Date(2026, 7, 20, 1, 0, 0, 0, time.UTC))
	newer := newPrecomputedBundle(t, sourceManifest, sourceLayer, "newer", testRootHashB, time.Date(2026, 7, 20, 2, 0, 0, 0, time.UTC))

	fetcher := &artifactFetcher{
		blobs: mergeBlobMaps(older.blobs, newer.blobs),
		refs: map[digest.Digest][]ocispec.Descriptor{
			sourceManifest.Digest: {older.descriptor, newer.descriptor},
		},
	}

	_, _, _, err := fetchSignatures(
		context.Background(),
		fetcher,
		sourceManifest.Digest,
		layerDigestSet(sourceLayer),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), older.descriptor.Digest.String())
	assert.Contains(t, err.Error(), "invalid SHA-256 root hash size")
}

func TestFetchSignaturesAcceptsEmbeddedSignatureData(t *testing.T) {
	sourceManifest := descriptorFor([]byte("source manifest"), ocispec.MediaTypeImageManifest)
	sourceLayer := descriptorFor([]byte("source layer"), ocispec.MediaTypeImageLayerGzip)
	bundle := newPrecomputedBundle(t, sourceManifest, sourceLayer, "embedded", testRootHashA, time.Now().UTC())

	var manifest ocispec.Manifest
	require.NoError(t, json.Unmarshal(bundle.blobs[bundle.descriptor.Digest], &manifest))
	for i := range manifest.Layers {
		if manifest.Layers[i].MediaType == LayerSignatureMediaType {
			manifest.Layers[i].Data = append([]byte(nil), bundle.blobs[manifest.Layers[i].Digest]...)
		}
	}
	manifestBytes, err := json.Marshal(manifest)
	require.NoError(t, err)
	manifestDesc := descriptorFor(manifestBytes, ocispec.MediaTypeImageManifest)
	manifestDesc.ArtifactType = SignatureArtifactType
	fetcher := &artifactFetcher{
		blobs: map[digest.Digest][]byte{
			manifestDesc.Digest: manifestBytes,
		},
		refs: map[digest.Digest][]ocispec.Descriptor{
			sourceManifest.Digest: {manifestDesc},
		},
	}

	signatures, artifacts, _, err := fetchSignatures(
		context.Background(),
		fetcher,
		sourceManifest.Digest,
		layerDigestSet(sourceLayer),
	)
	require.NoError(t, err)
	require.Contains(t, signatures, sourceLayer.Digest.String())
	require.Len(t, artifacts, 3)
	assert.Equal(t, bundle.blobs[bundle.signature.Digest], artifacts[0].Data)
}

func TestFetchSignaturesRejectsConflictingEmbeddedSignature(t *testing.T) {
	sourceManifest := descriptorFor([]byte("source manifest"), ocispec.MediaTypeImageManifest)
	sourceLayer := descriptorFor([]byte("source layer"), ocispec.MediaTypeImageLayerGzip)
	bundle := newPrecomputedBundle(t, sourceManifest, sourceLayer, "conflict", testRootHashA, time.Now().UTC())

	var manifest ocispec.Manifest
	require.NoError(t, json.Unmarshal(bundle.blobs[bundle.descriptor.Digest], &manifest))
	for i := range manifest.Layers {
		if manifest.Layers[i].MediaType == LayerSignatureMediaType {
			manifest.Layers[i].Data = append([]byte(nil), bundle.blobs[manifest.Layers[i].Digest]...)
			manifest.Layers[i].Annotations[sigLayerSignatureAnnotation] =
				base64.StdEncoding.EncodeToString([]byte("conflicting annotation"))
		}
	}
	manifestBytes, err := json.Marshal(manifest)
	require.NoError(t, err)
	manifestDesc := descriptorFor(manifestBytes, ocispec.MediaTypeImageManifest)
	manifestDesc.ArtifactType = SignatureArtifactType
	fetcher := &artifactFetcher{
		blobs: map[digest.Digest][]byte{
			manifestDesc.Digest: manifestBytes,
		},
		refs: map[digest.Digest][]ocispec.Descriptor{
			sourceManifest.Digest: {manifestDesc},
		},
	}

	_, _, _, err = fetchSignatures(
		context.Background(),
		fetcher,
		sourceManifest.Digest,
		layerDigestSet(sourceLayer),
	)
	require.ErrorContains(t, err, "embedded signature data does not match signed annotation")
}

func TestFetchSignaturesRejectsInvalidInlineSignatureDescriptor(t *testing.T) {
	sourceManifest := descriptorFor([]byte("source manifest"), ocispec.MediaTypeImageManifest)
	sourceLayer := descriptorFor([]byte("source layer"), ocispec.MediaTypeImageLayerGzip)

	tests := []struct {
		name    string
		mutate  func(*ocispec.Descriptor)
		wantErr string
	}{
		{
			name: "invalid digest",
			mutate: func(desc *ocispec.Descriptor) {
				desc.Digest = digest.Digest("invalid")
			},
			wantErr: "invalid descriptor digest",
		},
		{
			name: "size mismatch",
			mutate: func(desc *ocispec.Descriptor) {
				desc.Size++
			},
			wantErr: "size mismatch",
		},
		{
			name: "digest mismatch",
			mutate: func(desc *ocispec.Descriptor) {
				desc.Digest = digest.FromString("different signature")
			},
			wantErr: "digest verification failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bundle := newPrecomputedBundle(t, sourceManifest, sourceLayer, tt.name, testRootHashA, time.Now().UTC())
			var manifest ocispec.Manifest
			require.NoError(t, json.Unmarshal(bundle.blobs[bundle.descriptor.Digest], &manifest))
			for i := range manifest.Layers {
				if manifest.Layers[i].MediaType == LayerSignatureMediaType {
					tt.mutate(&manifest.Layers[i])
				}
			}
			manifestBytes, err := json.Marshal(manifest)
			require.NoError(t, err)
			manifestDesc := descriptorFor(manifestBytes, ocispec.MediaTypeImageManifest)
			manifestDesc.ArtifactType = SignatureArtifactType
			fetcher := &artifactFetcher{
				blobs: map[digest.Digest][]byte{
					manifestDesc.Digest: manifestBytes,
				},
				refs: map[digest.Digest][]ocispec.Descriptor{
					sourceManifest.Digest: {manifestDesc},
				},
			}

			_, _, _, err = fetchSignatures(
				context.Background(),
				fetcher,
				sourceManifest.Digest,
				layerDigestSet(sourceLayer),
			)
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestValidatePrecomputedDescriptorRejectsOversizedArtifact(t *testing.T) {
	desc := ocispec.Descriptor{
		MediaType: MerkleTreeArtifactMediaType,
		Digest:    digest.FromString("oversized artifact"),
		Size:      maxPrecomputedArtifactSize + 1,
	}
	require.ErrorContains(t, validatePrecomputedDescriptor(desc), "exceeds maximum")
}

func TestFetchSignaturesRejectsOversizedArtifactConfig(t *testing.T) {
	sourceManifest := descriptorFor([]byte("source manifest"), ocispec.MediaTypeImageManifest)
	sourceLayer := descriptorFor([]byte("source layer"), ocispec.MediaTypeImageLayerGzip)
	bundle := newPrecomputedBundle(t, sourceManifest, sourceLayer, "oversized-config", testRootHashA, time.Now().UTC())

	var manifest ocispec.Manifest
	require.NoError(t, json.Unmarshal(bundle.blobs[bundle.descriptor.Digest], &manifest))
	manifest.Config.Size = maxManifestSize + 1
	manifestBytes, err := json.Marshal(manifest)
	require.NoError(t, err)
	manifestDesc := descriptorFor(manifestBytes, ocispec.MediaTypeImageManifest)
	manifestDesc.ArtifactType = SignatureArtifactType

	blobs := mergeBlobMaps(bundle.blobs)
	blobs[manifestDesc.Digest] = manifestBytes
	fetcher := &artifactFetcher{
		blobs: blobs,
		refs: map[digest.Digest][]ocispec.Descriptor{
			sourceManifest.Digest: {manifestDesc},
		},
	}

	_, _, _, err = fetchSignatures(
		context.Background(),
		fetcher,
		sourceManifest.Digest,
		layerDigestSet(sourceLayer),
	)
	require.ErrorContains(t, err, "artifact config descriptor")
	require.ErrorContains(t, err, "exceeds maximum")
}

type precomputedBundleFixture struct {
	descriptor ocispec.Descriptor
	signature  ocispec.Descriptor
	tarIndex   ocispec.Descriptor
	tree       ocispec.Descriptor
	blobs      map[digest.Digest][]byte
}

func newPrecomputedBundle(
	t *testing.T,
	subject ocispec.Descriptor,
	sourceLayer ocispec.Descriptor,
	name string,
	rootHash string,
	createdAt time.Time,
) precomputedBundleFixture {
	t.Helper()

	signatureBytes := []byte("signature-" + name)
	signatureDesc := descriptorFor(signatureBytes, LayerSignatureMediaType)
	signatureDesc.Annotations = map[string]string{
		sigLayerDigestAnnotation:    sourceLayer.Digest.String(),
		sigLayerRootHashAnnotation:  rootHash,
		sigLayerSignatureAnnotation: base64.StdEncoding.EncodeToString(signatureBytes),
	}
	indexBytes := make([]byte, tarIndexAlignment)
	copy(indexBytes, "tar-index-"+name)
	indexDesc := descriptorFor(indexBytes, TarIndexArtifactMediaType)
	indexDesc.Annotations = precomputedAnnotations(sourceLayer.Digest.String())
	treeBytes := []byte("tree-" + name)
	treeDesc := descriptorFor(treeBytes, MerkleTreeArtifactMediaType)
	treeDesc.Annotations = precomputedAnnotations(sourceLayer.Digest.String())
	configBytes := []byte("{}")
	configDesc := descriptorFor(configBytes, ocispec.MediaTypeImageConfig)

	manifest := ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: SignatureArtifactType,
		Subject:      &subject,
		Config:       configDesc,
		Layers:       []ocispec.Descriptor{signatureDesc, indexDesc, treeDesc},
		Annotations: map[string]string{
			ociAnnotationCreated: createdAt.Format(time.RFC3339),
		},
	}
	manifestBytes, err := json.Marshal(manifest)
	require.NoError(t, err)
	manifestDesc := descriptorFor(manifestBytes, ocispec.MediaTypeImageManifest)
	manifestDesc.ArtifactType = SignatureArtifactType

	return precomputedBundleFixture{
		descriptor: manifestDesc,
		signature:  signatureDesc,
		tarIndex:   indexDesc,
		tree:       treeDesc,
		blobs: map[digest.Digest][]byte{
			manifestDesc.Digest:  manifestBytes,
			configDesc.Digest:    configBytes,
			signatureDesc.Digest: signatureBytes,
			indexDesc.Digest:     indexBytes,
			treeDesc.Digest:      treeBytes,
		},
	}
}

func mergeBlobMaps(maps ...map[digest.Digest][]byte) map[digest.Digest][]byte {
	merged := make(map[digest.Digest][]byte)
	for _, blobs := range maps {
		for dgst, data := range blobs {
			merged[dgst] = data
		}
	}
	return merged
}

func descriptorFor(data []byte, mediaType string) ocispec.Descriptor {
	return ocispec.Descriptor{
		MediaType: mediaType,
		Digest:    digest.FromBytes(data),
		Size:      int64(len(data)),
	}
}

func precomputedAnnotations(sourceDigest string) map[string]string {
	return map[string]string{
		precomputedSourceLayerAnnotation: sourceDigest,
	}
}

func layerDigestSet(layers ...ocispec.Descriptor) map[string]struct{} {
	result := make(map[string]struct{}, len(layers))
	for _, layer := range layers {
		result[layer.Digest.String()] = struct{}{}
	}
	return result
}
