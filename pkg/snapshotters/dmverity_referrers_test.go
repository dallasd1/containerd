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
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/images/imagetest"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/errdefs"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

func TestFetchSignaturesDiscovery(t *testing.T) {
	subject := ocispec.Descriptor{Digest: digest.FromString("subject")}
	for _, tc := range []struct {
		name       string
		fetcher    remotes.Fetcher
		discovered bool
		wantErr    error
	}{
		{"unsupported", plainTestFetcher{}, false, nil},
		{"empty result", signatureTestFetcher{}, true, nil},
		{"oversized index", signatureTestFetcher{err: fmt.Errorf("referrers index exceeds maximum allowed: %w", errdefs.ErrNotFound)}, false, errdefs.ErrNotFound},
		{"unavailable", signatureTestFetcher{err: errdefs.ErrUnavailable}, false, errdefs.ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bundle, discovered, err := fetchSignatures(t.Context(), tc.fetcher, nil, subject, nil)
			require.ErrorIs(t, err, tc.wantErr)
			require.Nil(t, bundle)
			require.Equal(t, tc.discovered, discovered)
		})
	}
}

func TestSignatureDiscoveryErrorPreservesSelection(t *testing.T) {
	subject := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageManifest,
		Digest:    digest.FromString("subject"),
	}
	handler := AppendSignatureHandlerWrapper(
		signatureTestFetcher{err: fmt.Errorf("referrers index exceeds maximum allowed: %w", errdefs.ErrNotFound)},
		nil,
	)(images.HandlerFunc(func(context.Context, ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		return nil, nil
	}))

	_, err := handler.Handle(t.Context(), subject)
	require.ErrorIs(t, err, errdefs.ErrNotFound)
}

type signatureTestFetcher struct {
	remotes.Fetcher
	err error
}

func (f signatureTestFetcher) FetchReferrers(context.Context, digest.Digest, ...remotes.FetchReferrersOpt) ([]ocispec.Descriptor, error) {
	return nil, f.err
}

type plainTestFetcher struct{ remotes.Fetcher }

type referrerTestFetcher struct {
	signatureTestFetcher
	referrers []ocispec.Descriptor
}

func (f referrerTestFetcher) FetchReferrers(context.Context, digest.Digest, ...remotes.FetchReferrersOpt) ([]ocispec.Descriptor, error) {
	return f.referrers, nil
}

func TestFetchSignaturesAcceptsOneBundleAndRejectsMultiple(t *testing.T) {
	ctx := t.Context()
	store := imagetest.NewContentStore(ctx, t)
	subject := ocispec.Descriptor{Digest: digest.FromString("subject")}
	layerDigest := digest.FromString("image layer")
	referrer := addTestDmverityReferrer(t, store, subject, layerDigest, "single")
	bundle, discovered, err := fetchSignatures(ctx, referrerTestFetcher{referrers: []ocispec.Descriptor{referrer}},
		store.Store, subject, map[string]struct{}{layerDigest.String(): {}})
	require.NoError(t, err)
	require.True(t, discovered)
	require.Equal(t, digest.FromString("root-single").Encoded(), bundle.layers[layerDigest.String()].RootHash)
	require.Equal(t, referrer.Digest, bundle.desc.Digest)

	other := addTestDmverityReferrer(t, store, subject, layerDigest, "other")
	_, _, err = fetchSignatures(ctx, referrerTestFetcher{
		referrers: []ocispec.Descriptor{referrer, other},
	}, store.Store, subject, map[string]struct{}{layerDigest.String(): {}})
	require.ErrorContains(t, err, "multiple dm-verity referrers")
}

func TestUnsignedManifestUsesOrdinaryLayerFallback(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fetcher remotes.Fetcher
	}{
		{name: "no matching referrer", fetcher: referrerTestFetcher{}},
		{name: "unsupported discovery", fetcher: plainTestFetcher{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			store := imagetest.NewContentStore(ctx, t)
			layer := ocispec.Descriptor{
				MediaType:   ocispec.MediaTypeImageLayer,
				Digest:      digest.FromString("ordinary layer"),
				Size:        1,
				Annotations: map[string]string{TargetLayerDmverityLabel: "untrusted"},
			}
			subject := store.Blob(ocispec.MediaTypeImageManifest, []byte("ordinary manifest")).Descriptor
			base := images.HandlerFunc(func(context.Context, ocispec.Descriptor) ([]ocispec.Descriptor, error) {
				return []ocispec.Descriptor{layer}, nil
			})

			children, err := AppendSignatureHandlerWrapper(tc.fetcher, store.Store)(base).Handle(ctx, subject)
			require.NoError(t, err)
			require.Len(t, children, 1)
			require.NotContains(t, children[0].Annotations, TargetLayerDmverityLabel)
		})
	}
}

func TestFetchSignaturesDeduplicatesSameReferrerDigest(t *testing.T) {
	ctx := t.Context()
	store := imagetest.NewContentStore(ctx, t)
	subject := ocispec.Descriptor{Digest: digest.FromString("subject")}
	layerDigest := digest.FromString("image layer")
	referrer := addTestDmverityReferrer(t, store, subject, layerDigest, "deduplicated")
	bundle, discovered, err := fetchSignatures(ctx, referrerTestFetcher{
		referrers: []ocispec.Descriptor{referrer, referrer},
	}, store.Store, subject, map[string]struct{}{layerDigest.String(): {}})
	require.NoError(t, err)
	require.True(t, discovered)
	require.Equal(t, referrer.Digest, bundle.desc.Digest)

	conflict := referrer
	conflict.Annotations = map[string]string{"description": "same immutable bundle"}
	_, _, err = fetchSignatures(ctx, referrerTestFetcher{
		referrers: []ocispec.Descriptor{referrer, conflict},
	}, store.Store, subject, map[string]struct{}{layerDigest.String(): {}})
	require.NoError(t, err)
}

func addTestDmverityReferrer(
	t *testing.T,
	store imagetest.ContentStore,
	subject ocispec.Descriptor,
	layerDigest digest.Digest,
	name string,
) ocispec.Descriptor {
	t.Helper()
	layerDesc := func(mediaType, suffix string, extra map[string]string) ocispec.Descriptor {
		labels := map[string]string{sourceLayerDigestAnnotation: layerDigest.String()}
		for key, value := range extra {
			labels[key] = value
		}
		descriptor := store.Blob(mediaType, []byte(name+suffix)).Descriptor
		descriptor.Annotations = labels
		return descriptor
	}
	manifest := ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: signatureArtifactType,
		Config:       ocispec.DescriptorEmptyJSON,
		Subject:      &subject,
		Layers: []ocispec.Descriptor{
			layerDesc(erofsMetadataArtifactMediaType, "-meta", nil),
			layerDesc(merkleTreeArtifactMediaType, "-tree", nil),
			layerDesc(layerSignatureMediaType, "-sig", map[string]string{
				layerRootHashAnnotation: digest.FromString("root-" + name).Encoded(),
			}),
		},
	}
	descriptor := store.JSONObject(ocispec.MediaTypeImageManifest, manifest).Descriptor
	descriptor.ArtifactType = signatureArtifactType
	return descriptor
}

func TestSignedBundleIsRetainedOnSubjectManifest(t *testing.T) {
	ctx := t.Context()
	store := imagetest.NewContentStore(ctx, t)
	layer := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageLayer,
		Digest:    digest.FromString("image layer"),
		Size:      1,
	}
	subjectContent := store.JSONObject(ocispec.MediaTypeImageManifest, ocispec.Manifest{
		MediaType: ocispec.MediaTypeImageManifest,
		Layers:    []ocispec.Descriptor{layer},
	})
	subject := subjectContent.Descriptor
	referrer := addTestDmverityReferrer(t, store, subject, layer.Digest, "retained")
	fetcher := referrerTestFetcher{referrers: []ocispec.Descriptor{referrer}}
	base := images.HandlerFunc(func(_ context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		if desc.Digest == subject.Digest {
			return []ocispec.Descriptor{layer}, nil
		}
		return nil, nil
	})

	children, err := AppendSignatureHandlerWrapper(fetcher, store.Store)(base).Handle(ctx, subject)
	require.NoError(t, err)
	target, err := ParseDmverityTarget(children[0].Annotations[TargetLayerDmverityLabel])
	require.NoError(t, err)
	require.Equal(t, digest.FromString("root-retained").Encoded(), target.RootHash)

	info, err := store.Store.Info(ctx, subject.Digest)
	require.NoError(t, err)
	require.Equal(t, referrer.Digest.String(), info.Labels[dmverityBundleContentLabel])
	require.Empty(t, info.Labels[dmverityNoReferrerLabel])
	var retainedChildren int
	refInfo, err := store.Store.Info(ctx, referrer.Digest)
	require.NoError(t, err)
	for key := range refInfo.Labels {
		if strings.HasPrefix(key, "containerd.io/gc.ref.content.") {
			retainedChildren++
		}
	}
	require.Equal(t, 3, retainedChildren)

	cached, err := AppendCachedSignatureHandlerWrapper(store.Store)(base).Handle(ctx, subject)
	require.NoError(t, err)
	require.Equal(t, children[0].Annotations[TargetLayerDmverityLabel], cached[0].Annotations[TargetLayerDmverityLabel])

	require.NoError(t, store.Store.Delete(ctx, target.Tree.Digest))
	_, err = AppendCachedSignatureHandlerWrapper(store.Store)(base).Handle(ctx, subject)
	require.ErrorContains(t, err, "read retained dm-verity payload")
}

func TestKnownSignedManifestWithMissingBundleFailsClosed(t *testing.T) {
	ctx := t.Context()
	store := imagetest.NewContentStore(ctx, t)
	subject := store.Blob(ocispec.MediaTypeImageManifest, []byte("{}")).Descriptor
	missingReferrer := digest.FromString("missing referrer")
	_, err := store.Store.Update(ctx, content.Info{
		Digest: subject.Digest,
		Labels: map[string]string{
			dmverityBundleContentLabel: missingReferrer.String(),
			dmverityNoReferrerLabel:    "",
		},
	}, "labels."+dmverityBundleContentLabel, "labels."+dmverityNoReferrerLabel)
	require.NoError(t, err)

	handler := AppendCachedSignatureHandlerWrapper(store.Store)(images.HandlerFunc(func(context.Context, ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		return nil, nil
	}))
	_, err = handler.Handle(ctx, subject)
	require.ErrorContains(t, err, "read retained signed dm-verity bundle")
}

func TestDmverityObservationReplacesSignedBundleButKeepsAbsenceSticky(t *testing.T) {
	ctx := t.Context()
	store := imagetest.NewContentStore(ctx, t)
	subject := store.Blob(ocispec.MediaTypeImageManifest, []byte("{}")).Descriptor.Digest
	first := digest.FromString("first referrer")
	second := digest.FromString("replacement referrer")

	for _, transition := range []struct {
		referrer digest.Digest
		expected digest.Digest
	}{
		{first, first},
		{"", first},
		{second, second},
		{"", second},
	} {
		signed, err := recordDmverityObservation(ctx, store.Store, subject, transition.referrer)
		require.NoError(t, err)
		require.True(t, signed)

		info, err := store.Store.Info(ctx, subject)
		require.NoError(t, err)
		require.Equal(t, transition.expected.String(), info.Labels[dmverityBundleContentLabel])
		require.Empty(t, info.Labels[dmverityNoReferrerLabel])
	}
}

func TestDmverityObservationRecordsNoReferrerWithoutDemotingKnownSigned(t *testing.T) {
	ctx := t.Context()
	store := imagetest.NewContentStore(ctx, t)
	subject := store.Blob(ocispec.MediaTypeImageManifest, []byte("{}")).Descriptor.Digest

	signed, err := recordDmverityObservation(ctx, store.Store, subject, "")
	require.NoError(t, err)
	require.False(t, signed)

	info, err := store.Store.Info(ctx, subject)
	require.NoError(t, err)
	require.Empty(t, info.Labels[dmverityBundleContentLabel])
	require.Equal(t, "true", info.Labels[dmverityNoReferrerLabel])

	_, observed, err := loadRetainedDmverityBundle(ctx, store.Store,
		ocispec.Descriptor{Digest: subject}, nil)
	require.NoError(t, err)
	require.True(t, observed)
}

func TestDmverityObservationConcurrentSameBundleIsIdempotent(t *testing.T) {
	ctx := t.Context()
	store := imagetest.NewContentStore(ctx, t)
	subject := store.Blob(ocispec.MediaTypeImageManifest, []byte("{}")).Descriptor.Digest
	referrer := digest.FromString("same referrer")

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < cap(errs); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := recordDmverityObservation(ctx, store.Store, subject, referrer)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	info, err := store.Store.Info(ctx, subject)
	require.NoError(t, err)
	require.Equal(t, referrer.String(), info.Labels[dmverityBundleContentLabel])
}
