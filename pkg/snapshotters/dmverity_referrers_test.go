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
	"maps"
	"strings"
	"sync"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/images/imagetest"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/errdefs"
	"github.com/containerd/platforms"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

func TestSanitizeDmverityImageLayersReservedAnnotations(t *testing.T) {
	reserved := []string{TargetLayerDmverityLabel, dmverityReferrerRootHashLabel, dmverityReferrerSignatureDigestLabel}
	for _, mediaType := range []string{ocispec.MediaTypeImageLayer, ocispec.MediaTypeImageConfig} {
		for _, keys := range [][]string{nil, reserved[:1], reserved[1:2], reserved[2:], reserved} {
			t.Run(fmt.Sprintf("%s/%v", mediaType, keys), func(t *testing.T) {
				annotations := map[string]string{"example.org/keep": "value"}
				for _, key := range keys {
					annotations[key] = ""
				}
				original := maps.Clone(annotations)
				desc := ocispec.Descriptor{
					MediaType:   mediaType,
					Digest:      digest.FromString("layer"),
					Annotations: annotations,
				}
				children := []ocispec.Descriptor{desc}
				layers := sanitizeDmverityImageLayers(children)
				require.Equal(t, original, annotations)
				require.Equal(t, map[string]string{"example.org/keep": "value"}, children[0].Annotations)
				for _, key := range reserved {
					require.NotContains(t, snapshots.FilterInheritedLabels(children[0].Annotations), key)
				}
				_, included := layers[desc.Digest.String()]
				require.Equal(t, images.IsLayerType(mediaType), included)
				if len(keys) > 0 {
					children[0].Annotations["example.org/keep"] = "changed"
					require.Equal(t, "value", annotations["example.org/keep"])
				}
			})
		}
	}
}

func TestSanitizedDmverityLayerPreparation(t *testing.T) {
	ctx := t.Context()
	desc := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageLayer,
		Digest:    digest.FromString("layer"),
		Annotations: map[string]string{
			TargetLayerDmverityLabel:             "untrusted",
			dmverityReferrerRootHashLabel:        "untrusted",
			dmverityReferrerSignatureDigestLabel: "untrusted",
		},
	}
	children := []ocispec.Descriptor{desc}
	sanitizeDmverityImageLayers(children)
	chainID := digest.FromString("chain").String()
	unsigned, err := PrepareDmverityLayer(ctx, children[0], chainID)
	require.NoError(t, err)
	require.Empty(t, unsigned.Labels)
	require.NoError(t, unsigned.ValidateExisting(snapshots.Info{}))

	target := &DmverityTarget{
		RootHash:  digest.FromString("trusted-root").Encoded(),
		Metadata:  ocispec.Descriptor{Digest: digest.FromString("metadata")},
		Tree:      ocispec.Descriptor{Digest: digest.FromString("tree")},
		Signature: ocispec.Descriptor{Digest: digest.FromString("signature")},
	}
	children, err = annotateDmverityTargets(children, map[string]*DmverityTarget{desc.Digest.String(): target})
	require.NoError(t, err)
	signed, err := PrepareDmverityLayer(ctx, children[0], chainID)
	require.NoError(t, err)
	require.Equal(t, target.RootHash, signed.Labels[dmverityReferrerRootHashLabel])
	require.Equal(t, target.Signature.Digest.String(), signed.Labels[dmverityReferrerSignatureDigestLabel])
	require.NoError(t, signed.ValidateExisting(snapshots.Info{Labels: signed.Labels}))
	require.Error(t, signed.ValidateExisting(snapshots.Info{}))
	require.Equal(t, "untrusted", desc.Annotations[TargetLayerDmverityLabel])
}

func TestImageHasDmverityReferrerForSelectedPlatform(t *testing.T) {
	ctx := t.Context()
	store := imagetest.NewContentStore(ctx, t)
	config := store.JSONObject(ocispec.MediaTypeImageConfig, ocispec.Image{})
	manifest := store.Manifest(config, store.RandomBlob(ocispec.MediaTypeImageLayer, 16))
	index := store.Index(imagetest.AddPlatform(manifest, platforms.DefaultSpec()))

	for _, signed := range []bool{true, false} {
		labels := map[string]string{dmverityNoReferrerLabel: "true"}
		if signed {
			labels = map[string]string{dmverityBundleContentLabel: digest.FromString("bundle").String()}
		}
		_, err := store.Update(ctx, content.Info{
			Digest: manifest.Descriptor.Digest,
			Labels: labels,
		}, "labels")
		require.NoError(t, err)
		got, err := ImageHasDmverityReferrer(ctx, store.Store, index.Descriptor, platforms.Default())
		require.NoError(t, err)
		require.Equal(t, signed, got)
	}
}

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
	return addTestDmverityReferrerWithRoot(t, store, subject, layerDigest, name, digest.FromString("root-"+name).Encoded())
}

func addTestDmverityReferrerWithRoot(
	t *testing.T,
	store imagetest.ContentStore,
	subject ocispec.Descriptor,
	layerDigest digest.Digest,
	name, root string,
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
				layerRootHashAnnotation: root,
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
	layer := digest.FromString("layer")
	root := digest.FromString("root").Encoded()
	first := addTestDmverityReferrerWithRoot(t, store, ocispec.Descriptor{Digest: subject}, layer, "first", root).Digest
	second := addTestDmverityReferrerWithRoot(t, store, ocispec.Descriptor{Digest: subject}, layer, "replacement", root).Digest

	for _, transition := range []struct {
		referrer digest.Digest
		expected digest.Digest
	}{
		{first, first},
		{"", first},
		{second, second},
		{"", second},
	} {
		signed, err := recordDmverityObservation(ctx, store.Store, subject, transition.referrer, map[string]struct{}{layer.String(): {}})
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

	signed, err := recordDmverityObservation(ctx, store.Store, subject, "", nil)
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
			_, err := recordDmverityObservation(ctx, store.Store, subject, referrer, nil)
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

func TestConflictingReferrerPreservesCachedSignedIdentity(t *testing.T) {
	ctx := t.Context()
	store := imagetest.NewContentStore(ctx, t)
	layer := store.Blob(ocispec.MediaTypeImageLayer, []byte("layer")).Descriptor
	subject := store.JSONObject(ocispec.MediaTypeImageManifest, ocispec.Manifest{
		MediaType: ocispec.MediaTypeImageManifest,
		Layers:    []ocispec.Descriptor{layer},
	}).Descriptor
	first := addTestDmverityReferrer(t, store, subject, layer.Digest, "first")
	conflict := addTestDmverityReferrer(t, store, subject, layer.Digest, "conflict")
	base := images.HandlerFunc(func(context.Context, ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		return []ocispec.Descriptor{layer}, nil
	})
	pull := func(ref ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		return AppendSignatureHandlerWrapper(referrerTestFetcher{referrers: []ocispec.Descriptor{ref}}, store.Store)(base).Handle(ctx, subject)
	}
	children, err := pull(first)
	require.NoError(t, err)
	committed, err := DmveritySnapshotLabels(children[0])
	require.NoError(t, err)

	_, err = pull(conflict)
	require.ErrorContains(t, err, "changes root hash")
	info, err := store.Store.Info(ctx, subject.Digest)
	require.NoError(t, err)
	require.Equal(t, first.Digest.String(), info.Labels[dmverityBundleContentLabel])

	cached, err := AppendCachedSignatureHandlerWrapper(store.Store)(base).Handle(ctx, subject)
	require.NoError(t, err)
	preparation, err := PrepareDmverityLayer(ctx, cached[0], digest.FromString("chain").String())
	require.NoError(t, err)
	require.NoError(t, preparation.ValidateExisting(snapshots.Info{Labels: committed}))

	replacement := addTestDmverityReferrerWithRoot(t, store, subject, layer.Digest, "new-signature", digest.FromString("root-first").Encoded())
	_, err = pull(replacement)
	require.NoError(t, err)
	info, err = store.Store.Info(ctx, subject.Digest)
	require.NoError(t, err)
	require.Equal(t, replacement.Digest.String(), info.Labels[dmverityBundleContentLabel])
	cached, err = AppendCachedSignatureHandlerWrapper(store.Store)(base).Handle(ctx, subject)
	require.NoError(t, err)
	replacedLabels, err := DmveritySnapshotLabels(cached[0])
	require.NoError(t, err)
	require.NotEqual(t, committed[dmverityReferrerSignatureDigestLabel], replacedLabels[dmverityReferrerSignatureDigestLabel])
	preparation, err = PrepareDmverityLayer(ctx, cached[0], digest.FromString("chain").String())
	require.NoError(t, err)
	require.NoError(t, preparation.ValidateExisting(snapshots.Info{Labels: committed}))

	target, err := ParseDmverityTarget(cached[0].Annotations[TargetLayerDmverityLabel])
	require.NoError(t, err)
	require.NoError(t, store.Store.Delete(ctx, target.Tree.Digest))
	next := addTestDmverityReferrerWithRoot(t, store, subject, layer.Digest, "another-signature", target.RootHash)
	_, err = pull(next)
	require.ErrorContains(t, err, "read retained dm-verity payload")
	info, err = store.Store.Info(ctx, subject.Digest)
	require.NoError(t, err)
	require.Equal(t, replacement.Digest.String(), info.Labels[dmverityBundleContentLabel])
}

func TestConcurrentConflictingObservationsPreserveWinner(t *testing.T) {
	ctx := t.Context()
	store := imagetest.NewContentStore(ctx, t)
	subject := store.Blob(ocispec.MediaTypeImageManifest, []byte("{}")).Descriptor
	layer := digest.FromString("layer")
	layers := map[string]struct{}{layer.String(): {}}
	refs := []ocispec.Descriptor{
		addTestDmverityReferrer(t, store, subject, layer, "a"),
		addTestDmverityReferrer(t, store, subject, layer, "b"),
	}
	type result struct {
		index int
		err   error
	}
	results := make(chan result, 2)
	var wg sync.WaitGroup
	for i := range refs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := recordDmverityObservation(ctx, store.Store, subject.Digest, refs[i].Digest, layers)
			results <- result{index: i, err: err}
		}(i)
	}
	wg.Wait()
	close(results)
	winner, successes := -1, 0
	for r := range results {
		if r.err == nil {
			winner = r.index
			successes++
		} else {
			require.ErrorContains(t, r.err, "changes root hash")
		}
	}
	require.Equal(t, 1, successes)
	info, err := store.Store.Info(ctx, subject.Digest)
	require.NoError(t, err)
	require.Equal(t, refs[winner].Digest.String(), info.Labels[dmverityBundleContentLabel])
	_, err = recordDmverityObservation(ctx, store.Store, subject.Digest, "", layers)
	require.NoError(t, err)
	info, err = store.Store.Info(ctx, subject.Digest)
	require.NoError(t, err)
	require.Equal(t, refs[winner].Digest.String(), info.Labels[dmverityBundleContentLabel])
}
