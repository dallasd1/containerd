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
	"io"
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
	"github.com/containerd/go-dmverity/pkg/verity"
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
	unsigned, err := PrepareDmverityLayer(ctx, children[0], chainID, "")
	require.NoError(t, err)
	require.Empty(t, unsigned.Labels)
	require.NoError(t, unsigned.ValidateExisting(snapshots.Info{}))

	target := &DmverityTarget{
		Referrer:  digest.FromString("referrer"),
		RootHash:  digest.FromString("trusted-root").Encoded(),
		Metadata:  ocispec.Descriptor{Digest: digest.FromString("metadata")},
		Tree:      ocispec.Descriptor{Digest: digest.FromString("tree")},
		Signature: ocispec.Descriptor{Digest: digest.FromString("signature")},
	}
	children, err = annotateDmverityTargets(children, map[string]*DmverityTarget{desc.Digest.String(): target})
	require.NoError(t, err)
	signed, err := PrepareDmverityLayer(ctx, children[0], chainID, "")
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

func TestDmverityImageSnapshotKeyUsesRetainedSelection(t *testing.T) {
	for _, mode := range []string{"selected platform", "non-layer artifacts", "no signed observation", "explicitly unsigned", "missing bundle", "missing payload", "wrong subject", "wrong diffID count"} {
		t.Run(mode, func(t *testing.T) {
			ctx := t.Context()
			store := imagetest.NewContentStore(ctx, t)
			diffID := digest.FromString("diffID")
			diffIDs := []digest.Digest{diffID}
			if mode == "wrong diffID count" {
				diffIDs = nil
			}
			config := store.JSONObject(ocispec.MediaTypeImageConfig, ocispec.Image{
				Platform: platforms.DefaultSpec(),
				RootFS:   ocispec.RootFS{Type: "layers", DiffIDs: diffIDs},
			})
			layer := store.Blob(ocispec.MediaTypeImageLayer, []byte("layer"))
			manifest := store.Manifest(config, layer)
			if mode == "non-layer artifacts" {
				before := store.Blob("application/vnd.example.before", []byte("before"))
				after := store.Blob("application/vnd.example.after", []byte("after"))
				manifest = store.Manifest(config, before, layer, after)
			}
			subject := manifest.Descriptor
			if mode == "wrong subject" {
				subject.Digest = digest.FromString("different subject")
			}
			root := digest.FromString("root").Encoded()
			bundle := addTestDmverityReferrerWithRoot(t, store, subject, layer.Descriptor.Digest, "selected", root)
			_, err := store.Update(ctx, content.Info{
				Digest: manifest.Descriptor.Digest,
				Labels: map[string]string{dmverityBundleContentLabel: bundle.Digest.String()},
			}, "labels."+dmverityBundleContentLabel)
			require.NoError(t, err)
			if mode == "no signed observation" {
				_, err = store.Update(ctx, content.Info{Digest: manifest.Descriptor.Digest}, "labels."+dmverityBundleContentLabel)
				require.NoError(t, err)
			}
			if mode == "explicitly unsigned" {
				_, err = store.Update(ctx, content.Info{
					Digest: manifest.Descriptor.Digest,
					Labels: map[string]string{dmverityNoReferrerLabel: "true"},
				}, "labels")
				require.NoError(t, err)
			}
			if mode == "missing bundle" {
				require.NoError(t, store.Delete(ctx, bundle.Digest))
			}
			if mode == "missing payload" {
				require.NoError(t, store.Delete(ctx, digest.FromString("selected-tree")))
			}
			// Neither unrelated GC pointers nor an unselected platform determine
			// the signed parent. The other manifest deliberately has no bundle.
			_, err = store.Update(ctx, content.Info{
				Digest: config.Descriptor.Digest,
				Labels: map[string]string{"containerd.io/gc.ref.snapshot.erofs/dmverity": "wrong-key"},
			}, "labels.containerd.io/gc.ref.snapshot.erofs/dmverity")
			require.NoError(t, err)
			otherPlatform := platforms.DefaultSpec()
			otherPlatform.Architecture = "unsupported"
			otherConfig := store.JSONObject(ocispec.MediaTypeImageConfig, ocispec.Image{Platform: otherPlatform})
			otherManifest := store.Manifest(otherConfig, layer)
			index := store.Index(
				imagetest.AddPlatform(otherManifest, otherPlatform),
				imagetest.AddPlatform(manifest, platforms.DefaultSpec()),
			)
			key, err := LookupDmverityImageSnapshotKey(ctx, store.Store, index.Descriptor, platforms.Default())
			switch mode {
			case "selected platform", "non-layer artifacts":
				require.NoError(t, err)
				expected, err := DmveritySnapshotKey(diffID.String(), "", root, digest.FromString("selected-sig").String())
				require.NoError(t, err)
				require.Equal(t, expected, key)
			case "no signed observation", "explicitly unsigned":
				require.NoError(t, err)
				require.Empty(t, key)
				_, err := DmverityImageSnapshotKey(ctx, store.Store, index.Descriptor, platforms.Default())
				require.ErrorContains(t, err, "no selected signed snapshot chain")
			default:
				require.Error(t, err)
				require.Empty(t, key)
			}
		})
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
	for _, failure := range []error{
		fmt.Errorf("referrers index exceeds maximum allowed: %w", errdefs.ErrNotFound),
		errdefs.ErrUnavailable,
		context.Canceled,
		context.DeadlineExceeded,
	} {
		t.Run(failure.Error(), func(t *testing.T) {
			handler := AppendSignatureHandlerWrapper(
				signatureTestFetcher{err: failure}, nil,
			)(images.HandlerFunc(func(context.Context, ocispec.Descriptor) ([]ocispec.Descriptor, error) {
				return nil, nil
			}))

			_, err := handler.Handle(t.Context(), subject)
			require.ErrorIs(t, err, failure)
		})
	}
}

func TestReferrerManifestReadErrorDoesNotFallBack(t *testing.T) {
	ctx := t.Context()
	store := imagetest.NewContentStore(ctx, t)
	subject := store.Blob(ocispec.MediaTypeImageManifest, []byte("{}")).Descriptor
	fetcher := referrerTestFetcher{
		signatureTestFetcher: signatureTestFetcher{
			Fetcher: remotes.FetcherFunc(func(context.Context, ocispec.Descriptor) (io.ReadCloser, error) {
				return nil, io.ErrUnexpectedEOF
			}),
		},
		referrers: []ocispec.Descriptor{{
			MediaType:    ocispec.MediaTypeImageManifest,
			ArtifactType: signatureArtifactType,
			Digest:       digest.FromString("unavailable referrer"),
			Size:         1,
		}},
	}
	handler := AppendSignatureHandlerWrapper(fetcher, store.Store)(
		images.HandlerFunc(func(context.Context, ocispec.Descriptor) ([]ocispec.Descriptor, error) {
			return nil, nil
		}),
	)
	_, err := handler.Handle(ctx, subject)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
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

func TestFetchSignaturesAcceptsOneBundle(t *testing.T) {
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
}

func TestFetchSignaturesSelectsLatestBundle(t *testing.T) {
	for _, tc := range []struct {
		name     string
		aCreated string
		bCreated string
		newest   string
	}{
		{"newer timestamp", "2026-11-12T22:00:00Z", "2026-11-13T12:00:00Z", "b"},
		{"timezone comparison", "2026-11-13T10:00:00-03:00", "2026-11-13T12:00:00Z", "a"},
		{"nanosecond comparison", "2026-11-13T12:00:00.1Z", "2026-11-13T12:00:00.2Z", "b"},
		{"missing timestamp", "", "2026-11-13T12:00:00Z", "b"},
		{"invalid timestamp", "not-a-timestamp", "2026-11-13T12:00:00Z", "b"},
		{"equal timestamps", "2026-11-13T12:00:00Z", "2026-11-13T13:00:00+01:00", ""},
		{"both timestamps missing", "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			store := imagetest.NewContentStore(ctx, t)
			subject := ocispec.Descriptor{Digest: digest.FromString("subject")}
			layerDigest := digest.FromString("image layer")
			a := addTestDmverityReferrer(t, store, subject, layerDigest, "a")
			b := addTestDmverityReferrer(t, store, subject, layerDigest, "b")
			a.Annotations = map[string]string{ocispec.AnnotationCreated: tc.aCreated}
			b.Annotations = map[string]string{ocispec.AnnotationCreated: tc.bCreated}
			want := a.Digest
			if tc.newest == "b" || tc.newest == "" && b.Digest < a.Digest {
				want = b.Digest
			}
			unrelated := ocispec.Descriptor{
				ArtifactType: "application/vnd.cncf.notary.signature",
				Digest:       digest.FromString("ordinary signature"),
				Annotations:  map[string]string{ocispec.AnnotationCreated: "2099-01-01T00:00:00Z"},
			}
			for _, refs := range [][]ocispec.Descriptor{{a, unrelated, b}, {b, unrelated, a}} {
				bundle, discovered, err := fetchSignatures(ctx, referrerTestFetcher{referrers: refs},
					store.Store, subject, map[string]struct{}{layerDigest.String(): {}})
				require.NoError(t, err)
				require.True(t, discovered)
				require.Equal(t, want, bundle.desc.Digest)
			}
		})
	}
}

func TestFetchSignaturesRejectsInvalidDescriptors(t *testing.T) {
	for _, tc := range []struct {
		name      string
		digest    digest.Digest
		mediaType string
		size      int64
		want      string
	}{
		{"empty digest", "", ocispec.MediaTypeImageManifest, 1, "invalid dm-verity referrer digest"},
		{"invalid digest", "not-a-digest", ocispec.MediaTypeImageManifest, 1, "invalid dm-verity referrer digest"},
		{"wrong media type", digest.FromString("bundle"), ocispec.MediaTypeImageIndex, 1, "unexpected media type"},
		{"zero manifest size", digest.FromString("bundle"), ocispec.MediaTypeImageManifest, 0, "invalid dm-verity referrer size"},
		{"negative manifest size", digest.FromString("bundle"), ocispec.MediaTypeImageManifest, -1, "invalid dm-verity referrer size"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			store := imagetest.NewContentStore(ctx, t)
			subject := store.Blob(ocispec.MediaTypeImageManifest, []byte("{}")).Descriptor
			source := digest.FromString("image layer")
			fetchCalls := 0
			fetcher := referrerTestFetcher{
				signatureTestFetcher: signatureTestFetcher{
					Fetcher: remotes.FetcherFunc(func(context.Context, ocispec.Descriptor) (io.ReadCloser, error) {
						fetchCalls++
						return nil, io.ErrUnexpectedEOF
					}),
				},
				referrers: []ocispec.Descriptor{{
					Digest:       tc.digest,
					MediaType:    tc.mediaType,
					ArtifactType: signatureArtifactType,
					Size:         tc.size,
				}},
			}
			bundle, discovered, err := fetchSignatures(ctx, fetcher, store.Store, subject, nil)
			require.ErrorContains(t, err, tc.want)
			var malformed malformedDmverityReferrerError
			require.ErrorAs(t, err, &malformed)
			require.True(t, discovered)
			require.Nil(t, bundle)
			assertUnsignedReferrerFallback(t, store, subject, source, fetcher)
			require.Zero(t, fetchCalls)
		})
	}
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
	for _, tc := range []struct {
		name      string
		mutate    func(*ocispec.Descriptor)
		malformed bool
	}{
		{"identical", func(*ocispec.Descriptor) {}, false},
		{"different annotation", func(d *ocispec.Descriptor) {
			d.Annotations = map[string]string{"description": "same immutable bundle"}
		}, false},
		{"conflicting media type", func(d *ocispec.Descriptor) { d.MediaType = ocispec.MediaTypeImageIndex }, true},
		{"conflicting size", func(d *ocispec.Descriptor) { d.Size++ }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			store := imagetest.NewContentStore(ctx, t)
			subject := store.Blob(ocispec.MediaTypeImageManifest, []byte("{}")).Descriptor
			layerDigest := digest.FromString("image layer")
			referrer := addTestDmverityReferrer(t, store, subject, layerDigest, "deduplicated")
			duplicate := referrer
			tc.mutate(&duplicate)
			for _, refs := range [][]ocispec.Descriptor{{referrer, duplicate}, {duplicate, referrer}} {
				fetcher := referrerTestFetcher{referrers: refs}
				bundle, discovered, err := fetchSignatures(ctx, fetcher,
					store.Store, subject, map[string]struct{}{layerDigest.String(): {}})
				require.True(t, discovered)
				if tc.malformed {
					require.ErrorContains(t, err, "conflicting dm-verity referrer descriptors")
					var malformed malformedDmverityReferrerError
					require.ErrorAs(t, err, &malformed)
					require.Nil(t, bundle)
					assertUnsignedReferrerFallback(t, store, subject, layerDigest, fetcher)
				} else {
					require.NoError(t, err)
					require.Equal(t, referrer.Digest, bundle.desc.Digest)
				}
			}
		})
	}
}

func TestFetchSignaturesRejectsSelectedDigestConflictsAcrossTimestamps(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*ocispec.Descriptor)
	}{
		{"media type", func(d *ocispec.Descriptor) { d.MediaType = ocispec.MediaTypeImageIndex }},
		{"size", func(d *ocispec.Descriptor) { d.Size++ }},
	} {
		for _, order := range []string{"older first", "newer first"} {
			t.Run(tc.name+"/"+order, func(t *testing.T) {
				ctx := t.Context()
				store := imagetest.NewContentStore(ctx, t)
				subject := store.Blob(ocispec.MediaTypeImageManifest, []byte("{}")).Descriptor
				layerDigest := digest.FromString("image layer")
				newer := addTestDmverityReferrer(t, store, subject, layerDigest, "selected")
				newer.Annotations = map[string]string{ocispec.AnnotationCreated: "2026-11-13T12:00:00Z"}
				older := newer
				older.Annotations = map[string]string{ocispec.AnnotationCreated: "2026-11-12T12:00:00Z"}
				tc.mutate(&older)
				refs := []ocispec.Descriptor{older, newer}
				if order == "newer first" {
					refs = []ocispec.Descriptor{newer, older}
				}
				fetcher := referrerTestFetcher{referrers: refs}
				bundle, discovered, err := fetchSignatures(ctx, fetcher,
					store.Store, subject, map[string]struct{}{layerDigest.String(): {}})
				require.ErrorContains(t, err, "conflicting dm-verity referrer descriptors")
				var malformed malformedDmverityReferrerError
				require.ErrorAs(t, err, &malformed)
				require.True(t, discovered)
				require.Nil(t, bundle)
				assertUnsignedReferrerFallback(t, store, subject, layerDigest, fetcher)
			})
		}
	}
}

func TestFetchSignaturesIgnoresConflictingOlderDescriptors(t *testing.T) {
	ctx := t.Context()
	store := imagetest.NewContentStore(ctx, t)
	subject := ocispec.Descriptor{Digest: digest.FromString("subject")}
	layerDigest := digest.FromString("image layer")
	older := addTestDmverityReferrer(t, store, subject, layerDigest, "older")
	older.Annotations = map[string]string{ocispec.AnnotationCreated: "2026-11-12T12:00:00Z"}
	conflict := older
	conflict.MediaType = ocispec.MediaTypeImageIndex
	newer := addTestDmverityReferrer(t, store, subject, layerDigest, "newer")
	newer.Annotations = map[string]string{ocispec.AnnotationCreated: "2026-11-13T12:00:00Z"}
	for _, refs := range [][]ocispec.Descriptor{
		{older, conflict, newer},
		{newer, older, conflict},
		{older, newer, conflict},
	} {
		bundle, discovered, err := fetchSignatures(ctx, referrerTestFetcher{referrers: refs},
			store.Store, subject, map[string]struct{}{layerDigest.String(): {}})
		require.NoError(t, err)
		require.True(t, discovered)
		require.Equal(t, newer.Digest, bundle.desc.Digest)
	}
}

func TestFetchSignaturesRejectsMalformedBundles(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*ocispec.Manifest)
		want   string
	}{
		{"missing subject", func(m *ocispec.Manifest) { m.Subject = nil }, "subject does not match"},
		{"wrong subject", func(m *ocispec.Manifest) {
			m.Subject = &ocispec.Descriptor{Digest: digest.FromString("other subject")}
		}, "subject does not match"},
		{"wrong artifact type", func(m *ocispec.Manifest) {
			m.ArtifactType = "application/vnd.example.invalid"
		}, "unexpected artifact type"},
		{"missing metadata", func(m *ocispec.Manifest) { m.Layers = m.Layers[1:] }, "incomplete dm-verity artifacts"},
		{"missing tree", func(m *ocispec.Manifest) { m.Layers = append(m.Layers[:1], m.Layers[2:]...) }, "incomplete dm-verity artifacts"},
		{"missing signature", func(m *ocispec.Manifest) { m.Layers = m.Layers[:2] }, "incomplete dm-verity artifacts"},
		{"duplicate metadata", func(m *ocispec.Manifest) { m.Layers = append(m.Layers, m.Layers[0]) }, "duplicate EROFS metadata"},
		{"duplicate tree", func(m *ocispec.Manifest) { m.Layers = append(m.Layers, m.Layers[1]) }, "duplicate Merkle-tree"},
		{"duplicate signature", func(m *ocispec.Manifest) { m.Layers = append(m.Layers, m.Layers[2]) }, "duplicate signature"},
		{"invalid payload digest", func(m *ocispec.Manifest) { m.Layers[0].Digest = "not-a-digest" }, "invalid payload digest"},
		{"zero payload size", func(m *ocispec.Manifest) { m.Layers[0].Size = 0 }, "invalid payload size"},
		{"oversized signature", func(m *ocispec.Manifest) { m.Layers[2].Size = verity.MaxSignatureSize + 1 }, "maximum is"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			store := imagetest.NewContentStore(ctx, t)
			subject := store.Blob(ocispec.MediaTypeImageManifest, []byte("{}")).Descriptor
			source := digest.FromString("layer")
			valid := addTestDmverityReferrer(t, store, subject, source, "valid")
			data, err := content.ReadBlob(ctx, store.Store, valid)
			require.NoError(t, err)
			var manifest ocispec.Manifest
			require.NoError(t, json.Unmarshal(data, &manifest))
			valid.Annotations = map[string]string{ocispec.AnnotationCreated: "2026-11-12T12:00:00Z"}
			tc.mutate(&manifest)
			referrer := store.JSONObject(ocispec.MediaTypeImageManifest, manifest).Descriptor
			referrer.ArtifactType = signatureArtifactType
			referrer.Annotations = map[string]string{ocispec.AnnotationCreated: "2026-11-13T12:00:00Z"}
			fetcher := referrerTestFetcher{referrers: []ocispec.Descriptor{valid, referrer}}
			bundle, discovered, err := fetchSignatures(ctx, fetcher,
				store.Store, subject, map[string]struct{}{source.String(): {}})
			require.ErrorContains(t, err, tc.want)
			require.True(t, discovered, "malformed metadata is not an empty discovery result")
			require.Nil(t, bundle)
			assertUnsignedReferrerFallback(t, store, subject, source, fetcher)
		})
	}
}

func assertUnsignedReferrerFallback(
	t *testing.T,
	store imagetest.ContentStore,
	subject ocispec.Descriptor,
	source digest.Digest,
	fetcher remotes.Fetcher,
) {
	t.Helper()
	ctx := t.Context()
	layer := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageLayer,
		Digest:    source,
		Size:      1,
		Annotations: map[string]string{
			TargetLayerDmverityLabel:             "untrusted",
			dmverityReferrerRootHashLabel:        "untrusted",
			dmverityReferrerSignatureDigestLabel: "untrusted",
		},
	}
	base := images.HandlerFunc(func(context.Context, ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		return []ocispec.Descriptor{layer}, nil
	})
	children, err := AppendSignatureHandlerWrapper(fetcher, store.Store)(base).Handle(ctx, subject)
	require.NoError(t, err)
	require.Len(t, children, 1)
	chainID := digest.FromString("ordinary chain").String()
	prepared, err := PrepareDmverityLayer(ctx, children[0], chainID, "")
	require.NoError(t, err)
	require.Equal(t, chainID, prepared.Key)
	require.Empty(t, prepared.Labels)
	info, err := store.Info(ctx, subject.Digest)
	require.NoError(t, err)
	require.NotContains(t, info.Labels, dmverityBundleContentLabel)
	require.NotContains(t, info.Labels, dmverityNoReferrerLabel)
	signed, err := DmverityManifestHasSignedReferrer(ctx, store.Store, subject.Digest)
	require.NoError(t, err)
	require.False(t, signed)
	cached, err := AppendCachedSignatureHandlerWrapper(store.Store)(base).Handle(ctx, subject)
	require.NoError(t, err)
	require.Equal(t, children, cached)
}

func TestMalformedReferrerRetryUsesRepairedBundle(t *testing.T) {
	ctx := t.Context()
	store := imagetest.NewContentStore(ctx, t)
	config := store.JSONObject(ocispec.MediaTypeImageConfig, ocispec.Image{})
	layer := store.Blob(ocispec.MediaTypeImageLayer, []byte("layer"))
	subject := store.Manifest(config, layer).Descriptor
	base := images.ChildrenHandler(store.Store)
	malformed := store.Blob(ocispec.MediaTypeImageManifest, []byte("{")).Descriptor
	malformed.ArtifactType = signatureArtifactType
	children, err := AppendSignatureHandlerWrapper(
		referrerTestFetcher{referrers: []ocispec.Descriptor{malformed}}, store.Store,
	)(base).Handle(ctx, subject)
	require.NoError(t, err)
	require.NotContains(t, children[1].Annotations, TargetLayerDmverityLabel)

	repaired := addTestDmverityReferrer(t, store, subject, layer.Descriptor.Digest, "repaired")
	children, err = AppendSignatureHandlerWrapper(
		referrerTestFetcher{referrers: []ocispec.Descriptor{repaired}}, store.Store,
	)(base).Handle(ctx, subject)
	require.NoError(t, err)
	target, err := ParseDmverityTarget(children[1].Annotations[TargetLayerDmverityLabel])
	require.NoError(t, err)
	require.Equal(t, digest.FromString("root-repaired").Encoded(), target.RootHash)
	info, err := store.Info(ctx, subject.Digest)
	require.NoError(t, err)
	require.Equal(t, repaired.Digest.String(), info.Labels[dmverityBundleContentLabel])
	require.NotContains(t, info.Labels, dmverityNoReferrerLabel)
}

func TestMalformedLatestReferrerPreservesRetainedSelection(t *testing.T) {
	for _, test := range []struct {
		state   string
		payload int
	}{
		{"valid cache", -1},
		{"missing cached payload", -1},
		{"missing cached bundle", -1},
		{"invalid cached selection", -1},
		{"metadata size", 0},
		{"tree size", 1},
		{"signature size", 2},
	} {
		t.Run(test.state, func(t *testing.T) {
			ctx := t.Context()
			store := imagetest.NewContentStore(ctx, t)
			config := store.JSONObject(ocispec.MediaTypeImageConfig, ocispec.Image{})
			layer := store.Blob(ocispec.MediaTypeImageLayer, []byte("layer"))
			subject := store.Manifest(config, layer).Descriptor
			base := images.Handlers(remotes.FetchHandler(store.Store, referrerTestFetcher{}), images.ChildrenHandler(store.Store))
			older := addTestDmverityReferrer(t, store, subject, layer.Descriptor.Digest, "older")
			older.Annotations = map[string]string{ocispec.AnnotationCreated: "2026-11-12T12:00:00Z"}
			children, err := AppendSignatureHandlerWrapper(
				referrerTestFetcher{referrers: []ocispec.Descriptor{older}}, store.Store,
			)(base).Handle(ctx, subject)
			require.NoError(t, err)
			target, err := ParseDmverityTarget(children[1].Annotations[TargetLayerDmverityLabel])
			require.NoError(t, err)

			var wantErr string
			switch test.state {
			case "missing cached payload":
				require.NoError(t, store.Delete(ctx, target.Tree.Digest))
				wantErr = "read retained dm-verity payload"
			case "missing cached bundle":
				require.NoError(t, store.Delete(ctx, older.Digest))
				wantErr = "read retained signed dm-verity bundle"
			case "invalid cached selection":
				_, err := store.Update(ctx, content.Info{
					Digest: subject.Digest,
					Labels: map[string]string{dmverityBundleContentLabel: "not-a-digest"},
				}, "labels."+dmverityBundleContentLabel)
				require.NoError(t, err)
				wantErr = "invalid retained dm-verity referrer"
			}
			before, err := store.Info(ctx, subject.Digest)
			require.NoError(t, err)
			beforeLabels := maps.Clone(before.Labels)

			malformed := store.Blob(ocispec.MediaTypeImageManifest, []byte("{")).Descriptor
			if test.payload >= 0 {
				data, err := content.ReadBlob(ctx, store.Store, older)
				require.NoError(t, err)
				var bundle ocispec.Manifest
				require.NoError(t, json.Unmarshal(data, &bundle))
				bundle.Layers[test.payload].Size++
				malformed = store.JSONObject(ocispec.MediaTypeImageManifest, bundle).Descriptor
			}
			malformed.ArtifactType = signatureArtifactType
			malformed.Annotations = map[string]string{ocispec.AnnotationCreated: "2026-11-13T12:00:00Z"}
			retained, err := AppendSignatureHandlerWrapper(
				referrerTestFetcher{referrers: []ocispec.Descriptor{older, malformed}}, store.Store,
			)(base).Handle(ctx, subject)
			if wantErr == "" {
				require.NoError(t, err)
				require.Equal(t, children, retained)
				cached, err := AppendCachedSignatureHandlerWrapper(store.Store)(base).Handle(ctx, subject)
				require.NoError(t, err)
				require.Equal(t, children, cached)
			} else {
				require.ErrorContains(t, err, wantErr)
				require.Nil(t, retained)
			}
			after, err := store.Info(ctx, subject.Digest)
			require.NoError(t, err)
			require.Equal(t, beforeLabels, after.Labels)
			if wantErr == "" {
				replacement := addTestDmverityReferrerWithRoot(t, store, subject, layer.Descriptor.Digest, "replacement", target.RootHash)
				publish := stageTestDmverityRotation(t, ctx, store.Store, base, subject, replacement)
				require.NoError(t, publish(ctx), "a malformed candidate must not prevent a later valid replacement")
				after, err = store.Info(ctx, subject.Digest)
				require.NoError(t, err)
				require.Equal(t, replacement.Digest.String(), after.Labels[dmverityBundleContentLabel])
			}
		})
	}
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
	referrer.Annotations = map[string]string{ocispec.AnnotationCreated: "2026-11-13T12:00:00Z"}
	older := addTestDmverityReferrerWithRoot(t, store, subject, layer.Digest, "older", digest.FromString("root-retained").Encoded())
	older.Annotations = map[string]string{ocispec.AnnotationCreated: "2026-11-12T12:00:00Z"}
	fetcher := referrerTestFetcher{referrers: []ocispec.Descriptor{older, referrer}}
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

func TestMetadataOnlyManifestPreservesDmverityObservation(t *testing.T) {
	for _, mode := range []string{"same root", "changed root", "unobserved"} {
		t.Run(mode, func(t *testing.T) {
			ctx := t.Context()
			store := imagetest.NewContentStore(ctx, t)
			platform := ocispec.Platform{OS: "linux", Architecture: "amd64"}
			config := store.JSONObject(ocispec.MediaTypeImageConfig, ocispec.Image{Platform: platform})
			layer := store.Blob(ocispec.MediaTypeImageLayer, []byte("layer"))
			subject := store.Manifest(config, layer).Descriptor
			subject.Platform = &platform
			base := images.ChildrenHandler(store.Store)
			root := digest.FromString("original root").Encoded()
			original := addTestDmverityReferrerWithRoot(t, store, subject, layer.Descriptor.Digest, "original", root)
			var selected []ocispec.Descriptor
			if mode != "unobserved" {
				var err error
				selected, err = AppendSignatureHandlerWrapper(
					referrerTestFetcher{referrers: []ocispec.Descriptor{original}}, store.Store,
				)(base).Handle(ctx, subject)
				require.NoError(t, err)
			}
			before, err := store.Info(ctx, subject.Digest)
			require.NoError(t, err)
			if mode == "changed root" {
				root = digest.FromString("changed root").Encoded()
			}
			replacement := addTestDmverityReferrerWithRoot(t, store, subject, layer.Descriptor.Digest, "replacement", root)
			require.NoError(t, store.Delete(ctx, digest.FromString("replacement-tree")))

			// WithAllMetadata returns only the config for this non-selected platform.
			metadataOnly := remotes.FilterManifestByPlatformHandler(base, platforms.Only(
				ocispec.Platform{OS: "linux", Architecture: "arm64"},
			))
			children, err := AppendSignatureHandlerWrapper(
				referrerTestFetcher{referrers: []ocispec.Descriptor{replacement}}, store.Store,
			)(metadataOnly).Handle(ctx, subject)
			require.NoError(t, err)
			require.Len(t, children, 1)
			require.Equal(t, config.Descriptor.Digest, children[0].Digest)
			after, err := store.Info(ctx, subject.Digest)
			require.NoError(t, err)
			require.Equal(t, before.Labels, after.Labels)

			children, err = AppendCachedSignatureHandlerWrapper(store.Store)(metadataOnly).Handle(ctx, subject)
			require.NoError(t, err)
			require.Len(t, children, 1)
			if mode != "unobserved" {
				cached, err := AppendCachedSignatureHandlerWrapper(store.Store)(base).Handle(ctx, subject)
				require.NoError(t, err)
				require.Equal(t, selected, cached)
			}
		})
	}
}

func TestEmptyImageStillRecordsDmverityObservation(t *testing.T) {
	ctx := t.Context()
	store := imagetest.NewContentStore(ctx, t)
	config := store.JSONObject(ocispec.MediaTypeImageConfig, ocispec.Image{})
	subject := store.Manifest(config).Descriptor
	children, err := AppendSignatureHandlerWrapper(referrerTestFetcher{}, store.Store)(
		images.ChildrenHandler(store.Store),
	).Handle(ctx, subject)
	require.NoError(t, err)
	require.Len(t, children, 1)
	info, err := store.Info(ctx, subject.Digest)
	require.NoError(t, err)
	require.Equal(t, "true", info.Labels[dmverityNoReferrerLabel])
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

func TestDmverityObservationKeepsSignedSelectionUntilPublication(t *testing.T) {
	ctx := t.Context()
	store := imagetest.NewContentStore(ctx, t)
	subject := store.Blob(ocispec.MediaTypeImageManifest, []byte("{}")).Descriptor.Digest
	layer := digest.FromString("layer")
	root := digest.FromString("root").Encoded()
	first := addTestDmverityReferrerWithRoot(t, store, ocispec.Descriptor{Digest: subject}, layer, "first", root).Digest
	second := addTestDmverityReferrerWithRoot(t, store, ocispec.Descriptor{Digest: subject}, layer, "replacement", root).Digest

	for _, referrer := range []digest.Digest{first, "", second, ""} {
		selected, err := recordDmverityObservation(ctx, store.Store, subject, referrer, map[string]struct{}{layer.String(): {}})
		require.NoError(t, err)
		require.Equal(t, first, selected)

		info, err := store.Store.Info(ctx, subject)
		require.NoError(t, err)
		require.Equal(t, first.String(), info.Labels[dmverityBundleContentLabel])
		require.Empty(t, info.Labels[dmverityNoReferrerLabel])
	}
}

func TestDmverityObservationRecordsNoReferrerWithoutDemotingKnownSigned(t *testing.T) {
	ctx := t.Context()
	store := imagetest.NewContentStore(ctx, t)
	subject := store.Blob(ocispec.MediaTypeImageManifest, []byte("{}")).Descriptor.Digest

	selected, err := recordDmverityObservation(ctx, store.Store, subject, "", nil)
	require.NoError(t, err)
	require.Empty(t, selected)

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
	preparation, err := PrepareDmverityLayer(ctx, cached[0], digest.FromString("chain").String(), "")
	require.NoError(t, err)
	require.NoError(t, preparation.ValidateExisting(snapshots.Info{Labels: committed}))
	originalKey := preparation.Key

	replacement := addTestDmverityReferrerWithRoot(t, store, subject, layer.Digest, "new-signature", digest.FromString("root-first").Encoded())
	overlap := addTestDmverityReferrerWithRoot(t, store, subject, layer.Digest, "overlapping-signature", digest.FromString("root-first").Encoded())
	publish := stageTestDmverityRotation(t, ctx, store.Store, base, subject, replacement)
	publishOverlap := stageTestDmverityRotation(t, ctx, store.Store, base, subject, overlap)
	require.NoError(t, publish(ctx))
	require.NoError(t, publishOverlap(ctx))
	info, err = store.Store.Info(ctx, subject.Digest)
	require.NoError(t, err)
	require.Equal(t, replacement.Digest.String(), info.Labels[dmverityBundleContentLabel], "an overlapping pull must not overwrite the published selection")
	cached, err = AppendCachedSignatureHandlerWrapper(store.Store)(base).Handle(ctx, subject)
	require.NoError(t, err)
	replacedLabels, err := DmveritySnapshotLabels(cached[0])
	require.NoError(t, err)
	require.NotEqual(t, committed[dmverityReferrerSignatureDigestLabel], replacedLabels[dmverityReferrerSignatureDigestLabel])
	preparation, err = PrepareDmverityLayer(ctx, cached[0], digest.FromString("chain").String(), "")
	require.NoError(t, err)
	require.NotEqual(t, originalKey, preparation.Key)
	require.ErrorContains(t, preparation.ValidateExisting(snapshots.Info{Labels: committed}), "different signed dm-verity signature digest")
	require.NoError(t, preparation.ValidateExisting(snapshots.Info{Labels: replacedLabels}))

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

func stageTestDmverityRotation(t *testing.T, ctx context.Context, store content.Store, base images.Handler, subject, ref ocispec.Descriptor) func(context.Context) error {
	t.Helper()
	wrap, publish := DmverityUnpackHandlers(referrerTestFetcher{referrers: []ocispec.Descriptor{ref}}, store)
	children, err := wrap(base).Handle(ctx, subject)
	require.NoError(t, err)
	target, err := PrepareDmverityLayer(ctx, children[len(children)-1], digest.FromString("chain").String(), "")
	require.NoError(t, err)
	require.Equal(t, ref.Digest, target.GCContent)
	// Simulate the signed snapshot owner's edge written by successful unpack.
	edge := "containerd.io/gc.ref.snapshot.erofs/" + target.GCQualifier
	_, err = store.Update(ctx, content.Info{
		Digest: ref.Digest,
		Labels: map[string]string{edge: target.Key},
	}, "labels."+edge)
	require.NoError(t, err)
	return publish
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
