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

package unpack

import (
	"context"
	"crypto/rand"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/containerd/containerd/v2/core/diff"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/images/imagetest"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/core/snapshots"
	snpkg "github.com/containerd/containerd/v2/pkg/snapshotters"
	"github.com/containerd/containerd/v2/plugins"
	"github.com/containerd/platforms"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

func generateRandomDiffIDs(t testing.TB, num int) []digest.Digest {
	const size = 10
	diffIDs := make([]digest.Digest, 0, num)
	for range num {
		b := make([]byte, size)
		_, err := rand.Read(b)
		if err != nil {
			t.Fatalf("failed to generate random bytes: %v", err)
		}
		diffIDs = append(diffIDs, digest.FromBytes(b))
	}
	return diffIDs
}

func BenchmarkUnpackWithChainID(b *testing.B) {
	// This simulates the old way of repeatedly calculating per-layer chainID
	// as we unpack every layers, by calling `identity.ChainID`.
	unpackWithChainID := func(diffIDs []digest.Digest) {
		var chain []digest.Digest
		for i := range diffIDs {
			_ = identity.ChainID(chain) // parent layer chainID
			chain = append(chain, diffIDs[i])
			_ = identity.ChainID(chain).String() // current layer chainID
		}
		_ = identity.ChainID(chain).String()
	}

	numLayers := []int{5, 10, 25, 50}
	for _, sz := range numLayers {
		b.Run(fmt.Sprintf("num of layers: %d", sz), func(b *testing.B) {
			diffIDs := generateRandomDiffIDs(b, sz)
			for i := 0; i < b.N; i++ {
				unpackWithChainID(diffIDs)
			}
		})
	}
}

func BenchmarkUnpackWithChainIDs(b *testing.B) {
	// This simulates the new way of pre-calculating all chainIDs for every layer
	// by calling `identity.ChainIDs` once.
	unpackWithChainIDs := func(diffIDs []digest.Digest) {
		chainIDs := make([]digest.Digest, len(diffIDs))
		copy(chainIDs, diffIDs)
		chainIDs = identity.ChainIDs(chainIDs)
		for i := range diffIDs {
			if i > 0 {
				_ = chainIDs[i-1].String() // parent layer chainID
			}
			_ = chainIDs[i].String() // current layer chainID
		}
		if len(chainIDs) > 0 {
			_ = chainIDs[len(chainIDs)-1].String()
		}
	}

	numLayers := []int{5, 10, 25, 50}
	for _, sz := range numLayers {
		b.Run(fmt.Sprintf("num of layers: %d", sz), func(b *testing.B) {
			diffIDs := generateRandomDiffIDs(b, sz)
			for i := 0; i < b.N; i++ {
				unpackWithChainIDs(diffIDs)
			}
		})
	}
}

func TestBindToOverlay(t *testing.T) {
	testCases := []struct {
		name   string
		mounts []mount.Mount
		expect []mount.Mount
	}{
		{
			name: "single bind mount",
			mounts: []mount.Mount{
				{
					Type:    "bind",
					Source:  "/path/to/source",
					Options: []string{"ro", "rbind"},
				},
			},
			expect: []mount.Mount{
				{
					Type:   "overlay",
					Source: "overlay",
					Options: []string{
						"ro",
						"upperdir=/path/to/source",
					},
				},
			},
		},
		{
			name: "overlay mount",
			mounts: []mount.Mount{
				{
					Type:   "overlay",
					Source: "overlay",
					Options: []string{
						"lowerdir=/path/to/lower",
						"upperdir=/path/to/upper",
					},
				},
			},
			expect: []mount.Mount{
				{
					Type:   "overlay",
					Source: "overlay",
					Options: []string{
						"lowerdir=/path/to/lower",
						"upperdir=/path/to/upper",
					},
				},
			},
		},
		{
			name: "multiple mounts",
			mounts: []mount.Mount{
				{
					Type:   "bind",
					Source: "/path/to/source1",
				},
				{
					Type:   "bind",
					Source: "/path/to/source2",
				},
			},
			expect: []mount.Mount{
				{
					Type:   "bind",
					Source: "/path/to/source1",
				},
				{
					Type:   "bind",
					Source: "/path/to/source2",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := bindToOverlay(tc.mounts)
			if !reflect.DeepEqual(result, tc.expect) {
				t.Errorf("unexpected result: got %v, want %v", result, tc.expect)
			}
		})
	}
}

type recordingSnapshotter struct {
	snapshots.Snapshotter
	committed map[string]snapshots.Info
}

func (s *recordingSnapshotter) Prepare(context.Context, string, string, ...snapshots.Opt) ([]mount.Mount, error) {
	return nil, nil
}

func (s *recordingSnapshotter) Commit(_ context.Context, name, _ string, opts ...snapshots.Opt) error {
	var info snapshots.Info
	for _, opt := range opts {
		if err := opt(&info); err != nil {
			return err
		}
	}
	s.committed[name] = info
	return nil
}

func (s *recordingSnapshotter) Remove(context.Context, string) error {
	return nil
}

type diffIDApplier map[digest.Digest]digest.Digest

func (a diffIDApplier) Apply(_ context.Context, desc ocispec.Descriptor, _ []mount.Mount, _ ...diff.ApplyOpt) (ocispec.Descriptor, error) {
	return ocispec.Descriptor{MediaType: ocispec.MediaTypeImageLayer, Digest: a[desc.Digest]}, nil
}

func TestUnpackIgnoresInheritedDmverityIdentity(t *testing.T) {
	const (
		rootHashLabel        = "containerd.io/snapshot/erofs.dmverity.root-hash"
		signatureDigestLabel = "containerd.io/snapshot/erofs.dmverity.signature-digest"
	)
	injected := map[string]string{
		rootHashLabel:        strings.Repeat("a", 64),
		signatureDigestLabel: digest.FromString("forged signature").String(),
	}

	for _, tc := range []struct {
		name         string
		capabilities []string
	}{
		{name: "dm-verity referrers disabled"},
		{name: "unsigned layer", capabilities: []string{plugins.CapabilityDmverityReferrers}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := imagetest.NewContentStore(ctx, t)
			layer := store.Blob(ocispec.MediaTypeImageLayerGzip, []byte("layer"))
			layer.Descriptor.Annotations = injected
			diffID := digest.FromString("uncompressed layer")
			config := store.JSONObject(ocispec.MediaTypeImageConfig, ocispec.Image{
				RootFS: ocispec.RootFS{Type: "layers", DiffIDs: []digest.Digest{diffID}},
			})
			manifest := store.Manifest(config, layer)

			sn := &recordingSnapshotter{committed: map[string]snapshots.Info{}}
			u, err := NewUnpacker(ctx, store.Store, WithUnpackPlatform(Platform{
				SnapshotterKey:          "erofs",
				Snapshotter:             sn,
				SnapshotterCapabilities: tc.capabilities,
				Applier:                 diffIDApplier{layer.Descriptor.Digest: diffID},
			}))
			require.NoError(t, err)
			require.NoError(t, images.Dispatch(ctx, u.Unpack(images.ChildrenHandler(store.Store)), nil, manifest.Descriptor))
			_, err = u.Wait()
			require.NoError(t, err)

			info, ok := sn.committed[diffID.String()]
			require.True(t, ok, "layer was not committed under its plain chain ID")
			require.NotContains(t, info.Labels, rootHashLabel)
			require.NotContains(t, info.Labels, signatureDigestLabel)
		})
	}
}

// signedImageFixture stores an image whose layer has a valid, retained
// dm-verity referrer bundle, plus the image labels that pin its selection.
func signedImageFixture(t *testing.T, store imagetest.ContentStore, rootHash string) (
	manifest imagetest.Content, layer ocispec.Descriptor, diffID digest.Digest, imageLabels map[string]string,
) {
	t.Helper()
	const (
		erofsAnnotationPrefix = "io.containerd.erofs.v1/"
		sourceLayerAnnotation = erofsAnnotationPrefix + "dmverity.source-layer-digest"
		rootHashAnnotation    = erofsAnnotationPrefix + "dmverity.root-hash"
		artifactType          = "application/vnd.containerd.erofs.dmverity.v1"
		metadataMediaType     = "application/vnd.containerd.erofs.metadata.v1"
		treeMediaType         = "application/vnd.containerd.erofs.dmverity.merkle-tree.v1"
		signatureMediaType    = "application/vnd.containerd.erofs.dmverity.layer-signature.v1+pkcs7"
	)

	layerBlob := store.Blob(ocispec.MediaTypeImageLayerGzip, []byte("layer"))
	layer = layerBlob.Descriptor
	diffID = digest.FromString("uncompressed layer")
	config := store.JSONObject(ocispec.MediaTypeImageConfig, ocispec.Image{
		RootFS: ocispec.RootFS{Type: "layers", DiffIDs: []digest.Digest{diffID}},
	})
	manifest = store.Manifest(config, layerBlob)

	payload := func(mediaType string, extra map[string]string) ocispec.Descriptor {
		blob := store.Blob(mediaType, []byte(mediaType+" for "+layer.Digest.String()))
		desc := blob.Descriptor
		desc.Annotations = map[string]string{sourceLayerAnnotation: layer.Digest.String()}
		for k, v := range extra {
			desc.Annotations[k] = v
		}
		return desc
	}
	subject := manifest.Descriptor
	referrer := store.JSONObject(ocispec.MediaTypeImageManifest, ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: artifactType,
		Config:       ocispec.DescriptorEmptyJSON,
		Subject:      &subject,
		Layers: []ocispec.Descriptor{
			payload(metadataMediaType, nil),
			payload(treeMediaType, nil),
			payload(signatureMediaType, map[string]string{rootHashAnnotation: rootHash}),
		},
	})

	imageLabels = map[string]string{
		"containerd.io/gc.ref.content.dmverity-referrer/" + subject.Digest.Encoded(): referrer.Descriptor.Digest.String(),
	}
	return manifest, layer, diffID, imageLabels
}

func TestUnpackRequiresValidatedReferrersForSignedIdentity(t *testing.T) {
	const rootHash = "b4e1c9f30a5d7e2186c4fb0937ad5e2c81f6b3a4d9c0e7182b5a6f3c4d9e0a71"

	for _, tc := range []struct {
		name       string
		validated  bool
		wantSigned bool
	}{
		{name: "discovery did not validate targets"},
		{name: "discovery validated targets", validated: true, wantSigned: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := imagetest.NewContentStore(ctx, t)
			manifest, layer, diffID, imageLabels := signedImageFixture(t, store, rootHash)

			sn := &recordingSnapshotter{committed: map[string]snapshots.Info{}}
			uopts := []UnpackerOpt{WithUnpackPlatform(Platform{
				SnapshotterKey:          "erofs",
				Snapshotter:             sn,
				SnapshotterCapabilities: []string{plugins.CapabilityDmverityReferrers},
				Applier:                 diffIDApplier{layer.Digest: diffID},
			})}
			if tc.validated {
				uopts = append(uopts, WithDmverityReferrersValidated())
			}
			u, err := NewUnpacker(ctx, store.Store, uopts...)
			require.NoError(t, err)

			handler := snpkg.AppendCachedSignatureHandlerWrapper(store.Store, imageLabels)(
				images.ChildrenHandler(store.Store))
			require.NoError(t, images.Dispatch(ctx, u.Unpack(handler), nil, manifest.Descriptor))
			_, err = u.Wait()
			require.NoError(t, err)

			if tc.wantSigned {
				require.NotContains(t, sn.committed, diffID.String(),
					"signed layer must not reuse the plain chain ID")
				require.Len(t, sn.committed, 1)
				for _, info := range sn.committed {
					require.Equal(t, rootHash, info.Labels["containerd.io/snapshot/erofs.dmverity.root-hash"])
				}
				return
			}
			// Without a capable applier the signed sidecars are never written,
			// so the layer must not claim a signed snapshot identity.
			require.Contains(t, sn.committed, diffID.String())
			require.NotContains(t, sn.committed[diffID.String()].Labels,
				"containerd.io/snapshot/erofs.dmverity.root-hash")
		})
	}
}

// TestUnpackQualifiedSnapshotEdgeTracksManifest verifies that re-signing an
// image replaces that manifest's snapshot GC edge rather than adding a second
// one, so superseded materializations do not stay rooted forever.
func TestUnpackQualifiedSnapshotEdgeTracksManifest(t *testing.T) {
	const snapshotGCPrefix = "containerd.io/gc.ref.snapshot.erofs"

	ctx := context.Background()
	store := imagetest.NewContentStore(ctx, t)

	rootHashes := []string{
		"b4e1c9f30a5d7e2186c4fb0937ad5e2c81f6b3a4d9c0e7182b5a6f3c4d9e0a71",
		"c5f2dae41b6e8f3297d50ac1a48be6f3d20a7c4b5eadf8293c6b7a4d5eaf1b82",
	}

	var configDigest digest.Digest
	chainIDs := map[string]string{}
	unpackManifest := func(manifest imagetest.Content, layer ocispec.Descriptor, diffID digest.Digest, imageLabels map[string]string) string {
		sn := &recordingSnapshotter{committed: map[string]snapshots.Info{}}
		u, err := NewUnpacker(ctx, store.Store, WithUnpackPlatform(Platform{
			SnapshotterKey:          "erofs",
			Snapshotter:             sn,
			SnapshotterCapabilities: []string{plugins.CapabilityDmverityReferrers},
			Applier:                 diffIDApplier{layer.Digest: diffID},
		}), WithDmverityReferrersValidated())
		require.NoError(t, err)

		handler := snpkg.AppendCachedSignatureHandlerWrapper(store.Store, imageLabels)(
			images.ChildrenHandler(store.Store))
		require.NoError(t, images.Dispatch(ctx, u.Unpack(handler), nil, manifest.Descriptor))
		_, err = u.Wait()
		require.NoError(t, err)

		require.Len(t, sn.committed, 1)
		for chainID := range sn.committed {
			return chainID
		}
		return ""
	}
	var (
		lastManifest imagetest.Content
		lastLayer    ocispec.Descriptor
		lastDiffID   digest.Digest
	)
	for _, rootHash := range rootHashes {
		manifest, layer, diffID, imageLabels := signedImageFixture(t, store, rootHash)
		chainIDs[rootHash] = unpackManifest(manifest, layer, diffID, imageLabels)
		lastManifest, lastLayer, lastDiffID = manifest, layer, diffID

		// Both pulls describe the same image content, so they share a config.
		cfg, err := images.Config(ctx, store.Store, manifest.Descriptor, platforms.All)
		require.NoError(t, err)
		if configDigest == "" {
			configDigest = cfg.Digest
		}
		require.Equal(t, configDigest, cfg.Digest, "fixtures must share a config")
	}

	require.NotEqual(t, chainIDs[rootHashes[0]], chainIDs[rootHashes[1]],
		"re-signing must produce a distinct snapshot identity")

	info, err := store.Store.Info(ctx, configDigest)
	require.NoError(t, err)

	var edges []string
	for key, value := range info.Labels {
		if strings.HasPrefix(key, snapshotGCPrefix) {
			edges = append(edges, key+"="+value)
		}
	}
	require.Len(t, edges, 1,
		"re-signing must replace the manifest's snapshot edge, got %v", edges)
	require.Contains(t, edges[0], chainIDs[rootHashes[1]],
		"the surviving edge must point at the current materialization")

	// An unsigned unpack of the same manifest releases its signed edge.
	plainChainID := unpackManifest(lastManifest, lastLayer, lastDiffID, nil)
	info, err = store.Store.Info(ctx, configDigest)
	require.NoError(t, err)
	edges = nil
	for key, value := range info.Labels {
		if strings.HasPrefix(key, snapshotGCPrefix) {
			edges = append(edges, key+"="+value)
		}
	}
	require.Equal(t, []string{snapshotGCPrefix + "=" + plainChainID}, edges)
}
