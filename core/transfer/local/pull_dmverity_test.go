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

package local

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/containerd/containerd/v2/core/content"

	"github.com/containerd/containerd/v2/core/diff"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/images/imagetest"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/core/transfer"
	imageTransfer "github.com/containerd/containerd/v2/core/transfer/image"
	"github.com/containerd/containerd/v2/core/unpack"
	snpkg "github.com/containerd/containerd/v2/pkg/snapshotters"
	"github.com/containerd/platforms"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

const (
	testDmverityArtifactType = "application/vnd.containerd.erofs.dmverity.v1"
	testDmveritySourceLayer  = "io.containerd.erofs.v1/dmverity.source-layer-digest"
	testDmverityRootHash     = "io.containerd.erofs.v1/dmverity.root-hash"
)

type testDmveritySource struct {
	name    string
	target  ocispec.Descriptor
	fetcher *testDmverityFetcher
}

func (s testDmveritySource) Resolve(context.Context) (string, ocispec.Descriptor, error) {
	return s.name, s.target, nil
}

func (s testDmveritySource) Fetcher(context.Context, string) (transfer.Fetcher, error) {
	return s.fetcher, nil
}

type testDmverityFetcher struct {
	refs     []ocispec.Descriptor
	requests int
	refErr   error
}

func (f *testDmverityFetcher) Fetch(context.Context, ocispec.Descriptor) (io.ReadCloser, error) {
	return nil, fmt.Errorf("unexpected network fetch")
}

func (f *testDmverityFetcher) FetchReferrers(context.Context, digest.Digest, ...remotes.FetchReferrersOpt) ([]ocispec.Descriptor, error) {
	f.requests++
	return f.refs, f.refErr
}

type testDmverityImageStore struct{}

func (testDmverityImageStore) Get(context.Context, string) (images.Image, error) {
	return images.Image{}, nil
}
func (testDmverityImageStore) List(context.Context, ...string) ([]images.Image, error) {
	return nil, nil
}
func (testDmverityImageStore) Create(_ context.Context, image images.Image) (images.Image, error) {
	return image, nil
}
func (testDmverityImageStore) Update(_ context.Context, image images.Image, _ ...string) (images.Image, error) {
	return image, nil
}
func (testDmverityImageStore) Delete(context.Context, string, ...images.DeleteOpt) error {
	return nil
}

type testDmverityUnpackImageStore struct {
	store *imageTransfer.Store
}

type testDmveritySnapshotter struct {
	snapshots.Snapshotter
}

type testDmverityApplier struct {
	diff.Applier
}

func (s testDmverityUnpackImageStore) Store(
	ctx context.Context,
	desc ocispec.Descriptor,
	store images.Store,
) ([]images.Image, error) {
	return s.store.Store(ctx, desc, store)
}

func (s testDmverityUnpackImageStore) UnpackPlatforms() []transfer.UnpackConfiguration {
	return s.store.UnpackPlatforms()
}

func TestFetchOnlyPullRetainsDmverityBundleForOfflineUnpack(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("retention-%v", enabled), func(t *testing.T) {
			ctx := t.Context()
			store := imagetest.NewContentStore(ctx, t)
			config := store.JSONObject(ocispec.MediaTypeImageConfig, ocispec.Image{})
			layer := store.RandomBlob(ocispec.MediaTypeImageLayer, 16)
			manifest := store.Manifest(config, layer)
			referrer := makeTestDmverityReferrer(store, manifest.Descriptor, layer.Descriptor)
			fetcher := &testDmverityFetcher{refs: []ocispec.Descriptor{referrer}}
			index := store.Index(imagetest.AddPlatform(manifest, platforms.DefaultSpec()))
			source := testDmveritySource{name: "registry.example/image:tag", target: index.Descriptor, fetcher: fetcher}
			is := imageTransfer.NewStore(source.name, imageTransfer.WithPlatforms(platforms.DefaultSpec()))

			ts := &localTransferService{
				content: store.Store,
				images:  testDmverityImageStore{},
				config:  TransferConfig{PullHandlerWrapper: testDmverityPullWrapper(enabled)},
			}
			require.NoError(t, ts.pull(ctx, source, is, &transfer.Config{}))
			require.Equal(t, boolToInt(enabled), fetcher.requests)

			info, err := store.Store.Info(ctx, manifest.Descriptor.Digest)
			require.NoError(t, err)
			if !enabled {
				require.Empty(t, info.Labels["containerd.io/gc.ref.content.dmverity"])
				return
			}

			require.Equal(t, referrer.Digest.String(), info.Labels["containerd.io/gc.ref.content.dmverity"])
			retained, err := snpkg.DmverityManifestHasSignedReferrer(ctx, store.Store, manifest.Descriptor.Digest)
			require.NoError(t, err)
			require.True(t, retained)

			offline := snpkg.AppendCachedSignatureHandlerWrapper(store.Store)(images.ChildrenHandler(store.Store))
			children, err := offline.Handle(ctx, manifest.Descriptor)
			require.NoError(t, err)
			target, err := snpkg.ParseDmverityTarget(children[1].Annotations[snpkg.TargetLayerDmverityLabel])
			require.NoError(t, err)
			require.Equal(t, digest.FromString("root").Encoded(), target.RootHash)

			bundleInfo, err := store.Store.Info(ctx, referrer.Digest)
			require.NoError(t, err)
			var retainedPayloads int
			for key := range bundleInfo.Labels {
				if strings.HasPrefix(key, "containerd.io/gc.ref.content.") {
					retainedPayloads++
				}
			}
			require.Equal(t, 3, retainedPayloads)
		})
	}
}

func TestExplicitUnpackDoesNotEnableFetchOnlyRetention(t *testing.T) {
	ctx := t.Context()
	store := imagetest.NewContentStore(ctx, t)
	config := store.JSONObject(ocispec.MediaTypeImageConfig, ocispec.Image{})
	manifest := store.Manifest(config)
	layer := store.RandomBlob(ocispec.MediaTypeImageLayer, 16)
	referrer := makeTestDmverityReferrer(store, manifest.Descriptor, layer.Descriptor)
	fetcher := &testDmverityFetcher{refs: []ocispec.Descriptor{referrer}}
	source := testDmveritySource{name: "registry.example/image:tag", target: manifest.Descriptor, fetcher: fetcher}
	is := imageTransfer.NewStore(source.name,
		imageTransfer.WithPlatforms(platforms.DefaultSpec()),
		imageTransfer.WithUnpack(platforms.DefaultSpec(), "overlayfs"),
	)

	ts := &localTransferService{
		content: store.Store,
		images:  testDmverityImageStore{},
		config: TransferConfig{
			PullHandlerWrapper: testDmverityPullWrapper(true),
			UnpackPlatforms: []unpack.Platform{{
				Platform:       platforms.Only(platforms.DefaultSpec()),
				SnapshotterKey: "overlayfs",
				Snapshotter:    testDmveritySnapshotter{},
				Applier:        testDmverityApplier{},
			}},
		},
	}
	err := ts.pull(ctx, source, testDmverityUnpackImageStore{store: is}, &transfer.Config{})
	require.NoError(t, err)
	require.Zero(t, fetcher.requests)
}

func TestFetchOnlyPullPropagatesDmverityDiscoveryError(t *testing.T) {
	ctx := t.Context()
	store := imagetest.NewContentStore(ctx, t)
	config := store.JSONObject(ocispec.MediaTypeImageConfig, ocispec.Image{})
	manifest := store.Manifest(config)
	sentinel := errors.New("referrer discovery failed")
	fetcher := &testDmverityFetcher{refErr: sentinel}
	source := testDmveritySource{name: "registry.example/image:tag", target: manifest.Descriptor, fetcher: fetcher}
	ts := &localTransferService{
		content: store.Store,
		images:  testDmverityImageStore{},
		config:  TransferConfig{PullHandlerWrapper: testDmverityPullWrapper(true)},
	}
	err := ts.pull(ctx, source, imageTransfer.NewStore(source.name), &transfer.Config{})
	require.ErrorIs(t, err, sentinel)
	require.Equal(t, 1, fetcher.requests)
	info, err := store.Store.Info(ctx, manifest.Descriptor.Digest)
	require.NoError(t, err)
	require.Empty(t, info.Labels["containerd.io/gc.ref.content.dmverity"])
}

func testDmverityPullWrapper(enabled bool) func(context.Context, remotes.Fetcher, content.Store, bool, []unpack.Platform) (func(images.Handler) images.Handler, error) {
	return func(_ context.Context, fetcher remotes.Fetcher, store content.Store, requestHasUnpack bool, _ []unpack.Platform) (func(images.Handler) images.Handler, error) {
		if enabled && !requestHasUnpack {
			return snpkg.AppendSignatureHandlerWrapper(fetcher, store), nil
		}
		return nil, nil
	}
}

func TestPullHandlerWrapperRequestContext(t *testing.T) {
	for _, mode := range []string{"nil", "fetch", "overlayfs", "unsupported", "error"} {
		t.Run(mode, func(t *testing.T) {
			ctx := t.Context()
			store := imagetest.NewContentStore(ctx, t)
			config := store.JSONObject(ocispec.MediaTypeImageConfig, ocispec.Image{})
			manifest := store.Manifest(config)
			fetcher := &testDmverityFetcher{}
			source := testDmveritySource{name: "registry.example/image:tag", target: manifest.Descriptor, fetcher: fetcher}
			options := []imageTransfer.StoreOpt{imageTransfer.WithPlatforms(platforms.DefaultSpec())}
			explicit := mode == "overlayfs" || mode == "unsupported"
			if explicit {
				options = append(options, imageTransfer.WithUnpack(platforms.DefaultSpec(), mode))
			}
			is := imageTransfer.NewStore(source.name, options...)
			ts := &localTransferService{content: store.Store, images: testDmverityImageStore{}}
			if mode == "overlayfs" {
				ts.config.UnpackPlatforms = []unpack.Platform{{
					Platform: platforms.Only(platforms.DefaultSpec()), SnapshotterKey: mode,
					Snapshotter: testDmveritySnapshotter{}, Applier: testDmverityApplier{},
				}}
			}
			calls := 0
			sentinel := errors.New("wrapper creation failure")
			if mode != "nil" {
				ts.config.PullHandlerWrapper = func(_ context.Context, f remotes.Fetcher, cs content.Store, requested bool, matched []unpack.Platform) (func(images.Handler) images.Handler, error) {
					calls++
					require.Same(t, fetcher, f)
					require.NotNil(t, cs)
					require.Equal(t, explicit, requested)
					if mode == "overlayfs" {
						require.Len(t, matched, 1)
					} else {
						require.Empty(t, matched)
					}
					if mode == "error" {
						return nil, sentinel
					}
					return func(h images.Handler) images.Handler { return h }, nil
				}
			}
			var storer transfer.ImageStorer = is
			if explicit {
				storer = testDmverityUnpackImageStore{store: is}
			}
			err := ts.pull(ctx, source, storer, &transfer.Config{})
			if mode == "error" {
				require.ErrorIs(t, err, sentinel)
			} else if mode == "unsupported" {
				require.ErrorContains(t, err, "no unpack platforms defined")
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, boolToInt(mode != "nil" && mode != "unsupported"), calls)
			require.Zero(t, fetcher.requests)
		})
	}
}

func makeTestDmverityReferrer(
	store imagetest.ContentStore,
	subject, imageLayer ocispec.Descriptor,
) ocispec.Descriptor {
	payload := func(mediaType, data string, annotations map[string]string) ocispec.Descriptor {
		descriptor := store.Blob(mediaType, []byte(data)).Descriptor
		descriptor.Annotations = map[string]string{testDmveritySourceLayer: imageLayer.Digest.String()}
		for key, value := range annotations {
			descriptor.Annotations[key] = value
		}
		return descriptor
	}
	manifest := ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: testDmverityArtifactType,
		Subject:      &subject,
		Config:       ocispec.DescriptorEmptyJSON,
		Layers: []ocispec.Descriptor{
			payload("application/vnd.containerd.erofs.metadata.v1", "metadata", nil),
			payload("application/vnd.containerd.erofs.dmverity.merkle-tree.v1", "tree", nil),
			payload("application/vnd.containerd.erofs.dmverity.layer-signature.v1+pkcs7", "signature",
				map[string]string{testDmverityRootHash: digest.FromString("root").Encoded()}),
		},
	}
	descriptor := store.JSONObject(ocispec.MediaTypeImageManifest, manifest).Descriptor
	descriptor.ArtifactType = testDmverityArtifactType
	return descriptor
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
