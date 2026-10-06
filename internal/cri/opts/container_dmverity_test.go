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

package opts

import (
	"context"
	"testing"

	introspectionapi "github.com/containerd/containerd/api/services/introspection/v1"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/diff"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/images/imagetest"
	"github.com/containerd/containerd/v2/core/introspection"
	"github.com/containerd/containerd/v2/core/leases"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	snpkg "github.com/containerd/containerd/v2/pkg/snapshotters"
	"github.com/containerd/containerd/v2/plugins"
	"github.com/containerd/errdefs"
	"github.com/containerd/platforms"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

type signedDmverityIntrospection struct {
	introspection.Service
}

func (signedDmverityIntrospection) Plugins(context.Context, ...string) (*introspectionapi.PluginsResponse, error) {
	return &introspectionapi.PluginsResponse{Plugins: []*introspectionapi.Plugin{{
		Capabilities: []string{plugins.CapabilityDmverityReferrers},
	}}}, nil
}

type countingIntrospection struct {
	introspection.Service
	calls *int
}

func (i countingIntrospection) Plugins(context.Context, ...string) (*introspectionapi.PluginsResponse, error) {
	(*i.calls)++
	return &introspectionapi.PluginsResponse{Plugins: []*introspectionapi.Plugin{{
		Type: string(plugins.SnapshotPlugin),
		ID:   "overlayfs",
	}}}, nil
}

type preflightSnapshotter struct {
	snapshots.Snapshotter
	prepares       int
	parent         string
	alreadyExists  bool
	existingLabels map[string]string
	statKeys       []string
}

func (s *preflightSnapshotter) Prepare(_ context.Context, key string, parent string, _ ...snapshots.Opt) ([]mount.Mount, error) {
	s.prepares++
	if key == "container-id" {
		s.parent = parent
	}
	if parent == "" && s.alreadyExists {
		return nil, errdefs.ErrAlreadyExists
	}
	return nil, nil
}

func (s *preflightSnapshotter) Stat(_ context.Context, key string) (snapshots.Info, error) {
	s.statKeys = append(s.statKeys, key)
	return snapshots.Info{Labels: s.existingLabels}, nil
}

type noOpDiffService struct{}

func (noOpDiffService) Compare(context.Context, []mount.Mount, []mount.Mount, ...diff.Opt) (ocispec.Descriptor, error) {
	return ocispec.Descriptor{}, nil
}

func (noOpDiffService) Apply(_ context.Context, desc ocispec.Descriptor, _ []mount.Mount, _ ...diff.ApplyOpt) (ocispec.Descriptor, error) {
	return desc, nil
}

func TestHasSignedDmverityManifestForSelectedPlatform(t *testing.T) {
	ctx := namespaces.WithNamespace(context.Background(), "test")
	store := imagetest.NewContentStore(ctx, t)
	config := store.JSONObject(ocispec.MediaTypeImageConfig, ocispec.Image{})
	layer := store.RandomBlob(ocispec.MediaTypeImageLayer, 16)
	manifest := store.Manifest(config, layer)
	index := store.Index(imagetest.AddPlatform(manifest, platforms.DefaultSpec()))

	client, err := containerd.New("", containerd.WithServices(containerd.WithContentStore(store.Store)))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	image := containerd.NewImageWithPlatform(client, images.Image{
		Name:   "test-image",
		Target: index.Descriptor,
	}, platforms.Default())

	_, err = store.Update(ctx, content.Info{
		Digest: manifest.Descriptor.Digest,
		Labels: map[string]string{"containerd.io/gc.ref.content.dmverity": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
	}, "labels")
	require.NoError(t, err)
	signed, err := snpkg.ImageHasDmverityReferrer(ctx, image.ContentStore(), image.Target(), platforms.Default())
	require.NoError(t, err)
	require.True(t, signed)

	_, err = store.Update(ctx, content.Info{
		Digest: manifest.Descriptor.Digest,
		Labels: map[string]string{"containerd.io/snapshot/erofs.dmverity.no-referrer": "true"},
	}, "labels")
	require.NoError(t, err)
	signed, err = snpkg.ImageHasDmverityReferrer(ctx, image.ContentStore(), image.Target(), platforms.Default())
	require.NoError(t, err)
	require.False(t, signed)
}

func TestWithNewSnapshotValidatesKnownSignedImageBeforeSnapshotCreation(t *testing.T) {
	ctx := leases.WithLease(namespaces.WithNamespace(context.Background(), "test"), "test-lease")
	store := imagetest.NewContentStore(ctx, t)
	config := store.JSONObject(ocispec.MediaTypeImageConfig, ocispec.Image{})
	layer := store.RandomBlob(ocispec.MediaTypeImageLayer, 16)
	manifest := store.Manifest(config, layer)
	_, err := store.Update(ctx, content.Info{
		Digest: manifest.Descriptor.Digest,
		Labels: map[string]string{
			"containerd.io/gc.ref.content.dmverity": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	}, "labels")
	require.NoError(t, err)

	snapshotter := &preflightSnapshotter{}
	client, err := containerd.New("", containerd.WithServices(
		containerd.WithContentStore(store.Store),
		containerd.WithSnapshotters(map[string]snapshots.Snapshotter{"erofs": snapshotter}),
		containerd.WithIntrospectionService(signedDmverityIntrospection{}),
	))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	image := containerd.NewImageWithPlatform(client, images.Image{
		Name:   "signed-image",
		Target: manifest.Descriptor,
	}, platforms.Default())

	container := &containers.Container{Snapshotter: "erofs"}
	err = WithNewSnapshot("container-id", image, false)(ctx, client, container)
	require.ErrorContains(t, err, "read retained signed dm-verity bundle")
	require.Zero(t, snapshotter.prepares, "snapshot creation must not precede signed-chain validation")
}

func TestWithNewSnapshotUnsignedImageDoesNotRequireIntrospection(t *testing.T) {
	ctx := leases.WithLease(namespaces.WithNamespace(context.Background(), "test"), "test-lease")
	store := imagetest.NewContentStore(ctx, t)
	config := store.JSONObject(ocispec.MediaTypeImageConfig, ocispec.Image{})
	layer := store.RandomBlob(ocispec.MediaTypeImageLayer, 16)
	manifest := store.Manifest(config, layer)

	snapshotter := &preflightSnapshotter{}
	introspectionCalls := 0
	client, err := containerd.New("", containerd.WithServices(
		containerd.WithContentStore(store.Store),
		containerd.WithSnapshotters(map[string]snapshots.Snapshotter{"overlayfs": snapshotter}),
		containerd.WithIntrospectionService(countingIntrospection{calls: &introspectionCalls}),
	))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	image := containerd.NewImageWithPlatform(client, images.Image{
		Name:   "unsigned-image",
		Target: manifest.Descriptor,
	}, platforms.Default())

	err = WithNewSnapshot("container-id", image, false)(ctx, client, &containers.Container{Snapshotter: "overlayfs"})
	require.NoError(t, err)
	require.Equal(t, 1, snapshotter.prepares)
	require.Equal(t, 1, introspectionCalls, "only the underlying snapshot option resolution should introspect")
}

func TestNewSnapshotParentResolverSelectsSignedLane(t *testing.T) {
	ctx := leases.WithLease(namespaces.WithNamespace(context.Background(), "test"), "test-lease")
	store := imagetest.NewContentStore(ctx, t)
	diffIDs := []digest.Digest{digest.FromString("base diff"), digest.FromString("layer diff")}
	chainID := identity.ChainID(diffIDs).String()
	config := store.JSONObject(ocispec.MediaTypeImageConfig, ocispec.Image{
		RootFS: ocispec.RootFS{Type: "layers", DiffIDs: diffIDs},
	})
	layer := store.RandomBlob(ocispec.MediaTypeImageLayer, 16)
	manifest := store.Manifest(config, store.RandomBlob(ocispec.MediaTypeImageLayer, 16), layer)
	snapshotter := &preflightSnapshotter{}
	client, err := containerd.New("", containerd.WithServices(
		containerd.WithContentStore(store.Store),
		containerd.WithSnapshotters(map[string]snapshots.Snapshotter{"erofs": snapshotter}),
		containerd.WithIntrospectionService(signedDmverityIntrospection{}),
	))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	image := containerd.NewImageWithPlatform(client, images.Image{
		Name:   "signed-image",
		Target: manifest.Descriptor,
	}, platforms.Default())

	err = containerd.WithNewSnapshotParentResolver("container-id", image, func(_ context.Context, parent string) (string, error) {
		require.Equal(t, chainID, parent)
		return snpkg.DmveritySnapshotKey(parent)
	})(ctx, client, &containers.Container{Snapshotter: "erofs"})
	require.NoError(t, err)
	expected, err := snpkg.DmveritySnapshotKey(chainID)
	require.NoError(t, err)
	require.Equal(t, expected, snapshotter.parent)
	require.NotEqual(t, chainID, snapshotter.parent)
}

func TestWithNewSnapshotPreflightsAndCreatesFromSignedLane(t *testing.T) {
	ctx := leases.WithLease(namespaces.WithNamespace(context.Background(), "test"), "test-lease")
	store := imagetest.NewContentStore(ctx, t)
	diffID := digest.FromString("signed layer diff")
	config := store.JSONObject(ocispec.MediaTypeImageConfig, ocispec.Image{
		Platform: platforms.DefaultSpec(),
		RootFS:   ocispec.RootFS{Type: "layers", DiffIDs: []digest.Digest{diffID}},
	})
	layer := store.RandomBlob(ocispec.MediaTypeImageLayer, 16)
	manifest := store.Manifest(config, layer)
	const (
		artifactType          = "application/vnd.containerd.erofs.dmverity.v1"
		sourceLayerAnnotation = "io.containerd.erofs.v1/dmverity.source-layer-digest"
		rootHashAnnotation    = "io.containerd.erofs.v1/dmverity.root-hash"
		metadataMediaType     = "application/vnd.containerd.erofs.metadata.v1"
		treeMediaType         = "application/vnd.containerd.erofs.dmverity.merkle-tree.v1"
		signatureMediaType    = "application/vnd.containerd.erofs.dmverity.layer-signature.v1+pkcs7"
	)
	const rootHash = "b4e1c9f30a5d7e2186c4fb0937ad5e2c81f6b3a4d9c0e7182b5a6f3c4d9e0a71"
	payload := func(mediaType string, annotations map[string]string) ocispec.Descriptor {
		blob := store.Blob(mediaType, []byte(mediaType))
		blob.Descriptor.Annotations = map[string]string{sourceLayerAnnotation: layer.Descriptor.Digest.String()}
		for key, value := range annotations {
			blob.Descriptor.Annotations[key] = value
		}
		return blob.Descriptor
	}
	signature := payload(signatureMediaType, map[string]string{rootHashAnnotation: rootHash})
	subject := manifest.Descriptor
	referrer := store.JSONObject(ocispec.MediaTypeImageManifest, ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: artifactType,
		Config:       ocispec.DescriptorEmptyJSON,
		Subject:      &subject,
		Layers: []ocispec.Descriptor{
			payload(metadataMediaType, nil),
			payload(treeMediaType, nil),
			signature,
		},
	})
	_, err := store.Store.Update(ctx, content.Info{
		Digest: subject.Digest,
		Labels: map[string]string{
			"containerd.io/gc.ref.content.dmverity": referrer.Descriptor.Digest.String(),
		},
	}, "labels.containerd.io/gc.ref.content.dmverity")
	require.NoError(t, err)

	signedKey, err := snpkg.DmveritySnapshotKey(identity.ChainID([]digest.Digest{diffID}).String())
	require.NoError(t, err)
	snapshotter := &preflightSnapshotter{
		alreadyExists: true,
		existingLabels: map[string]string{
			"containerd.io/snapshot/erofs.dmverity.root-hash":        rootHash,
			"containerd.io/snapshot/erofs.dmverity.signature-digest": signature.Digest.String(),
		},
	}
	client, err := containerd.New("", containerd.WithServices(
		containerd.WithContentStore(store.Store),
		containerd.WithSnapshotters(map[string]snapshots.Snapshotter{"erofs": snapshotter}),
		containerd.WithIntrospectionService(signedDmverityIntrospection{}),
		containerd.WithDiffService(noOpDiffService{}),
	))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	image := containerd.NewImageWithPlatform(client, images.Image{
		Name:   "signed-image",
		Target: manifest.Descriptor,
	}, platforms.Default())
	signed, err := snpkg.ImageHasDmverityReferrer(ctx, image.ContentStore(), image.Target(), platforms.Default())
	require.NoError(t, err)
	require.True(t, signed)

	err = WithNewSnapshot("container-id", image, false)(ctx, client, &containers.Container{Snapshotter: "erofs"})
	require.NoError(t, err)
	require.Equal(t, signedKey, snapshotter.parent)
	require.Equal(t, 2, snapshotter.prepares)
	require.Equal(t, []string{signedKey}, snapshotter.statKeys)
}
