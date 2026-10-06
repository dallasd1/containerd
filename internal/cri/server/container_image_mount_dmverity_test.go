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

package server

import (
	"context"
	"errors"
	"testing"

	introspectionapi "github.com/containerd/containerd/api/services/introspection/v1"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/images/imagetest"
	"github.com/containerd/containerd/v2/core/introspection"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/plugins"
	"github.com/containerd/errdefs"
	"github.com/containerd/platforms"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

type dmverityVolumeSnapshotter struct {
	snapshots.Snapshotter
	info snapshots.Info
	err  error
}

type volumeIntrospection struct {
	introspection.Service
	calls        int
	id           string
	capabilities []string
}

func (i *volumeIntrospection) Plugins(context.Context, ...string) (*introspectionapi.PluginsResponse, error) {
	i.calls++
	id := i.id
	if id == "" {
		id = "overlayfs"
	}
	return &introspectionapi.PluginsResponse{Plugins: []*introspectionapi.Plugin{{
		Type:         string(plugins.SnapshotPlugin),
		ID:           id,
		Capabilities: i.capabilities,
	}}}, nil
}

func (s dmverityVolumeSnapshotter) Stat(context.Context, string) (snapshots.Info, error) {
	if s.err != nil {
		return snapshots.Info{}, s.err
	}
	return s.info, nil
}

func TestRejectSignedImageVolume(t *testing.T) {
	ctx := namespaces.WithNamespace(context.Background(), "test")
	store := imagetest.NewContentStore(ctx, t)
	config := store.JSONObject(ocispec.MediaTypeImageConfig, ocispec.Image{})
	layer := store.RandomBlob(ocispec.MediaTypeImageLayer, 16)
	manifest := store.Manifest(config, layer)
	client, err := containerd.New("", containerd.WithServices(
		containerd.WithContentStore(store.Store),
		containerd.WithSnapshotters(map[string]snapshots.Snapshotter{
			"erofs": dmverityVolumeSnapshotter{err: errdefs.ErrNotFound},
		}),
	))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })

	image := containerd.NewImageWithPlatform(client, images.Image{
		Name:   "test-image",
		Target: manifest.Descriptor,
	}, nil)
	subject := manifest.Descriptor.Digest

	t.Run("signed manifest rejected", func(t *testing.T) {
		_, err := store.Update(ctx, content.Info{
			Digest: subject,
			Labels: map[string]string{"containerd.io/gc.ref.content.dmverity": digest.FromString("bundle").String()},
		}, "labels")
		require.NoError(t, err)
		service := &criService{
			client:               client,
			dmverityCapabilities: map[string]bool{"erofs": true},
		}
		err = service.rejectSignedImageVolume(ctx, image, "erofs", platforms.Default())
		require.ErrorIs(t, err, errdefs.ErrNotImplemented)
	})

	t.Run("signed manifest allowed on non-capable snapshotter", func(t *testing.T) {
		_, err := store.Update(ctx, content.Info{
			Digest: subject,
			Labels: map[string]string{"containerd.io/gc.ref.content.dmverity": digest.FromString("bundle").String()},
		}, "labels")
		require.NoError(t, err)
		service := &criService{
			client:               client,
			dmverityCapabilities: map[string]bool{"overlayfs": false},
		}
		err = service.rejectSignedImageVolume(ctx, image, "overlayfs", platforms.Default())
		require.NoError(t, err)
	})

	t.Run("ordinary volume does not inspect snapshot identities", func(t *testing.T) {
		_, err := store.Update(ctx, content.Info{
			Digest: subject,
			Labels: map[string]string{
				"containerd.io/snapshot/erofs.dmverity.no-referrer": "true",
			},
		}, "labels")
		require.NoError(t, err)
		signedSnapshot := dmverityVolumeSnapshotter{
			err: errors.New("ordinary volume must not stat snapshots"),
		}
		introspection := &volumeIntrospection{
			id:           "erofs",
			capabilities: []string{plugins.CapabilityDmverityReferrers},
		}
		client, err := containerd.New("", containerd.WithServices(
			containerd.WithContentStore(store.Store),
			containerd.WithSnapshotters(map[string]snapshots.Snapshotter{"erofs": signedSnapshot}),
			containerd.WithIntrospectionService(introspection),
		))
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, client.Close()) })
		image := containerd.NewImageWithPlatform(client, images.Image{Name: "test-image", Target: manifest.Descriptor}, nil)
		service := &criService{client: client}
		require.Nil(t, service.dmverityCapabilities)
		err = service.rejectSignedImageVolume(ctx, image, "erofs", platforms.Default())
		require.NoError(t, err)
		require.Equal(t, 1, introspection.calls)
	})

	t.Run("legacy manifest without observation allowed", func(t *testing.T) {
		_, err := store.Update(ctx, content.Info{Digest: subject}, "labels")
		require.NoError(t, err)
		service := &criService{
			client:               client,
			dmverityCapabilities: map[string]bool{"erofs": true},
		}
		err = service.rejectSignedImageVolume(ctx, image, "erofs", platforms.Default())
		require.NoError(t, err)
	})
}

func TestRejectSignedImageVolumeForSelectedIndexManifest(t *testing.T) {
	ctx := namespaces.WithNamespace(context.Background(), "test")
	store := imagetest.NewContentStore(ctx, t)
	config := store.JSONObject(ocispec.MediaTypeImageConfig, ocispec.Image{})
	layer := store.RandomBlob(ocispec.MediaTypeImageLayer, 16)
	manifest := store.Manifest(config, layer)
	index := store.Index(imagetest.AddPlatform(manifest, platforms.DefaultSpec()))
	_, err := store.Update(ctx, content.Info{
		Digest: manifest.Descriptor.Digest,
		Labels: map[string]string{
			"containerd.io/gc.ref.content.dmverity": digest.FromString("bundle").String(),
		},
	}, "labels")
	require.NoError(t, err)

	client, err := containerd.New("", containerd.WithServices(containerd.WithContentStore(store.Store)))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	image := containerd.NewImageWithPlatform(client, images.Image{
		Name:   "indexed-signed-image",
		Target: index.Descriptor,
	}, platforms.Default())

	service := &criService{
		client:               client,
		dmverityCapabilities: map[string]bool{"erofs": true},
	}
	capable, err := service.dmverityReferrersEnabled(ctx, "erofs")
	require.NoError(t, err)
	require.True(t, capable)
	err = service.rejectSignedImageVolume(ctx, image, "erofs", platforms.Default())
	require.ErrorIs(t, err, errdefs.ErrNotImplemented)
}

func TestMountedOrdinaryImageVolumeCapabilityIsCached(t *testing.T) {
	ctx := namespaces.WithNamespace(context.Background(), "test")
	store := imagetest.NewContentStore(ctx, t)
	introspection := &volumeIntrospection{}
	client, err := containerd.New("", containerd.WithServices(
		containerd.WithContentStore(store.Store),
		containerd.WithIntrospectionService(introspection),
	))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })

	service := &criService{client: client}
	capable, err := service.dmverityReferrersEnabled(ctx, "overlayfs")
	require.NoError(t, err)
	require.False(t, capable)
	capable, err = service.dmverityReferrersEnabled(ctx, "overlayfs")
	require.NoError(t, err)
	require.False(t, capable)
	require.Equal(t, 1, introspection.calls)
}
