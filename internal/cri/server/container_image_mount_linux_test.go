//go:build linux

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
	"os"
	"testing"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/images/imagetest"
	"github.com/containerd/containerd/v2/core/snapshots"
	imagestore "github.com/containerd/containerd/v2/internal/cri/store/image"
	"github.com/containerd/containerd/v2/pkg/testutil"
	"github.com/containerd/platforms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
)

func TestReuseOrdinaryImageVolumeWithoutRootFS(t *testing.T) {
	testutil.RequiresRoot(t)
	ctx := t.Context()
	store := imagetest.NewContentStore(ctx, t)
	manifest := imagetest.SimpleManifest(50)(store)
	config := manifest.Children[0].Descriptor.Digest
	const ref = "docker.io/library/test:volume"
	client, err := containerd.New("", containerd.WithServices(
		containerd.WithContentStore(store.Store),
		containerd.WithImageStore(aliasImageStore{records: map[string]images.Image{
			ref: {Name: ref, Target: manifest.Descriptor},
		}}),
	))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	service := &criService{
		client: client, dmverityCapabilities: map[string]bool{"erofs": true},
		ImageService: volumeImageService{image: imagestore.Image{ID: config.String(), References: []string{ref}}},
	}
	service.config.StateDir = t.TempDir()
	target := service.getImageVolumeHostPath("sandbox", manifest.Descriptor.Digest.Encoded())
	require.NoError(t, os.MkdirAll(target, 0700))
	err = unix.Mount(target, target, "", unix.MS_BIND, "")
	if errors.Is(err, unix.EPERM) {
		t.Skip("requires bind mount privileges")
	}
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, unix.Unmount(target, 0)) })

	require.NoError(t, store.Delete(ctx, config))
	m := &runtime.Mount{Readonly: true, Image: &runtime.ImageSpec{Image: ref}}
	require.NoError(t, service.mutateImageMount(ctx, m, "erofs", "sandbox", platforms.DefaultSpec()))
	require.Equal(t, target, m.HostPath)
}

func TestGetImageVolumeSnapshotOpts(t *testing.T) {
	ctx := context.Background()

	mappings := []*runtime.IDMapping{
		{
			ContainerId: 0,
			HostId:      65536,
			Length:      65536,
		},
	}

	expectedOpts := optsToInfo(t, containerd.WithRemapperLabels(0, 65536, 0, 65536, 65536))

	for _, test := range []struct {
		name        string
		mount       *runtime.Mount
		expectInfo  *snapshots.Info
		expectError bool
	}{
		{
			name: "with user namespace mappings",
			mount: &runtime.Mount{
				ContainerPath: "/test",
				UidMappings:   mappings,
				GidMappings:   mappings,
			},
			expectInfo: expectedOpts,
		},
		{
			name: "without mappings",
			mount: &runtime.Mount{
				ContainerPath: "/test",
			},
		},
		{
			name: "with empty mappings",
			mount: &runtime.Mount{
				ContainerPath: "/test",
				UidMappings:   []*runtime.IDMapping{},
				GidMappings:   []*runtime.IDMapping{},
			},
		},
		{
			name: "with only UID mappings",
			mount: &runtime.Mount{
				ContainerPath: "/test",
				UidMappings:   mappings,
			},
		},
		{
			name: "with only GID mappings",
			mount: &runtime.Mount{
				ContainerPath: "/test",
				GidMappings:   mappings,
			},
		},
		{
			name: "with multiple UID mapping lines",
			mount: &runtime.Mount{
				ContainerPath: "/test",
				UidMappings: []*runtime.IDMapping{
					{
						ContainerId: 0,
						HostId:      65536,
						Length:      65536,
					},
					{
						ContainerId: 65536,
						HostId:      131072,
						Length:      65536,
					},
				},
				GidMappings: mappings,
			},
			expectError: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := &criService{}

			opts, err := c.getImageVolumeSnapshotOpts(ctx, test.mount)

			if test.expectError {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)

			gotInfo := optsToInfo(t, opts...)
			if test.expectInfo == nil {
				assert.Nil(t, gotInfo)
			} else {
				require.NotNil(t, gotInfo)
				assert.Equal(t, test.expectInfo.Labels, gotInfo.Labels)
			}

			if test.mount.UidMappings != nil {
				assert.NotNil(t, test.mount.UidMappings, "UidMappings should NOT be cleared by getImageVolumeSnapshotOpts")
			}
			if test.mount.GidMappings != nil {
				assert.NotNil(t, test.mount.GidMappings, "GidMappings should NOT be cleared by getImageVolumeSnapshotOpts")
			}
		})
	}
}

func optsToInfo(t *testing.T, opts ...snapshots.Opt) *snapshots.Info {
	t.Helper()
	if len(opts) == 0 {
		return nil
	}
	var info snapshots.Info
	for _, opt := range opts {
		require.NoError(t, opt(&info))
	}
	return &info
}
