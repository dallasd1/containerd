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

package images

import (
	"context"
	"testing"

	introspectionapi "github.com/containerd/containerd/api/services/introspection/v1"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/content"
	coreimages "github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/images/imagetest"
	"github.com/containerd/containerd/v2/core/introspection"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	snpkg "github.com/containerd/containerd/v2/pkg/snapshotters"
	"github.com/containerd/containerd/v2/plugins"
	"github.com/containerd/platforms"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

type dmverityReadinessIntrospection struct {
	introspection.Service
}

func (dmverityReadinessIntrospection) Plugins(context.Context, ...string) (*introspectionapi.PluginsResponse, error) {
	return &introspectionapi.PluginsResponse{Plugins: []*introspectionapi.Plugin{{
		Type:         string(plugins.SnapshotPlugin),
		ID:           "erofs",
		Capabilities: []string{plugins.CapabilityDmverityReferrers},
	}}}, nil
}

type dmverityReadinessSnapshotter struct {
	snapshots.Snapshotter
	keys []string
}

func (s *dmverityReadinessSnapshotter) Stat(_ context.Context, key string) (snapshots.Info, error) {
	s.keys = append(s.keys, key)
	return snapshots.Info{}, nil
}

func (s *dmverityReadinessSnapshotter) Prepare(context.Context, string, string, ...snapshots.Opt) ([]mount.Mount, error) {
	return nil, nil
}

func TestImageReadinessUsesSelectedSnapshotLane(t *testing.T) {
	for _, signed := range []bool{false, true} {
		name := "unsigned"
		if signed {
			name = "signed"
		}
		t.Run(name, func(t *testing.T) {
			ctx := namespaces.WithNamespace(context.Background(), "test")
			store := imagetest.NewContentStore(ctx, t)
			diffID := digest.FromString("layer diff")
			config := store.JSONObject(ocispec.MediaTypeImageConfig, ocispec.Image{
				RootFS: ocispec.RootFS{Type: "layers", DiffIDs: []digest.Digest{diffID}},
			})
			layer := store.RandomBlob(ocispec.MediaTypeImageLayer, 16)
			manifest := store.Manifest(config, layer)
			if signed {
				_, err := store.Update(ctx, content.Info{
					Digest: manifest.Descriptor.Digest,
					Labels: map[string]string{
						"containerd.io/gc.ref.content.dmverity": digest.FromString("referrer").String(),
					},
				}, "labels.containerd.io/gc.ref.content.dmverity")
				require.NoError(t, err)
			}

			snapshotter := &dmverityReadinessSnapshotter{}
			client, err := containerd.New("", containerd.WithServices(
				containerd.WithContentStore(store.Store),
				containerd.WithSnapshotters(map[string]snapshots.Snapshotter{"erofs": snapshotter}),
				containerd.WithIntrospectionService(dmverityReadinessIntrospection{}),
			))
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, client.Close()) })
			image := containerd.NewImageWithPlatform(client, coreimages.Image{
				Name:   "test-image",
				Target: manifest.Descriptor,
			}, platforms.Default())
			service := &CRIImageService{client: client}

			ok, err := service.imageIsUnpacked(ctx, image, "erofs")
			require.NoError(t, err)
			require.True(t, ok)
			require.Len(t, snapshotter.keys, 1)
			expected := identity.ChainID([]digest.Digest{diffID}).String()
			if signed {
				expected, err = snpkg.DmveritySnapshotKey(expected)
				require.NoError(t, err)
			}
			require.Equal(t, expected, snapshotter.keys[0])
		})
	}
}
