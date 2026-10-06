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

package client

import (
	"context"
	"encoding/json"
	"testing"

	introspectionapi "github.com/containerd/containerd/api/services/introspection/v1"
	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/introspection"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeImage implements the subset of Image used by container option tests:
// Config returns a descriptor with the config blob inlined in Data, so the
// content store is never consulted.
type fakeImage struct {
	Image
	config  ocispec.Descriptor
	diffIDs []digest.Digest
}

func (i fakeImage) Config(context.Context) (ocispec.Descriptor, error) {
	return i.config, nil
}

func (i fakeImage) ContentStore() content.Store {
	return nil
}

func (i fakeImage) RootFS(context.Context) ([]digest.Digest, error) {
	return i.diffIDs, nil
}

func (i fakeImage) Name() string {
	return "test-image"
}

type parentResolverSnapshotter struct {
	snapshots.Snapshotter
	parent string
}

func (s *parentResolverSnapshotter) Prepare(_ context.Context, _ string, parent string, _ ...snapshots.Opt) ([]mount.Mount, error) {
	s.parent = parent
	return nil, nil
}

type parentResolverIntrospection struct {
	introspection.Service
}

func (parentResolverIntrospection) Plugins(context.Context, ...string) (*introspectionapi.PluginsResponse, error) {
	return &introspectionapi.PluginsResponse{Plugins: []*introspectionapi.Plugin{{}}}, nil
}

func TestWithNewSnapshotParentResolver(t *testing.T) {
	image := fakeImage{diffIDs: []digest.Digest{digest.FromString("base diff"), digest.FromString("layer diff")}}
	snapshotter := &parentResolverSnapshotter{}
	client, err := New("", WithServices(
		WithSnapshotters(map[string]snapshots.Snapshotter{"test": snapshotter}),
		WithIntrospectionService(parentResolverIntrospection{}),
	))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })

	c := &containers.Container{Snapshotter: "test"}
	err = WithNewSnapshotParentResolver("container-id", image, func(_ context.Context, parent string) (string, error) {
		require.Equal(t, identity.ChainID(image.diffIDs).String(), parent)
		return "selected-parent", nil
	})(t.Context(), client, c)
	require.NoError(t, err)
	require.Equal(t, "selected-parent", snapshotter.parent)
	require.Equal(t, "container-id", c.SnapshotKey)
	require.Equal(t, image.Name(), c.Image)
}

func TestWithImageConfigLabels(t *testing.T) {
	blob, err := json.Marshal(ocispec.Image{
		Config: ocispec.ImageConfig{
			Labels: map[string]string{
				"foo":                          "bar",
				"containerd.io/restart.policy": "always",
				"io.cri-containerd.kind":       "sandbox",
			},
		},
	})
	require.NoError(t, err)

	img := fakeImage{
		config: ocispec.Descriptor{
			MediaType: ocispec.MediaTypeImageConfig,
			Digest:    digest.FromBytes(blob),
			Size:      int64(len(blob)),
			Data:      blob,
		},
	}

	var c containers.Container
	require.NoError(t, WithImageConfigLabels(img)(t.Context(), nil, &c))

	// labels in the namespaces reserved for containerd and the CRI plugin
	// are not copied from the image config
	assert.Equal(t, map[string]string{"foo": "bar"}, c.Labels)
}
