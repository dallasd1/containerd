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
	"sort"
	"testing"

	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/pkg/oci"
	runtimespec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
)

func TestOrderedMounts(t *testing.T) {
	mounts := []*runtime.Mount{
		{ContainerPath: "/a/b/c"},
		{ContainerPath: "/a/b"},
		{ContainerPath: "/a/b/c/d"},
		{ContainerPath: "/a"},
		{ContainerPath: "/b"},
		{ContainerPath: "/b/c"},
	}
	expected := []*runtime.Mount{
		{ContainerPath: "/a"},
		{ContainerPath: "/b"},
		{ContainerPath: "/a/b"},
		{ContainerPath: "/b/c"},
		{ContainerPath: "/a/b/c"},
		{ContainerPath: "/a/b/c/d"},
	}
	sort.Stable(orderedMounts(mounts))
	assert.Equal(t, expected, mounts)
}

func TestWithCachedAdditionalGIDs(t *testing.T) {
	snapshotter := &committedSnapshotter{}
	client := snapshotClient{snapshotter: snapshotter}
	cache := &recordingSupplementalGroupsCache{gids: []uint32{11111}}
	container := &containers.Container{
		Snapshotter: "erofs",
		SnapshotKey: "active-container",
	}
	spec := &runtimespec.Spec{
		Process: &runtimespec.Process{
			User: runtimespec.User{
				UID:            1000,
				GID:            2000,
				AdditionalGids: []uint32{3333},
			},
		},
	}

	err := WithCachedAdditionalGIDs(cache, "chain-id", "")(
		context.Background(),
		client,
		container,
		spec,
	)
	require.NoError(t, err)
	assert.Equal(t, []uint32{2000, 3333, 11111}, spec.Process.User.AdditionalGids)
	require.Len(t, cache.keys, 1)
	assert.Equal(t, SupplementalGroupsCacheKey{
		Snapshotter: "erofs",
		ChainID:     "chain-id",
		User:        "1000",
		PrimaryGID:  2000,
	}, cache.keys[0])

	spec.Process.User.GID = 4000
	spec.Process.User.AdditionalGids = []uint32{5555}
	err = WithCachedAdditionalGIDs(cache, "chain-id", "")(
		context.Background(),
		client,
		container,
		spec,
	)
	require.NoError(t, err)
	assert.Equal(t, []uint32{4000, 5555, 11111}, spec.Process.User.AdditionalGids)
	assert.Equal(t, uint32(4000), cache.keys[1].PrimaryGID)
	assert.NotEqual(t, cache.keys[0], cache.keys[1], "different primary groups need independent image-group results")

	spec.Process.User.UID = 0
	spec.Process.User.GID = 0
	spec.Process.User.AdditionalGids = nil
	err = WithCachedAdditionalGIDs(cache, "chain-id", "alice")(
		context.Background(),
		client,
		container,
		spec,
	)
	require.NoError(t, err)
	assert.Equal(t, "alice", cache.keys[2].User)
	assert.Equal(t, uint32(0), cache.keys[2].PrimaryGID)
}

type recordingSupplementalGroupsCache struct {
	keys []SupplementalGroupsCacheKey
	gids []uint32
}

func (c *recordingSupplementalGroupsCache) Resolve(
	_ context.Context,
	key SupplementalGroupsCacheKey,
	_ func(context.Context) ([]uint32, error),
) ([]uint32, error) {
	c.keys = append(c.keys, key)
	return append([]uint32(nil), c.gids...), nil
}

type snapshotClient struct {
	snapshotter snapshots.Snapshotter
}

func (c snapshotClient) SnapshotService(string) snapshots.Snapshotter {
	return c.snapshotter
}

type committedSnapshotter struct{}

func (*committedSnapshotter) Stat(context.Context, string) (snapshots.Info, error) {
	return snapshots.Info{Kind: snapshots.KindCommitted}, nil
}

func (*committedSnapshotter) Update(context.Context, snapshots.Info, ...string) (snapshots.Info, error) {
	panic("unexpected Update")
}

func (*committedSnapshotter) Usage(context.Context, string) (snapshots.Usage, error) {
	panic("unexpected Usage")
}

func (*committedSnapshotter) Mounts(context.Context, string) ([]mount.Mount, error) {
	panic("unexpected Mounts")
}

func (*committedSnapshotter) Prepare(context.Context, string, string, ...snapshots.Opt) ([]mount.Mount, error) {
	panic("unexpected Prepare")
}

func (*committedSnapshotter) View(context.Context, string, string, ...snapshots.Opt) ([]mount.Mount, error) {
	panic("unexpected View")
}

func (*committedSnapshotter) Commit(context.Context, string, string, ...snapshots.Opt) error {
	panic("unexpected Commit")
}

func (*committedSnapshotter) Remove(context.Context, string) error {
	panic("unexpected Remove")
}

func (*committedSnapshotter) Walk(context.Context, snapshots.WalkFunc, ...string) error {
	panic("unexpected Walk")
}

func (*committedSnapshotter) Close() error {
	return nil
}

var _ oci.Client = snapshotClient{}
