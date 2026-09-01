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

package rootfs

import (
	"context"
	"testing"

	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/core/snapshots"
	snpkg "github.com/containerd/containerd/v2/pkg/snapshotters"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplyLayerValidatesExistingDmverityMaterialization(t *testing.T) {
	signed := map[string]string{
		snpkg.DmverityMaterializationVersionLabel:         snpkg.DmverityMaterializationVersion,
		snpkg.DmverityMaterializationStateLabel:           snpkg.DmverityMaterializationStateSigned,
		snpkg.DmverityMaterializationRootHashLabel:        digest.FromString("root").Hex(),
		snpkg.DmverityMaterializationSignatureDigestLabel: digest.FromString("signature").String(),
	}
	plain := map[string]string{
		snpkg.DmverityMaterializationVersionLabel: snpkg.DmverityMaterializationVersion,
		snpkg.DmverityMaterializationStateLabel:   snpkg.DmverityMaterializationStatePlain,
	}
	layer := Layer{Diff: descriptor(digest.FromString("layer"))}

	t.Run("matching signed snapshot is reused", func(t *testing.T) {
		snapshotter := &statOnlySnapshotter{info: snapshots.Info{Kind: snapshots.KindCommitted, Labels: signed}}
		applied, err := ApplyLayerWithOpts(
			context.Background(),
			layer,
			nil,
			snapshotter,
			nil,
			[]snapshots.Opt{snapshots.WithLabels(signed)},
			nil,
		)
		require.NoError(t, err)
		assert.False(t, applied)
	})

	t.Run("plain snapshot cannot satisfy signed request", func(t *testing.T) {
		snapshotter := &statOnlySnapshotter{info: snapshots.Info{Kind: snapshots.KindCommitted, Labels: plain}}
		_, err := ApplyLayerWithOpts(
			context.Background(),
			layer,
			nil,
			snapshotter,
			nil,
			[]snapshots.Opt{snapshots.WithLabels(signed)},
			nil,
		)
		require.ErrorContains(t, err, "does not satisfy dm-verity policy")
	})

	t.Run("legacy snapshot remains valid for plain request", func(t *testing.T) {
		snapshotter := &statOnlySnapshotter{info: snapshots.Info{Kind: snapshots.KindCommitted}}
		applied, err := ApplyLayerWithOpts(
			context.Background(),
			layer,
			nil,
			snapshotter,
			nil,
			[]snapshots.Opt{snapshots.WithLabels(plain)},
			nil,
		)
		require.NoError(t, err)
		assert.False(t, applied)
	})
}

func descriptor(dgst digest.Digest) ocispec.Descriptor {
	return ocispec.Descriptor{Digest: dgst}
}

type statOnlySnapshotter struct {
	info snapshots.Info
	err  error
}

func (s *statOnlySnapshotter) Stat(context.Context, string) (snapshots.Info, error) {
	return s.info, s.err
}

func (*statOnlySnapshotter) Update(context.Context, snapshots.Info, ...string) (snapshots.Info, error) {
	panic("unexpected Update")
}

func (*statOnlySnapshotter) Usage(context.Context, string) (snapshots.Usage, error) {
	panic("unexpected Usage")
}

func (*statOnlySnapshotter) Mounts(context.Context, string) ([]mount.Mount, error) {
	panic("unexpected Mounts")
}

func (*statOnlySnapshotter) Prepare(context.Context, string, string, ...snapshots.Opt) ([]mount.Mount, error) {
	panic("unexpected Prepare")
}

func (*statOnlySnapshotter) View(context.Context, string, string, ...snapshots.Opt) ([]mount.Mount, error) {
	panic("unexpected View")
}

func (*statOnlySnapshotter) Commit(context.Context, string, string, ...snapshots.Opt) error {
	panic("unexpected Commit")
}

func (*statOnlySnapshotter) Remove(context.Context, string) error {
	panic("unexpected Remove")
}

func (*statOnlySnapshotter) Walk(context.Context, snapshots.WalkFunc, ...string) error {
	panic("unexpected Walk")
}

func (*statOnlySnapshotter) Close() error {
	return nil
}
