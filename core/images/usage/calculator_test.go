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

package usage

import (
	"context"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/images/imagetest"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/errdefs"
	"github.com/containerd/log/logtest"
	"github.com/containerd/platforms"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

func TestSnapshotUsageQualifiedReferences(t *testing.T) {
	ctx := t.Context()
	cs := imagetest.NewContentStore(ctx, t)
	target := imagetest.SimpleManifest(50)(cs)
	_, err := cs.Update(ctx, content.Info{Digest: target.Children[0].Descriptor.Digest, Labels: map[string]string{
		"containerd.io/gc.ref.snapshot.erofs":          "plain",
		"containerd.io/gc.ref.snapshot.erofs/signed-a": "signed-a",
		"containerd.io/gc.ref.snapshot.erofs/signed-b": "signed-b",
	}}, "labels")
	require.NoError(t, err)
	sn := snapshotUsageTestSnapshotter{sizes: map[string]int64{"plain": 5, "signed-a": 7, "signed-b": 11}}
	usage, err := CalculateImageUsage(ctx, images.Image{Target: target.Descriptor}, cs,
		WithManifestUsage(), WithSnapshotters(func(name string) snapshots.Snapshotter {
			require.Equal(t, "erofs", name)
			return sn
		}))
	require.NoError(t, err)
	require.Equal(t, imagetest.SizeOfManifest(target)+23, usage)
}

type snapshotUsageTestSnapshotter struct {
	snapshots.Snapshotter
	sizes map[string]int64
}

func (s snapshotUsageTestSnapshotter) Usage(_ context.Context, key string) (snapshots.Usage, error) {
	size, ok := s.sizes[key]
	if !ok {
		return snapshots.Usage{}, errdefs.ErrNotFound
	}
	return snapshots.Usage{Size: size}, nil
}

func TestUsageCalculation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		target   imagetest.ContentCreator
		expected imagetest.ContentSizeCalculator
		opts     []Opt
	}{
		{
			name:     "simple",
			target:   imagetest.SimpleManifest(50),
			expected: imagetest.SizeOfManifest,
			opts:     []Opt{WithManifestUsage()},
		},
		{
			name:     "simpleIndex",
			target:   imagetest.SimpleIndex(5, 50),
			expected: imagetest.SizeOfContent,
		},
		{
			name:     "stripLayersManifestOnly",
			target:   imagetest.StripLayers(imagetest.SimpleIndex(3, 51)),
			expected: imagetest.SizeOfManifest,
			opts:     []Opt{WithManifestUsage()},
		},
		{
			name:     "stripLayers",
			target:   imagetest.StripLayers(imagetest.SimpleIndex(4, 60)),
			expected: imagetest.SizeOfContent,
		},
		{
			name: "manifestlimit",
			target: func(tc imagetest.ContentStore) imagetest.Content {
				return tc.Index(
					imagetest.AddPlatform(imagetest.SimpleManifest(5)(tc), ocispec.Platform{Architecture: "amd64", OS: "linux"}),
					imagetest.AddPlatform(imagetest.SimpleManifest(10)(tc), ocispec.Platform{Architecture: "arm64", OS: "linux"}),
				)
			},
			expected: func(t imagetest.Content) int64 { return imagetest.SizeOfManifest(imagetest.LimitChildren(t, 1)) },
			opts: []Opt{
				WithManifestLimit(platforms.Only(ocispec.Platform{Architecture: "amd64", OS: "linux"}), 1),
				WithManifestUsage(),
			},
		},
		// TODO: Add test with snapshot
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := logtest.WithT(context.Background(), t)

			cs := imagetest.NewContentStore(ctx, t)
			content := tc.target(cs)
			img := images.Image{
				Name:   tc.name,
				Target: content.Descriptor,
				Labels: content.Labels,
			}

			usage, err := CalculateImageUsage(ctx, img, cs, tc.opts...)
			if err != nil {
				t.Fatal(err)
			}

			expected := tc.expected(content)

			if expected != usage {
				t.Fatalf("unexpected usage: %d, expected %d", usage, expected)
			}
		})
	}

}
