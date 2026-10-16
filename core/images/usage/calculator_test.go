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
	"github.com/containerd/log/logtest"
	"github.com/containerd/platforms"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

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

type qualifiedReferenceSnapshotter struct {
	snapshots.Snapshotter
	key string
}

func (s *qualifiedReferenceSnapshotter) Usage(_ context.Context, key string) (snapshots.Usage, error) {
	s.key = key
	return snapshots.Usage{Size: 10}, nil
}

func TestUsageCalculationUsesQualifiedSnapshotReference(t *testing.T) {
	ctx := context.Background()
	cs := imagetest.NewContentStore(ctx, t)
	target := imagetest.SimpleManifest(50)(cs)
	key := "dmverity-0123456789"
	_, err := cs.Store.Update(ctx, content.Info{
		Digest: target.Children[0].Descriptor.Digest,
		Labels: map[string]string{
			"containerd.io/gc.ref.snapshot.erofs/dmverity": key,
		},
	}, "labels.containerd.io/gc.ref.snapshot.erofs/dmverity")
	if err != nil {
		t.Fatal(err)
	}

	snapshotter := &qualifiedReferenceSnapshotter{}
	img := images.Image{Name: "qualified", Target: target.Descriptor}
	_, err = CalculateImageUsage(ctx, img, cs, WithSnapshotters(func(name string) snapshots.Snapshotter {
		if name != "erofs" {
			t.Errorf("snapshotter lookup received %q, want erofs", name)
		}
		return snapshotter
	}))
	if err != nil {
		t.Fatal(err)
	}
	if snapshotter.key != key {
		t.Fatalf("snapshot usage used key %q, want %q", snapshotter.key, key)
	}
}
