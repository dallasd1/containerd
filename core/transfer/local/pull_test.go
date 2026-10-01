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
	"testing"

	"github.com/containerd/platforms"
	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/require"

	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/transfer"
	"github.com/containerd/containerd/v2/core/unpack"
	"github.com/containerd/containerd/v2/defaults"
	snpkg "github.com/containerd/containerd/v2/pkg/snapshotters"
)

func TestGetSupportedPlatform(t *testing.T) {
	supportedPlatforms := []unpack.Platform{
		{
			Platform:       platforms.OnlyStrict(platforms.MustParse("linux/amd64")),
			SnapshotterKey: "native",
		},
		{
			Platform:       platforms.OnlyStrict(platforms.MustParse("linux/amd64")),
			SnapshotterKey: "devmapper",
		},
		{
			Platform:       platforms.OnlyStrict(platforms.MustParse("linux/arm64")),
			SnapshotterKey: "native",
		},
		{
			Platform:       platforms.OnlyStrict(platforms.MustParse("linux/arm")),
			SnapshotterKey: "native",
		},
		{
			Platform:       platforms.DefaultStrict(),
			SnapshotterKey: defaults.DefaultSnapshotter,
		},
	}

	for _, testCase := range []struct {
		// Name is the name of the test
		Name string

		// Input
		UnpackConfig       transfer.UnpackConfiguration
		SupportedPlatforms []unpack.Platform

		// Expected
		Match            bool
		ExpectedPlatform transfer.UnpackConfiguration
	}{
		{
			Name: "No match on input linux/arm64 and devmapper snapshotter",
			UnpackConfig: transfer.UnpackConfiguration{
				Platform:    platforms.MustParse("linux/arm64"),
				Snapshotter: "devmapper",
			},
			SupportedPlatforms: supportedPlatforms,
			Match:              false,
			ExpectedPlatform:   transfer.UnpackConfiguration{},
		},
		{
			Name: "No match on input linux/386 and native snapshotter",
			UnpackConfig: transfer.UnpackConfiguration{
				Platform:    platforms.MustParse("linux/386"),
				Snapshotter: "native",
			},
			SupportedPlatforms: supportedPlatforms,
			Match:              false,
			ExpectedPlatform:   transfer.UnpackConfiguration{},
		},
		{
			Name: "Match linux/amd64 and native snapshotter",
			UnpackConfig: transfer.UnpackConfiguration{
				Platform:    platforms.MustParse("linux/amd64"),
				Snapshotter: "native",
			},
			SupportedPlatforms: supportedPlatforms,
			Match:              true,
			ExpectedPlatform: transfer.UnpackConfiguration{
				Platform:    platforms.MustParse("linux/amd64"),
				Snapshotter: "native",
			},
		},
		{
			Name: "Match linux/arm64 and native snapshotter",
			UnpackConfig: transfer.UnpackConfiguration{
				Platform:    platforms.MustParse("linux/arm64"),
				Snapshotter: "native",
			},
			SupportedPlatforms: supportedPlatforms,
			Match:              true,
			ExpectedPlatform: transfer.UnpackConfiguration{
				Platform:    platforms.MustParse("linux/arm64"),
				Snapshotter: "native",
			},
		},
		{
			Name: "Default platform input only match with defaultSnapshotter",
			UnpackConfig: transfer.UnpackConfiguration{
				Platform: platforms.DefaultSpec(),
			},
			SupportedPlatforms: supportedPlatforms,
			Match:              true,
			ExpectedPlatform: transfer.UnpackConfiguration{
				Platform:    platforms.DefaultSpec(),
				Snapshotter: defaults.DefaultSnapshotter,
			},
		},
	} {
		t.Run(testCase.Name, func(t *testing.T) {
			m, sp := getSupportedPlatform(t.Context(), testCase.UnpackConfig, testCase.SupportedPlatforms)

			// Match result should match expected
			if m != testCase.Match {
				t.Fatalf("Expect match result %v, but got %v", testCase.Match, m)
			}

			// If match result is false, the Platform should be nil too
			if !m && sp.Platform != nil {
				t.Fatalf("Expect nil Platform when we don't have a match")
			}

			// Snapshotter should match, empty string can be compared too
			if sp.SnapshotterKey != testCase.ExpectedPlatform.Snapshotter {
				t.Fatalf("Expect SnapshotterKey %v, but got %v", testCase.ExpectedPlatform.Snapshotter, sp.SnapshotterKey)
			}

			// If the matched Platform is not nil, it should match the expected Platform
			if sp.Platform != nil && !sp.Platform.Match(testCase.ExpectedPlatform.Platform) {
				t.Fatalf("Expect Platform %v doesn't match", testCase.ExpectedPlatform.Platform)
			}
			// If the ExectedPlatform is not empty, the matched Platform should not be nil either
			if sp.Platform == nil && testCase.ExpectedPlatform.Platform.OS != "" {
				t.Fatalf("Expect Platform %v doesn't match", testCase.ExpectedPlatform.Platform)
			}
		})
	}

}

func TestDmveritySelectionStoreKeepsSelections(t *testing.T) {
	manifest := digest.FromString("manifest")
	referrer := digest.FromString("referrer")
	selections := &snpkg.DmveritySelections{}
	selections.Record(manifest, referrer)
	selectionKey := "containerd.io/gc.ref.content.dmverity-referrer/" + manifest.Encoded()

	recorder := &recordingImageStore{}
	s := dmveritySelectionStore{Store: recorder, selections: selections}
	img := images.Image{Name: "example.com/test:tag", Labels: map[string]string{"user": "value"}}

	_, err := s.Create(t.Context(), img)
	require.NoError(t, err)
	// The transfer image storer replaces the whole record on re-pull.
	_, err = s.Update(t.Context(), img)
	require.NoError(t, err)

	require.Len(t, recorder.written, 2)
	for _, written := range recorder.written {
		require.Equal(t, referrer.String(), written.Labels[selectionKey])
		require.Equal(t, "value", written.Labels["user"])
	}
	require.NotContains(t, img.Labels, selectionKey, "caller labels must not be mutated")
}

type recordingImageStore struct {
	images.Store
	written []images.Image
}

func (s *recordingImageStore) Create(_ context.Context, image images.Image) (images.Image, error) {
	s.written = append(s.written, image)
	return image, nil
}

func (s *recordingImageStore) Update(_ context.Context, image images.Image, _ ...string) (images.Image, error) {
	s.written = append(s.written, image)
	return image, nil
}
