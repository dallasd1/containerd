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
	"testing"

	"github.com/containerd/containerd/v2/plugins"
	"github.com/stretchr/testify/require"
)

func TestEffectiveDmverityCapabilities(t *testing.T) {
	erofs := plugins.CapabilityErofsLayers
	referrers := plugins.CapabilityDmverityReferrers
	required := plugins.CapabilityDmveritySignaturesRequired

	tests := []struct {
		name        string
		snapshotter []string
		differ      []string
		want        []string
		wantError   bool
	}{
		{
			name:        "unsupported snapshotter is unchanged",
			snapshotter: []string{"rebase"},
			want:        []string{"rebase"},
		},
		{
			name:        "optional snapshotter disables dmverity without capable differ",
			snapshotter: []string{"rebase", erofs, referrers},
			want:        []string{"rebase", erofs},
		},
		{
			name:        "matching optional path stays enabled",
			snapshotter: []string{"rebase", erofs, referrers},
			differ:      []string{referrers},
			want:        []string{"rebase", erofs, referrers},
		},
		{
			name:        "required snapshotter rejects incapable differ",
			snapshotter: []string{erofs, referrers, required},
			wantError:   true,
		},
		{
			name:        "required differ rejects optional snapshotter",
			snapshotter: []string{erofs, referrers},
			differ:      []string{referrers, required},
			wantError:   true,
		},
		{
			name:        "required differ rejects disabled erofs snapshotter",
			snapshotter: []string{erofs},
			differ:      []string{referrers, required},
			wantError:   true,
		},
		{
			name:        "required erofs differ permits unrelated snapshotter fallback",
			snapshotter: []string{"overlay"},
			differ:      []string{referrers, required},
			want:        []string{"overlay"},
		},
		{
			name:        "matching required path stays enabled",
			snapshotter: []string{erofs, referrers, required},
			differ:      []string{referrers, required},
			want:        []string{erofs, referrers, required},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := effectiveDmverityCapabilities(test.snapshotter, test.differ)
			if test.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.want, got)
		})
	}
}
