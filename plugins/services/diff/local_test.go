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

package diff

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/pkg/snapshotters"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateDmverityApply(t *testing.T) {
	layer := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(layer, ".erofslayer"), nil, 0o600))
	erofsMounts := []mount.Mount{{Type: "bind", Source: filepath.Join(layer, "layer.erofs")}}
	signed := ocispec.Descriptor{
		Annotations: map[string]string{
			snapshotters.TargetLayerSignatureLabel: "sha256:signature",
		},
	}

	tests := []struct {
		name      string
		service   local
		mounts    []mount.Mount
		wantError bool
	}{
		{
			name: "configured without capable ordered differ",
			service: local{
				orderedNames:       []string{"walking"},
				dmverityConfigured: true,
			},
			mounts:    erofsMounts,
			wantError: true,
		},
		{
			name:      "feature disabled ignores annotations",
			service:   local{orderedNames: []string{"walking"}},
			mounts:    erofsMounts,
			wantError: false,
		},
		{
			name: "capable differ is not first",
			service: local{
				orderedNames:       []string{"walking", "erofs"},
				dmverityCapable:    []string{"erofs"},
				dmverityConfigured: true,
			},
			mounts:    erofsMounts,
			wantError: true,
		},
		{
			name: "capable differ is first",
			service: local{
				orderedNames:       []string{"erofs", "walking"},
				dmverityCapable:    []string{"erofs"},
				dmverityConfigured: true,
			},
			mounts: erofsMounts,
		},
		{
			name:      "overlay mount is unaffected",
			service:   local{orderedNames: []string{"walking"}},
			mounts:    []mount.Mount{{Type: "overlay", Options: []string{"upperdir=" + t.TempDir()}}},
			wantError: false,
		},
		{
			name:      "empty mounts are unaffected",
			service:   local{orderedNames: []string{"walking"}},
			mounts:    nil,
			wantError: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.service.validateDmverityApply(signed, test.mounts)
			if test.wantError {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}
