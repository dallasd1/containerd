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

package snapshotters

import (
	"context"
	"fmt"
	"maps"
	"strings"
	"testing"

	digest "github.com/opencontainers/go-digest"
	imagespec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestImageLayersLabel(t *testing.T) {
	sampleKey := "sampleKey"
	sampleDigest, err := digest.Parse("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	assert.NoError(t, err)
	sampleMaxSize := 300
	sampleValidate := func(k, v string) error {
		if (len(k) + len(v)) > sampleMaxSize {
			return fmt.Errorf("invalid: %q: %q", k, v)
		}
		return nil
	}

	tests := []struct {
		name      string
		layersNum int
		wantNum   int
	}{
		{
			name:      "valid number of layers",
			layersNum: 2,
			wantNum:   2,
		},
		{
			name:      "many layers",
			layersNum: 5, // hits sampleMaxSize (300 chars).
			wantNum:   4, // layers should be omitted for avoiding invalid label.
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sampleLayers := make([]imagespec.Descriptor, 0, tt.layersNum)
			for i := 0; i < tt.layersNum; i++ {
				sampleLayers = append(sampleLayers, imagespec.Descriptor{
					MediaType: imagespec.MediaTypeImageLayerGzip,
					Digest:    sampleDigest,
				})
			}
			gotS := getLayers(context.Background(), sampleKey, sampleLayers, sampleValidate)
			got := len(strings.Split(gotS, ","))
			assert.Equal(t, tt.wantNum, got)
		})
	}
}

func TestValidateDmveritySnapshotIdentity(t *testing.T) {
	expected := map[string]string{
		dmverityReferrerRootHashLabel:        digest.FromString("root").Encoded(),
		dmverityReferrerSignatureDigestLabel: digest.FromString("signature").String(),
	}
	require.NoError(t, ValidateDmveritySnapshot(expected, expected))
	uppercaseRoot := maps.Clone(expected)
	uppercaseRoot[dmverityReferrerRootHashLabel] = strings.ToUpper(expected[dmverityReferrerRootHashLabel])
	require.NoError(t, ValidateDmveritySnapshot(uppercaseRoot, expected))
	require.Error(t, ValidateDmveritySnapshot(nil, expected))
	require.NoError(t, ValidateDmveritySnapshot(expected, nil))
	for _, label := range []string{dmverityReferrerRootHashLabel, dmverityReferrerSignatureDigestLabel} {
		existing := map[string]string{
			dmverityReferrerRootHashLabel:        expected[dmverityReferrerRootHashLabel],
			dmverityReferrerSignatureDigestLabel: expected[dmverityReferrerSignatureDigestLabel],
		}
		if label == dmverityReferrerRootHashLabel {
			existing[label] = digest.FromString("different root").Encoded()
			require.Error(t, ValidateDmveritySnapshot(existing, expected))
		} else {
			existing[label] = digest.FromString("different signature").String()
			require.NoError(t, ValidateDmveritySnapshot(existing, expected))
		}
		delete(existing, label)
		require.Error(t, ValidateDmveritySnapshot(existing, expected))
	}
	require.NoError(t, ValidateDmveritySnapshot(nil, nil))
	require.Error(t, ValidateDmveritySnapshot(map[string]string{
		dmverityReferrerRootHashLabel:        "malformed",
		dmverityReferrerSignatureDigestLabel: digest.FromString("signature").String(),
	}, nil))
}
