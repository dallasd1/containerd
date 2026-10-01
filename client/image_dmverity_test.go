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

	"github.com/containerd/containerd/v2/pkg/snapshotters"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

func TestGetLayersStripsUnvalidatedDmverityTarget(t *testing.T) {
	layer := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageLayerGzip,
		Digest:    digest.FromString("layer"),
		Annotations: map[string]string{
			snapshotters.TargetLayerDmverityLabel: `{"rootHash":"attacker"}`,
			"other":                               "kept",
		},
	}
	img := &image{diffIDs: []digest.Digest{digest.FromString("diff")}}

	layers, err := img.getLayers(t.Context(), ocispec.Manifest{Layers: []ocispec.Descriptor{layer}})
	require.NoError(t, err)
	require.Len(t, layers, 1)
	require.Equal(t, map[string]string{"other": "kept"}, layers[0].Blob.Annotations)
	require.Contains(t, layer.Annotations, snapshotters.TargetLayerDmverityLabel, "manifest descriptor must not be mutated")
}

func TestImageSnapshotKeyWithoutDmveritySelectionLabels(t *testing.T) {
	diffIDs := []digest.Digest{
		digest.FromString("first diff"),
		digest.FromString("second diff"),
	}
	img := &image{diffIDs: diffIDs}

	key, err := (&Client{}).imageSnapshotKey(t.Context(), img, "missing")
	require.NoError(t, err)
	require.Equal(t, identity.ChainID(diffIDs).String(), key)
}
