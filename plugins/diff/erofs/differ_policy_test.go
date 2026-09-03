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

package erofs

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	snpkg "github.com/containerd/containerd/v2/pkg/snapshotters"
)

func TestDmverityForLayer(t *testing.T) {
	layer := func(annotations map[string]string) ocispec.Descriptor {
		return ocispec.Descriptor{
			Digest:      digest.FromString("layer"),
			Annotations: annotations,
		}
	}
	signed := map[string]string{
		snpkg.TargetLayerSignatureLabel: base64.StdEncoding.EncodeToString([]byte("signature")),
		snpkg.TargetLayerRootHashLabel:  digest.FromString("root").Hex(),
	}

	t.Run("disabled ignores annotations", func(t *testing.T) {
		use, err := (erofsDiff{}).dmverityForLayer(layer(signed))
		require.NoError(t, err)
		assert.False(t, use)
	})

	t.Run("unsigned layer remains plain erofs", func(t *testing.T) {
		use, err := (erofsDiff{enableDmverity: true}).dmverityForLayer(layer(nil))
		require.NoError(t, err)
		assert.False(t, use)
	})

	t.Run("required signature fails closed", func(t *testing.T) {
		_, err := (erofsDiff{
			enableDmverity:    true,
			requireSignatures: true,
		}).dmverityForLayer(layer(nil))
		require.ErrorContains(t, err, "signature required")
	})

	t.Run("signed layer uses dm-verity", func(t *testing.T) {
		use, err := (erofsDiff{enableDmverity: true}).dmverityForLayer(layer(signed))
		require.NoError(t, err)
		assert.True(t, use)
	})

	t.Run("signature requires root hash", func(t *testing.T) {
		_, err := (erofsDiff{enableDmverity: true}).dmverityForLayer(layer(map[string]string{
			snpkg.TargetLayerSignatureLabel: base64.StdEncoding.EncodeToString([]byte("signature")),
		}))
		require.ErrorContains(t, err, "missing expected root hash")
	})

	t.Run("metadata without signature fails closed", func(t *testing.T) {
		_, err := (erofsDiff{enableDmverity: true}).dmverityForLayer(layer(map[string]string{
			snpkg.TargetLayerRootHashLabel: digest.FromString("root").Hex(),
		}))
		require.ErrorContains(t, err, "metadata without a signature")
	})

	t.Run("precomputed artifacts must be paired", func(t *testing.T) {
		_, err := (erofsDiff{enableDmverity: true}).dmverityForLayer(layer(map[string]string{
			snpkg.TargetLayerSignatureLabel:               base64.StdEncoding.EncodeToString([]byte("signature")),
			snpkg.TargetLayerRootHashLabel:                digest.FromString("root").Hex(),
			snpkg.TargetLayerEROFSMetadataDescriptorLabel: "{}",
		}))
		require.ErrorContains(t, err, "incomplete precomputed dm-verity artifacts")
	})
}
