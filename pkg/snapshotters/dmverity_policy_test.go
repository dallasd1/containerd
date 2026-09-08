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
	"encoding/base64"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDmveritySnapshotLabels(t *testing.T) {
	layer := func(annotations map[string]string) ocispec.Descriptor {
		return ocispec.Descriptor{
			Digest:      digest.FromString("layer"),
			Annotations: annotations,
		}
	}

	plain, err := DmveritySnapshotLabels(layer(nil), false)
	require.NoError(t, err)
	assert.Equal(t, DmverityMaterializationStatePlain, plain[DmverityMaterializationStateLabel])

	_, err = DmveritySnapshotLabels(layer(nil), true)
	require.ErrorContains(t, err, "signature required")

	signature := []byte("signature")
	signed, err := DmveritySnapshotLabels(layer(map[string]string{
		TargetLayerSignatureLabel: base64.StdEncoding.EncodeToString(signature),
		TargetLayerRootHashLabel:  digest.FromString("root").Hex(),
	}), false)
	require.NoError(t, err)
	assert.Equal(t, DmverityMaterializationStateSigned, signed[DmverityMaterializationStateLabel])
	assert.Equal(t, digest.FromBytes(signature).String(), signed[DmverityMaterializationSignatureDigestLabel])

	_, err = DmveritySnapshotLabels(layer(map[string]string{
		TargetLayerRootHashLabel: digest.FromString("root").Hex(),
	}), false)
	require.ErrorContains(t, err, "without a signature")

	_, err = DmveritySnapshotLabels(layer(map[string]string{
		TargetLayerSignatureLabel: "not-base64",
		TargetLayerRootHashLabel:  digest.FromString("root").Hex(),
	}), false)
	require.ErrorContains(t, err, "invalid dm-verity signature encoding")

	_, err = DmveritySnapshotLabels(layer(map[string]string{
		TargetLayerSignatureLabel: base64.StdEncoding.EncodeToString(signature),
		TargetLayerRootHashLabel:  "abcd",
	}), false)
	require.ErrorContains(t, err, "invalid SHA-256 dm-verity root hash")
}

func TestValidateDmveritySnapshot(t *testing.T) {
	plain := map[string]string{
		DmverityMaterializationVersionLabel: DmverityMaterializationVersion,
		DmverityMaterializationStateLabel:   DmverityMaterializationStatePlain,
	}
	signed := map[string]string{
		DmverityMaterializationVersionLabel:         DmverityMaterializationVersion,
		DmverityMaterializationStateLabel:           DmverityMaterializationStateSigned,
		DmverityMaterializationRootHashLabel:        digest.FromString("root").Hex(),
		DmverityMaterializationSignatureDigestLabel: digest.FromString("signature").String(),
	}

	assert.NoError(t, ValidateDmveritySnapshot(nil, plain))
	assert.NoError(t, ValidateDmveritySnapshot(plain, plain))
	assert.NoError(t, ValidateDmveritySnapshot(signed, plain))
	assert.NoError(t, ValidateDmveritySnapshot(signed, signed))

	require.ErrorContains(t, ValidateDmveritySnapshot(nil, signed), "unsupported dm-verity materialization version")
	require.ErrorContains(t, ValidateDmveritySnapshot(plain, signed), "not signed")

	different := make(map[string]string, len(signed))
	for key, value := range signed {
		different[key] = value
	}
	different[DmverityMaterializationRootHashLabel] = digest.FromString("other").Hex()
	require.ErrorContains(t, ValidateDmveritySnapshot(different, signed), "does not match required root hash")
}
