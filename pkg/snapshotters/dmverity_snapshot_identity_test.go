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
	"maps"
	"slices"
	"testing"

	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

func TestDmverityChainIDs(t *testing.T) {
	diffs := []digest.Digest{digest.FromString("base"), digest.FromString("middle"), digest.FromString("top")}
	original := slices.Clone(diffs)
	plain := identity.ChainIDs(slices.Clone(diffs))
	target := DmverityTarget{
		RootHash:  digest.FromString("root").Encoded(),
		Metadata:  ocispec.Descriptor{Digest: digest.FromString("metadata")},
		Tree:      ocispec.Descriptor{Digest: digest.FromString("tree")},
		Signature: ocispec.Descriptor{Digest: digest.FromString("signature")},
	}
	for _, signedLayer := range []int{0, 1} {
		layers := make([]ocispec.Descriptor, len(diffs))
		got, err := DmverityChainIDs(diffs, layers)
		require.NoError(t, err)
		require.Equal(t, plain, got)

		annotation, err := targetAnnotation(&target)
		require.NoError(t, err)
		layers[signedLayer].Annotations = map[string]string{TargetLayerDmverityLabel: annotation}
		signed, err := DmverityChainIDs(diffs, layers)
		require.NoError(t, err)
		require.Equal(t, plain[:signedLayer], signed[:signedLayer])
		for i := signedLayer; i < len(diffs); i++ {
			require.NotEqual(t, plain[i], signed[i])
		}
		require.Equal(t, identity.ChainID([]digest.Digest{signed[1], diffs[2]}), signed[2])
		got, err = DmverityChainIDs(diffs, layers)
		require.NoError(t, err)
		require.Equal(t, signed, got)

		for _, changeRoot := range []bool{true, false} {
			other := target
			if changeRoot {
				other.RootHash = digest.FromString("different salt").Encoded()
			} else {
				other.Signature.Digest = digest.FromString("different signature")
			}
			annotation, err := targetAnnotation(&other)
			require.NoError(t, err)
			layers[signedLayer].Annotations[TargetLayerDmverityLabel] = annotation
			got, err := DmverityChainIDs(diffs, layers)
			require.NoError(t, err)
			for i := signedLayer; i < len(diffs); i++ {
				require.NotEqual(t, signed[i], got[i])
			}
		}
	}
	require.Equal(t, original, diffs)
	_, err := DmverityChainIDs(diffs, nil)
	require.Error(t, err)
	_, err = DmverityChainIDs(diffs[:1], []ocispec.Descriptor{{Annotations: map[string]string{TargetLayerDmverityLabel: "{}"}}})
	require.Error(t, err)
	empty, err := DmverityChainIDs(nil, nil)
	require.NoError(t, err)
	require.Empty(t, empty)
}

func TestValidateDmveritySnapshotIdentity(t *testing.T) {
	expected := map[string]string{
		dmverityMaterializationRootHashLabel:        digest.FromString("root").Encoded(),
		dmverityMaterializationSignatureDigestLabel: digest.FromString("signature").String(),
	}
	require.NoError(t, ValidateDmveritySnapshot(expected, expected))
	require.Error(t, ValidateDmveritySnapshot(nil, expected))
	for _, label := range []string{dmverityMaterializationRootHashLabel, dmverityMaterializationSignatureDigestLabel} {
		existing := map[string]string{
			dmverityMaterializationRootHashLabel:        expected[dmverityMaterializationRootHashLabel],
			dmverityMaterializationSignatureDigestLabel: expected[dmverityMaterializationSignatureDigestLabel],
		}
		existing[label] = "different"
		require.Error(t, ValidateDmveritySnapshot(existing, expected))
		delete(existing, label)
		require.Error(t, ValidateDmveritySnapshot(existing, expected))
	}
	require.NoError(t, ValidateDmveritySnapshot(nil, nil))
}

func TestStripDmveritySnapshotLabels(t *testing.T) {
	for name, labels := range map[string]map[string]string{
		"nil":       nil,
		"unrelated": {"other": "preserved"},
		"signed": {
			dmverityMaterializationRootHashLabel:        "untrusted root",
			dmverityMaterializationSignatureDigestLabel: "untrusted signature",
			"other": "preserved",
		},
	} {
		t.Run(name, func(t *testing.T) {
			StripDmveritySnapshotLabels(labels)
			require.NotContains(t, labels, dmverityMaterializationRootHashLabel)
			require.NotContains(t, labels, dmverityMaterializationSignatureDigestLabel)
			if name == "nil" {
				require.Nil(t, labels)
			} else {
				require.Equal(t, map[string]string{"other": "preserved"}, labels)
			}
		})
	}
}

func TestWithoutDmverityAnnotations(t *testing.T) {
	for name, annotations := range map[string]map[string]string{
		"nil":          nil,
		"empty":        {},
		"target":       {TargetLayerDmverityLabel: "untrusted"},
		"other":        {"other": "preserved"},
		"target+other": {TargetLayerDmverityLabel: "untrusted", "other": "preserved"},
	} {
		t.Run(name, func(t *testing.T) {
			original := maps.Clone(annotations)
			got := WithoutDmverityTargetAnnotation(annotations)
			require.NotContains(t, got, TargetLayerDmverityLabel)
			require.Equal(t, original, annotations)
			if value, ok := annotations["other"]; ok {
				require.Equal(t, map[string]string{"other": value}, got)
			} else {
				require.Nil(t, got)
			}
		})
	}
}
