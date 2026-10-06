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

	"github.com/containerd/containerd/v2/core/snapshots"
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

func TestDmveritySnapshotLabels(t *testing.T) {
	rootHash := digest.FromString("root").Encoded()
	signature := digest.FromString("signature")
	for _, tt := range []struct {
		name      string
		rootHash  string
		signature digest.Digest
		wantErr   string
	}{
		{name: "valid", rootHash: rootHash, signature: signature},
		{name: "uppercase root", rootHash: strings.ToUpper(rootHash), signature: signature},
		{name: "invalid root hex", rootHash: strings.Repeat("g", 64), signature: signature, wantErr: "root hash"},
		{name: "short root", rootHash: "ab", signature: signature, wantErr: "root hash"},
		{name: "invalid signature", rootHash: rootHash, signature: "sha256:bad", wantErr: "signature digest"},
		{name: "missing root", signature: signature, wantErr: "incomplete dm-verity target"},
		{name: "missing signature", rootHash: rootHash, wantErr: "incomplete dm-verity target"},
		{name: "missing identity", wantErr: "incomplete dm-verity target"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			annotation, err := targetAnnotation(&DmverityTarget{
				RootHash:  tt.rootHash,
				Metadata:  imagespec.Descriptor{Digest: digest.FromString("metadata")},
				Tree:      imagespec.Descriptor{Digest: digest.FromString("tree")},
				Signature: imagespec.Descriptor{Digest: tt.signature},
			})
			require.NoError(t, err)
			labels, err := DmveritySnapshotLabels(imagespec.Descriptor{
				Digest:      digest.FromString("layer"),
				Annotations: map[string]string{TargetLayerDmverityLabel: annotation},
			})
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				require.Nil(t, labels)
				return
			}
			require.NoError(t, err)
			require.Equal(t, map[string]string{
				dmverityReferrerRootHashLabel:        tt.rootHash,
				dmverityReferrerSignatureDigestLabel: tt.signature.String(),
			}, labels)
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

func TestDmveritySnapshotKey(t *testing.T) {
	chainID := digest.FromString("chain").String()
	key, err := DmveritySnapshotKey(chainID)
	require.NoError(t, err)
	require.Equal(t, chainID+"-dmverity", key)

	for _, invalid := range []string{"", "not-a-digest", "sha256:bad", key} {
		got, err := DmveritySnapshotKey(invalid)
		require.ErrorContains(t, err, "parse OCI ChainID")
		require.Empty(t, got)
	}
}

func TestPrepareDmverityLayerUsesStableSignedLane(t *testing.T) {
	chainID := digest.FromString("chain").String()
	desc := imagespec.Descriptor{}
	unsigned, err := PrepareDmverityLayer(t.Context(), desc, chainID)
	require.NoError(t, err)
	require.Equal(t, chainID, unsigned.Key)
	require.Empty(t, unsigned.GCQualifier)
	require.Empty(t, unsigned.Labels)
	require.NotNil(t, unsigned.ValidateExisting)
	require.NoError(t, unsigned.ValidateExisting(snapshots.Info{}))

	desc.Annotations = map[string]string{TargetLayerDmverityLabel: ""}
	_, err = PrepareDmverityLayer(t.Context(), desc, chainID)
	require.ErrorContains(t, err, "parse dm-verity target")

	target := &DmverityTarget{
		RootHash:  digest.FromString("root").Encoded(),
		Metadata:  imagespec.Descriptor{Digest: digest.FromString("metadata")},
		Tree:      imagespec.Descriptor{Digest: digest.FromString("tree")},
		Signature: imagespec.Descriptor{Digest: digest.FromString("signature")},
	}
	desc.Annotations[TargetLayerDmverityLabel], err = targetAnnotation(target)
	require.NoError(t, err)
	signed, err := PrepareDmverityLayer(t.Context(), desc, chainID)
	require.NoError(t, err)
	require.NotEqual(t, chainID, signed.Key)
	require.Equal(t, "dmverity", signed.GCQualifier)
	expectedKey, err := DmveritySnapshotKey(chainID)
	require.NoError(t, err)
	require.Equal(t, expectedKey, signed.Key)
	require.Equal(t, map[string]string{
		dmverityReferrerRootHashLabel:        target.RootHash,
		dmverityReferrerSignatureDigestLabel: target.Signature.Digest.String(),
	}, signed.Labels)
	require.NotNil(t, signed.ValidateExisting)
	require.NoError(t, signed.ValidateExisting(snapshots.Info{Labels: signed.Labels}))
	require.Error(t, signed.ValidateExisting(snapshots.Info{}))
	require.NoError(t, unsigned.ValidateExisting(snapshots.Info{Labels: signed.Labels}))

	target.Signature.Digest = digest.FromString("replacement signature")
	desc.Annotations[TargetLayerDmverityLabel], err = targetAnnotation(target)
	require.NoError(t, err)
	replacedSignature, err := PrepareDmverityLayer(t.Context(), desc, chainID)
	require.NoError(t, err)
	require.Equal(t, signed.Key, replacedSignature.Key)
	require.Equal(t, target.Signature.Digest.String(), replacedSignature.Labels[dmverityReferrerSignatureDigestLabel])
	require.NoError(t, replacedSignature.ValidateExisting(snapshots.Info{Labels: signed.Labels}))

	target.RootHash = digest.FromString("different root").Encoded()
	desc.Annotations[TargetLayerDmverityLabel], err = targetAnnotation(target)
	require.NoError(t, err)
	replacedRoot, err := PrepareDmverityLayer(t.Context(), desc, chainID)
	require.NoError(t, err)
	require.Equal(t, signed.Key, replacedRoot.Key)
	require.Equal(t, target.RootHash, replacedRoot.Labels[dmverityReferrerRootHashLabel])
	require.ErrorContains(t, replacedRoot.ValidateExisting(snapshots.Info{Labels: signed.Labels}), "different signed dm-verity root hash")
}
