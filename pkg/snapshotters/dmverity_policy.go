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
	"fmt"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	DmverityMaterializationVersionLabel         = "containerd.io/snapshot/dmverity.version"
	DmverityMaterializationStateLabel           = "containerd.io/snapshot/dmverity.state"
	DmverityMaterializationRootHashLabel        = "containerd.io/snapshot/dmverity.root-hash"
	DmverityMaterializationSignatureDigestLabel = "containerd.io/snapshot/dmverity.signature-digest"

	DmverityMaterializationVersion     = "1"
	DmverityMaterializationStatePlain  = "plain"
	DmverityMaterializationStateSigned = "signed"
)

// DmveritySnapshotLabels describes the expected on-disk materialization for a
// layer handled by a dm-verity-aware EROFS snapshotter.
func DmveritySnapshotLabels(desc ocispec.Descriptor, requireSignature bool) (map[string]string, error) {
	signature := desc.Annotations[TargetLayerSignatureLabel]
	rootHash := desc.Annotations[TargetLayerRootHashLabel]
	tarIndex := desc.Annotations[TargetLayerTarIndexDescriptorLabel]
	merkleTree := desc.Annotations[TargetLayerMerkleTreeDescriptorLabel]

	labels := map[string]string{
		DmverityMaterializationVersionLabel: DmverityMaterializationVersion,
		DmverityMaterializationStateLabel:   DmverityMaterializationStatePlain,
	}
	if signature == "" {
		if rootHash != "" || tarIndex != "" || merkleTree != "" {
			return nil, fmt.Errorf("layer %s has dm-verity metadata without a signature", desc.Digest)
		}
		if requireSignature {
			return nil, fmt.Errorf("dm-verity signature required but not present on layer %s", desc.Digest)
		}
		return labels, nil
	}
	if rootHash == "" {
		return nil, fmt.Errorf("dm-verity signature present but missing expected root hash for layer %s", desc.Digest)
	}
	if (tarIndex == "") != (merkleTree == "") {
		return nil, fmt.Errorf("layer %s has incomplete precomputed dm-verity artifacts", desc.Digest)
	}
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return nil, fmt.Errorf("layer %s has invalid dm-verity signature encoding: %w", desc.Digest, err)
	}

	labels[DmverityMaterializationStateLabel] = DmverityMaterializationStateSigned
	labels[DmverityMaterializationRootHashLabel] = rootHash
	labels[DmverityMaterializationSignatureDigestLabel] = digest.FromBytes(signatureBytes).String()
	return labels, nil
}

// ValidateDmveritySnapshot checks that an existing ChainID snapshot satisfies
// the materialization requested for the current layer. A signed snapshot is
// safe to reuse for a plain request, but a plain, legacy, or differently signed
// snapshot must never satisfy a signed request.
func ValidateDmveritySnapshot(existing, expected map[string]string) error {
	if expected[DmverityMaterializationVersionLabel] == "" {
		return nil
	}

	switch expected[DmverityMaterializationStateLabel] {
	case DmverityMaterializationStatePlain:
		switch existing[DmverityMaterializationStateLabel] {
		case "", DmverityMaterializationStatePlain:
			return nil
		case DmverityMaterializationStateSigned:
			return validateSignedMaterialization(existing)
		default:
			return fmt.Errorf("existing snapshot has unknown dm-verity materialization state %q", existing[DmverityMaterializationStateLabel])
		}
	case DmverityMaterializationStateSigned:
		if err := validateSignedMaterialization(existing); err != nil {
			return err
		}
		if existing[DmverityMaterializationRootHashLabel] != expected[DmverityMaterializationRootHashLabel] {
			return fmt.Errorf(
				"existing snapshot dm-verity root hash %q does not match required root hash %q",
				existing[DmverityMaterializationRootHashLabel],
				expected[DmverityMaterializationRootHashLabel],
			)
		}
		if existing[DmverityMaterializationSignatureDigestLabel] != expected[DmverityMaterializationSignatureDigestLabel] {
			return fmt.Errorf(
				"existing snapshot dm-verity signature digest %q does not match required digest %q",
				existing[DmverityMaterializationSignatureDigestLabel],
				expected[DmverityMaterializationSignatureDigestLabel],
			)
		}
		return nil
	default:
		return fmt.Errorf("invalid expected dm-verity materialization state %q", expected[DmverityMaterializationStateLabel])
	}
}

func validateSignedMaterialization(labels map[string]string) error {
	if labels[DmverityMaterializationVersionLabel] != DmverityMaterializationVersion {
		return fmt.Errorf(
			"existing signed snapshot has unsupported dm-verity materialization version %q",
			labels[DmverityMaterializationVersionLabel],
		)
	}
	if labels[DmverityMaterializationStateLabel] != DmverityMaterializationStateSigned {
		return fmt.Errorf(
			"existing snapshot is not signed dm-verity materialization (state %q)",
			labels[DmverityMaterializationStateLabel],
		)
	}
	if labels[DmverityMaterializationRootHashLabel] == "" {
		return fmt.Errorf("existing signed snapshot is missing its dm-verity root hash label")
	}
	if _, err := digest.Parse(labels[DmverityMaterializationSignatureDigestLabel]); err != nil {
		return fmt.Errorf("existing signed snapshot has invalid dm-verity signature digest label: %w", err)
	}
	return nil
}
