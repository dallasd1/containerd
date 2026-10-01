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
	"fmt"
	"slices"

	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	dmverityMaterializationRootHashLabel        = "containerd.io/snapshot/erofs.dmverity.root-hash"
	dmverityMaterializationSignatureDigestLabel = "containerd.io/snapshot/erofs.dmverity.signature-digest"
)

// DmverityChainIDs derives snapshot keys from signed materializations. Unsigned
// chains keep their OCI ChainIDs.
func DmverityChainIDs(diffIDs []digest.Digest, layers []ocispec.Descriptor) ([]digest.Digest, error) {
	if len(diffIDs) != len(layers) {
		return nil, fmt.Errorf("number of layers and diffIDs don't match: %d != %d", len(layers), len(diffIDs))
	}
	// Preserve verified DiffIDs while deriving separate identities for signed layers.
	chainIDs := slices.Clone(diffIDs)
	for i, layer := range layers {
		labels, err := DmveritySnapshotLabels(layer)
		if err != nil {
			return nil, err
		}
		if len(labels) > 0 {
			chainIDs[i] = digest.FromString("containerd.io/snapshot/erofs.dmverity.v1 " +
				diffIDs[i].String() + " " + labels[dmverityMaterializationRootHashLabel] +
				" " + labels[dmverityMaterializationSignatureDigestLabel])
		}
	}
	// Include parent identities so a changed materialization also changes descendant keys.
	return identity.ChainIDs(chainIDs), nil
}

// DmveritySnapshotLabels returns identity labels for a signed materialization.
func DmveritySnapshotLabels(desc ocispec.Descriptor) (map[string]string, error) {
	targetValue := desc.Annotations[TargetLayerDmverityLabel]
	if targetValue == "" {
		return nil, nil
	}
	target, err := ParseDmverityTarget(targetValue)
	if err != nil {
		return nil, fmt.Errorf("layer %s has an invalid dm-verity target: %w", desc.Digest, err)
	}

	// Persist the same root hash and signature identity used to derive the snapshot key.
	return map[string]string{
		dmverityMaterializationRootHashLabel:        target.RootHash,
		dmverityMaterializationSignatureDigestLabel: target.Signature.Digest.String(),
	}, nil
}

// StripDmveritySnapshotLabels removes inherited, untrusted signed identities.
func StripDmveritySnapshotLabels(labels map[string]string) {
	delete(labels, dmverityMaterializationRootHashLabel)
	delete(labels, dmverityMaterializationSignatureDigestLabel)
}

// DmveritySnapshotIdentity returns the signed identity recorded on a snapshot.
func DmveritySnapshotIdentity(labels map[string]string) (rootHash, signatureDigest string, signed bool, err error) {
	rootHash = labels[dmverityMaterializationRootHashLabel]
	signatureDigest = labels[dmverityMaterializationSignatureDigestLabel]
	if rootHash == "" && signatureDigest == "" {
		return "", "", false, nil
	}
	if rootHash == "" || signatureDigest == "" {
		return "", "", false, fmt.Errorf("incomplete signed dm-verity snapshot identity")
	}
	return rootHash, signatureDigest, true, nil
}

// ValidateDmveritySnapshot rejects a snapshot that lacks the selected signed identity.
func ValidateDmveritySnapshot(existing, expected map[string]string) error {
	expectedRootHash, expectedSignatureDigest, expectedSigned, err := DmveritySnapshotIdentity(expected)
	if err != nil {
		return fmt.Errorf("invalid expected dm-verity snapshot identity: %w", err)
	}
	if !expectedSigned {
		return nil
	}

	if existing[dmverityMaterializationRootHashLabel] != expectedRootHash ||
		existing[dmverityMaterializationSignatureDigestLabel] != expectedSignatureDigest {
		return fmt.Errorf("existing snapshot does not match required signed dm-verity root hash and signature")
	}
	return nil
}
