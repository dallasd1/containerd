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

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	dmverityMaterializationRootHashLabel        = "containerd.io/snapshot/erofs.dmverity.root-hash"
	dmverityMaterializationSignatureDigestLabel = "containerd.io/snapshot/erofs.dmverity.signature-digest"
)

// DmveritySnapshotLabels returns snapshot identity labels for a selected
// signed materialization. Unsigned layers do not receive dm-verity labels.
func DmveritySnapshotLabels(desc ocispec.Descriptor) (map[string]string, error) {
	targetValue := desc.Annotations[TargetLayerDmverityLabel]
	if targetValue == "" {
		return nil, nil
	}
	target, err := ParseDmverityTarget(targetValue)
	if err != nil {
		return nil, fmt.Errorf("layer %s has an invalid dm-verity target: %w", desc.Digest, err)
	}

	return map[string]string{
		dmverityMaterializationRootHashLabel:        target.RootHash,
		dmverityMaterializationSignatureDigestLabel: target.Signature.Digest.String(),
	}, nil
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

// ValidateDmveritySnapshot prevents an unsigned or differently signed ChainID
// snapshot from satisfying a selected signed materialization.
func ValidateDmveritySnapshot(existing, expected map[string]string) error {
	expectedRootHash, expectedSignatureDigest, expectedSigned, err := DmveritySnapshotIdentity(expected)
	if err != nil {
		return fmt.Errorf("invalid expected dm-verity snapshot identity: %w", err)
	}
	if !expectedSigned {
		return nil
	}

	existingRootHash, existingSignatureDigest, existingSigned, err := DmveritySnapshotIdentity(existing)
	if err != nil {
		return fmt.Errorf("invalid existing dm-verity snapshot identity: %w", err)
	}
	if !existingSigned {
		return fmt.Errorf("existing snapshot is not a signed dm-verity materialization")
	}
	if existingRootHash != expectedRootHash {
		return fmt.Errorf(
			"existing snapshot dm-verity root hash %q does not match required root hash %q",
			existingRootHash,
			expectedRootHash,
		)
	}
	if existingSignatureDigest != expectedSignatureDigest {
		return fmt.Errorf(
			"existing snapshot dm-verity signature digest %q does not match required digest %q",
			existingSignatureDigest,
			expectedSignatureDigest,
		)
	}
	return nil
}
