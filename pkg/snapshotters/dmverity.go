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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	erofsAnnotationPrefix = "io.containerd.erofs.v1/"

	// TargetLayerDmverityLabel carries the identity of the selected referrer and this layer's signed root hash.
	TargetLayerDmverityLabel = erofsAnnotationPrefix + "dmverity.target"

	dmverityReferrerRootHashLabel        = "containerd.io/snapshot/erofs.dmverity.root-hash"
	dmverityReferrerSignatureDigestLabel = "containerd.io/snapshot/erofs.dmverity.signature-digest"
)

// DmveritySnapshotKey derives the signed snapshot key for an OCI ChainID.
func DmveritySnapshotKey(chainID string) (string, error) {
	chainDigest, err := digest.Parse(chainID)
	if err != nil {
		return "", fmt.Errorf("parse OCI ChainID %q: %w", chainID, err)
	}
	return chainDigest.String() + "-dmverity", nil
}

// DmverityTarget is the trusted layer annotation. Payload descriptors are
// resolved from the selected referrer in the local content store.
type DmverityTarget struct {
	RootHash  string             `json:"rootHash"`
	Metadata  ocispec.Descriptor `json:"metadata"`
	Tree      ocispec.Descriptor `json:"tree"`
	Signature ocispec.Descriptor `json:"signature"`
}

// ParseDmverityTarget parses a target injected by a validated referrer handler.
func ParseDmverityTarget(value string) (DmverityTarget, error) {
	var target DmverityTarget
	if err := json.Unmarshal([]byte(value), &target); err != nil {
		return DmverityTarget{}, fmt.Errorf("parse dm-verity target: %w", err)
	}
	if target.RootHash == "" ||
		target.Metadata.Digest == "" ||
		target.Tree.Digest == "" ||
		target.Signature.Digest == "" {
		return DmverityTarget{}, fmt.Errorf("incomplete dm-verity target")
	}
	return target, nil
}

func targetAnnotation(info *DmverityTarget) (string, error) {
	// Carry only the fields needed to identify and read the selected payloads.
	target := DmverityTarget{
		RootHash:  info.RootHash,
		Metadata:  compactDescriptor(info.Metadata),
		Tree:      compactDescriptor(info.Tree),
		Signature: compactDescriptor(info.Signature),
	}
	data, err := json.Marshal(target)
	if err != nil {
		return "", fmt.Errorf("marshal dm-verity target: %w", err)
	}
	return string(data), nil
}

func compactDescriptor(desc ocispec.Descriptor) ocispec.Descriptor {
	return ocispec.Descriptor{
		MediaType: desc.MediaType,
		Digest:    desc.Digest,
		Size:      desc.Size,
	}
}

func validateRootHash(rootHash string) error {
	rootDigest, err := hex.DecodeString(rootHash)
	if err != nil || len(rootDigest) != sha256.Size {
		return fmt.Errorf("invalid SHA-256 dm-verity root hash %q", rootHash)
	}
	return nil
}

// DmveritySnapshotLabels returns identity labels for a signed referrer materialization.
// Callers must persist these labels during snapshot preparation and commit,
// and use ValidateDmveritySnapshot on cache hits.
func DmveritySnapshotLabels(desc ocispec.Descriptor) (map[string]string, error) {
	targetValue, exists := desc.Annotations[TargetLayerDmverityLabel]
	if !exists {
		return nil, nil
	}
	target, err := ParseDmverityTarget(targetValue)
	if err != nil {
		return nil, fmt.Errorf("layer %s has an invalid dm-verity target: %w", desc.Digest, err)
	}

	labels := map[string]string{
		dmverityReferrerRootHashLabel:        target.RootHash,
		dmverityReferrerSignatureDigestLabel: target.Signature.Digest.String(),
	}
	if _, _, _, err := GetDmveritySnapshotIdentity(labels); err != nil {
		return nil, fmt.Errorf("layer %s has an invalid dm-verity target: %w", desc.Digest, err)
	}
	return labels, nil
}

// GetDmveritySnapshotIdentity returns the signed identity recorded on a snapshot.
func GetDmveritySnapshotIdentity(labels map[string]string) (rootHash, signatureDigest string, signed bool, err error) {
	rootHash = labels[dmverityReferrerRootHashLabel]
	signatureDigest = labels[dmverityReferrerSignatureDigestLabel]
	if rootHash == "" && signatureDigest == "" {
		return "", "", false, nil
	}
	if rootHash == "" || signatureDigest == "" {
		return "", "", false, fmt.Errorf("incomplete signed dm-verity snapshot identity")
	}
	if err := validateRootHash(rootHash); err != nil {
		return "", "", false, fmt.Errorf("invalid signed dm-verity snapshot root hash: %w", err)
	}
	if _, err := digest.Parse(signatureDigest); err != nil {
		return "", "", false, fmt.Errorf("invalid signed dm-verity snapshot signature digest: %w", err)
	}
	return rootHash, signatureDigest, true, nil
}

// ValidateDmveritySnapshot rejects a snapshot that lacks the selected signed identity.
func ValidateDmveritySnapshot(existing, expected map[string]string) error {
	expectedRootHash, _, expectedSigned, err := GetDmveritySnapshotIdentity(expected)
	if err != nil {
		return fmt.Errorf("invalid expected dm-verity snapshot identity: %w", err)
	}
	return validateDmveritySnapshot(existing, expectedRootHash, expectedSigned)
}

func validateDmveritySnapshot(existing map[string]string, expectedRootHash string, expectedSigned bool) error {
	existingRootHash, _, existingSigned, err := GetDmveritySnapshotIdentity(existing)
	if err != nil {
		return fmt.Errorf("invalid existing dm-verity snapshot identity: %w", err)
	}
	if !expectedSigned {
		return nil
	}

	if !existingSigned {
		return fmt.Errorf("existing snapshot is not signed for the requested dm-verity layer; remove the affected snapshot and descendants or reimage before retrying")
	}
	if !strings.EqualFold(existingRootHash, expectedRootHash) {
		return fmt.Errorf("existing snapshot has a different signed dm-verity root hash; remove the affected snapshot and descendants or reimage before retrying")
	}
	// Reuse keeps the existing signature label and mounted materialization unchanged.
	return nil
}
