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

// Package dmverity provides functions for working with dm-verity for integrity verification
// using the veritysetup-go library
package dmverity

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	MountOptionModePrefix            = "X-containerd.dmverity="
	MountOptionRootHashPrefix        = "X-containerd.dmverity.root-hash="
	MountOptionSignatureDigestPrefix = "X-containerd.dmverity.signature-digest="
)

type DmverityOptions struct {
	// Salt for hashing, represented as a hex string
	Salt string
	// Hash algorithm to use (default: sha256)
	HashAlgorithm string
	// Size of data blocks in bytes (default: 4096)
	DataBlockSize uint32
	// Size of hash blocks in bytes (default: 4096)
	HashBlockSize uint32
	// Number of data blocks
	DataBlocks uint64
	// Offset of hash area in bytes
	HashOffset uint64
	// Hash type (default: 1)
	HashType uint32
	// NoSuperblock disables superblock usage (matches library's NoSuperblock field)
	NoSuperblock bool
	// UUID for device to use
	UUID string
}

func DefaultDmverityOptions() *DmverityOptions {
	return &DmverityOptions{
		Salt:          "0000000000000000000000000000000000000000000000000000000000000000",
		HashAlgorithm: "sha256",
		DataBlockSize: 4096,
		HashBlockSize: 4096,
		HashType:      1,
		NoSuperblock:  false, // By default, use superblock
	}
}

func MetadataPath(layerBlobPath string) string {
	return layerBlobPath + ".dmverity"
}

// SignaturePath returns the path to the dm-verity signature file for a layer.
// The signature file contains the decoded PKCS7 signature for root hash verification.
func SignaturePath(layerBlobPath string) string {
	return layerBlobPath + ".sig"
}

// SignatureRequiredPath returns the marker path used to distinguish protected
// materializations from legacy unsigned layers that were formatted with
// dm-verity metadata before signatures became the activation gate.
func SignatureRequiredPath(layerBlobPath string) string {
	return layerBlobPath + ".sig-required"
}

// HashDevicePath returns the path used for a separate precomputed Merkle tree.
func HashDevicePath(layerBlobPath string) string {
	return layerBlobPath + ".hashtree"
}

// WriteSignature decodes and writes a base64-encoded signature for a layer.
func WriteSignature(layerBlobPath string, base64Sig string) error {
	sigPath := SignaturePath(layerBlobPath)
	sigBytes, err := base64.StdEncoding.DecodeString(base64Sig)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}
	if err := writeFileAtomic(sigPath, sigBytes, 0644); err != nil {
		return fmt.Errorf("failed to write signature file: %w", err)
	}
	if err := writeFileAtomic(SignatureRequiredPath(layerBlobPath), []byte("1\n"), 0644); err != nil {
		return fmt.Errorf("failed to write signature-required marker: %w", err)
	}
	return nil
}

func DevicePath(name string) string {
	return fmt.Sprintf("/dev/mapper/%s", name)
}

// DeviceInfo describes the lifecycle state needed by dm-verity mount handlers.
type DeviceInfo struct {
	Exists    bool
	OpenCount int32
}

type DmverityMetadata struct {
	RootHash   string `json:"roothash"`
	HashOffset uint64 `json:"hashoffset"`
	HashDevice string `json:"hashdevice,omitempty"`
}

// WriteMetadata writes dm-verity mount metadata for a layer.
func WriteMetadata(layerBlobPath string, metadata DmverityMetadata) error {
	if metadata.RootHash == "" {
		return fmt.Errorf("cannot write dm-verity metadata without a root hash")
	}
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal dm-verity metadata: %w", err)
	}
	if err := writeFileAtomic(MetadataPath(layerBlobPath), data, 0644); err != nil {
		return fmt.Errorf("failed to write dm-verity metadata: %w", err)
	}
	return nil
}

// ResolveHashDevice returns the hash device path described by metadata.
func ResolveHashDevice(layerBlobPath string, metadata *DmverityMetadata) string {
	if metadata == nil || metadata.HashDevice == "" {
		return layerBlobPath
	}
	if filepath.IsAbs(metadata.HashDevice) {
		return metadata.HashDevice
	}
	return filepath.Join(filepath.Dir(layerBlobPath), metadata.HashDevice)
}

func ReadMetadata(layerBlobPath string) (*DmverityMetadata, error) {
	metadataPath := MetadataPath(layerBlobPath)
	data, err := os.ReadFile(metadataPath)
	if err != nil {
		return nil, fmt.Errorf("metadata file not found at %q: %w", metadataPath, err)
	}

	var metadata DmverityMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("failed to parse metadata file %q: %w", metadataPath, err)
	}

	if metadata.RootHash == "" {
		return nil, fmt.Errorf("missing root hash in metadata file %q", metadataPath)
	}

	return &metadata, nil
}
