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

package dmverity

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/go-dmverity/pkg/utils"
	"github.com/containerd/go-dmverity/pkg/verity"
	"github.com/containerd/log"
	"github.com/google/uuid"
)

func IsSupported() (bool, error) {
	moduleData, err := os.ReadFile("/proc/modules")
	if err != nil {
		return false, fmt.Errorf("failed to read /proc/modules: %w", err)
	}
	if !bytes.Contains(moduleData, []byte("dm_verity")) {
		return false, fmt.Errorf("dm_verity module not loaded")
	}

	return true, nil
}

func convertToVerityParams(opts *DmverityOptions) (verity.Params, error) {
	params := verity.DefaultParams()

	if opts != nil {
		if opts.HashAlgorithm != "" {
			params.HashName = opts.HashAlgorithm
		}
		if opts.DataBlockSize > 0 {
			params.DataBlockSize = opts.DataBlockSize
		}
		if opts.HashBlockSize > 0 {
			params.HashBlockSize = opts.HashBlockSize
		}
		if opts.DataBlocks > 0 {
			params.DataBlocks = opts.DataBlocks
		}
		if opts.HashOffset > 0 {
			params.HashAreaOffset = opts.HashOffset
		}
		if opts.HashType > 0 {
			params.HashType = opts.HashType
		}

		if opts.Salt != "" {
			salt, saltSize, err := utils.ApplySalt(opts.Salt, 256)
			if err != nil {
				return params, fmt.Errorf("invalid salt: %w", err)
			}
			params.Salt = salt
			params.SaltSize = saltSize
		}

		if opts.UUID != "" {
			uuidBytes, err := utils.ApplyUUID(opts.UUID, false, opts.NoSuperblock, nil)
			if err != nil {
				return params, fmt.Errorf("invalid UUID: %w", err)
			}
			params.UUID = uuidBytes
		}

		params.NoSuperblock = opts.NoSuperblock
	}

	return params, nil
}

// Format creates a dm-verity hash for a data device and returns the root hash.
// If hashDevice is the same as dataDevice, the hash will be stored on the same device.
func Format(dataDevice, hashDevice string, opts *DmverityOptions) (string, error) {
	if opts == nil {
		opts = DefaultDmverityOptions()
	}

	params, err := convertToVerityParams(opts)
	if err != nil {
		return "", fmt.Errorf("failed to convert options: %w", err)
	}

	if params.DataBlocks == 0 {
		size, err := utils.GetBlockOrFileSize(dataDevice)
		if err != nil {
			return "", fmt.Errorf("failed to get device size: %w", err)
		}
		params.DataBlocks = uint64(size / int64(params.DataBlockSize))
	}

	// IMPORTANT: This may modify params.HashAreaOffset when using superblock mode
	rootDigest, err := verity.Create(&params, dataDevice, hashDevice)
	if err != nil {
		return "", fmt.Errorf("failed to format dm-verity device: %w", err)
	}

	return fmt.Sprintf("%x", rootDigest), nil
}

// Open creates a read-only device-mapper target for transparent integrity verification.
// It supports both superblock and no-superblock modes:
//
//   - Superblock mode (opts == nil or opts.NoSuperblock == false):
//     Reads dm-verity parameters from the superblock at the specified hashOffset.
//     Only rootHash needs to be provided; all other parameters are read from the device.
//     Use hashOffset to specify where the superblock is located (required when hash tree
//     is stored in the same file as data).
//
//   - No-superblock mode (opts != nil and opts.NoSuperblock == true):
//     Uses explicitly provided parameters from opts. All dm-verity parameters must be
//     supplied programmatically since there's no superblock to read from.
func Open(dataDevice string, name string, hashDevice string, rootHash string, hashOffset uint64, opts *DmverityOptions) (string, error) {
	return OpenWithSignature(dataDevice, name, hashDevice, rootHash, hashOffset, opts, "")
}

// OpenWithSignature creates a read-only device-mapper target with optional signature verification.
// When signatureFile is provided, dm-verity will verify the root hash signature using the kernel keyring.
// This provides cryptographic proof that the root hash hasn't been tampered with.
func OpenWithSignature(dataDevice string, name string, hashDevice string, rootHash string, hashOffset uint64, opts *DmverityOptions, signatureFile string) (string, error) {
	if rootHash == "" {
		return "", fmt.Errorf("rootHash cannot be empty")
	}

	rootDigest, err := utils.ParseRootHash(rootHash)
	if err != nil {
		return "", fmt.Errorf("invalid root hash: %w", err)
	}

	var params verity.Params

	if opts != nil && opts.NoSuperblock {
		params, err = convertToVerityParams(opts)
		if err != nil {
			return "", fmt.Errorf("failed to convert options: %w", err)
		}
	} else {
		params = verity.DefaultParams()
		params.HashAreaOffset = hashOffset
	}

	loopParams := mount.LoopParams{
		Readonly:  true,
		Autoclear: false, // Don't use autoclear - dm-verity needs the loop device to stay active
	}

	dataLoop, err := mount.SetupLoop(dataDevice, loopParams)
	if err != nil {
		return "", fmt.Errorf("failed to setup loop device for data: %w", err)
	}
	dataLoopDevice := dataLoop.Name()

	var hashLoop *os.File
	var hashLoopDevice string
	if hashDevice != dataDevice {
		hashLoop, err = mount.SetupLoop(hashDevice, loopParams)
		if err != nil {
			dataLoop.Close()
			mount.DetachLoopDevice(dataLoopDevice)
			return "", fmt.Errorf("failed to setup loop device for hash: %w", err)
		}
		hashLoopDevice = hashLoop.Name()
	} else {
		hashLoopDevice = dataLoopDevice
	}

	devicePath, err := verity.Open(&params, name, dataLoopDevice, hashLoopDevice, rootDigest, signatureFile, nil)
	if err != nil {
		dataLoop.Close()
		mount.DetachLoopDevice(dataLoopDevice)
		if hashLoop != nil {
			hashLoop.Close()
			mount.DetachLoopDevice(hashLoopDevice)
		}
		return "", fmt.Errorf("failed to open dm-verity device: %w", err)
	}

	return devicePath, nil
}

func Close(name string) error {
	if err := verity.Close(name); err != nil {
		return fmt.Errorf("failed to close dm-verity device: %w", err)
	}
	return nil
}

// FormatLayerBlob formats an existing EROFS layer blob with a dm-verity hash tree
// in-place (appended after the data) and writes the .dmverity sidecar.
// Returns the computed root hash.
//
// Idempotent: if a .dmverity sidecar already exists at MetadataPath(layerBlobPath)
// the cached root hash is returned and no re-formatting is done.
//
// On error after the in-place truncate, the helper restores the original blob
// size and removes any stale .dmverity sidecar — leaving the layer in the
// pre-call state so the caller can clean up the bare blob via its normal
// orphan-handling path.
//
// blockSize must match the EROFS image's logical block size:
//   - tar-index mode requires 512 (mkfs.erofs --tar=i uses 512-byte metadata blocks)
//   - all other modes use 4096 (standard page size)
func FormatLayerBlob(ctx context.Context, layerBlobPath string, blockSize uint32) (string, error) {
	startedAt := time.Now()
	metadataPath := MetadataPath(layerBlobPath)
	if _, err := os.Stat(metadataPath); err == nil {
		metadata, err := ReadMetadata(layerBlobPath)
		if err != nil {
			log.G(ctx).WithError(err).WithFields(log.Fields{
				"tag":          "dmverity_format",
				"event":        "idempotent_read_failed",
				"path":         layerBlobPath,
				"metadataPath": metadataPath,
			}).Warn("dmverity_format: failed to read existing .dmverity sidecar during idempotency check")
			return "", fmt.Errorf("failed to read existing dm-verity metadata: %w", err)
		}
		log.G(ctx).WithFields(log.Fields{
			"tag":      "dmverity_format",
			"event":    "idempotent_hit",
			"path":     layerBlobPath,
			"rootHash": metadata.RootHash,
		}).Info("dmverity_format: layer already formatted (.dmverity sidecar present), returning cached root hash")
		return metadata.RootHash, nil
	}

	fileInfo, err := os.Stat(layerBlobPath)
	if err != nil {
		return "", fmt.Errorf("failed to stat layer blob: %w", err)
	}
	originalSize := fileInfo.Size()

	log.G(ctx).WithFields(log.Fields{
		"tag":          "dmverity_format",
		"event":        "enter",
		"path":         layerBlobPath,
		"originalSize": originalSize,
		"blockSize":    blockSize,
	}).Info("dmverity_format: ENTER FormatLayerBlob")

	opts := DefaultDmverityOptions()
	if blockSize > 0 {
		opts.DataBlockSize = blockSize
		opts.HashBlockSize = blockSize
	}

	dataBlocks := (originalSize + int64(opts.DataBlockSize) - 1) / int64(opts.DataBlockSize)
	hashOffset := uint64(dataBlocks * int64(opts.DataBlockSize))

	opts.HashOffset = hashOffset
	opts.DataBlocks = uint64(dataBlocks)

	hashTreeSize, err := verity.GetHashTreeSize(&verity.Params{
		HashName:      opts.HashAlgorithm,
		DataBlockSize: opts.DataBlockSize,
		HashBlockSize: opts.HashBlockSize,
		DataBlocks:    opts.DataBlocks,
		HashType:      opts.HashType,
	})
	if err != nil {
		return "", fmt.Errorf("failed to calculate hash tree size: %w", err)
	}

	superblockSize := uint64(0)
	if !opts.NoSuperblock {
		superblockSize = utils.AlignUp(uint64(verity.SuperblockSize), uint64(opts.HashBlockSize))
	}
	requiredSize := hashOffset + superblockSize + hashTreeSize
	if err := os.Truncate(layerBlobPath, int64(requiredSize)); err != nil {
		return "", fmt.Errorf("failed to pre-allocate space for hash tree: %w", err)
	}

	// Rollback: if we fail after the truncate, restore the original blob size
	// and remove any partial .dmverity sidecar so the caller sees the same
	// pre-call state (bare layer.erofs, no .dmverity). This lets the caller's
	// orphan-handling path treat the layer uniformly.
	formatted := false
	defer func() {
		if formatted {
			return
		}
		log.G(ctx).WithFields(log.Fields{
			"tag":          "dmverity_format",
			"event":        "rollback",
			"path":         layerBlobPath,
			"originalSize": originalSize,
			"elapsedMs":    time.Since(startedAt).Milliseconds(),
		}).Warn("dmverity_format: ROLLBACK — format failed after pre-allocation; restoring blob and removing partial sidecar")
		if terr := os.Truncate(layerBlobPath, originalSize); terr != nil {
			log.G(ctx).WithError(terr).WithField("path", layerBlobPath).Warn("FormatLayerBlob rollback: failed to restore original blob size")
		}
		if rerr := os.Remove(metadataPath); rerr != nil && !os.IsNotExist(rerr) {
			log.G(ctx).WithError(rerr).WithField("path", metadataPath).Warn("FormatLayerBlob rollback: failed to remove stale .dmverity sidecar")
		}
	}()

	if opts.UUID == "" {
		opts.UUID = uuid.New().String()
	}

	rootHash, err := Format(layerBlobPath, layerBlobPath, opts)
	if err != nil {
		return "", fmt.Errorf("failed to format dm-verity: %w", err)
	}

	metadata := DmverityMetadata{
		RootHash:   rootHash,
		HashOffset: hashOffset,
	}
	metadataBytes, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal dm-verity metadata: %w", err)
	}
	if err := os.WriteFile(metadataPath, metadataBytes, 0644); err != nil {
		return "", fmt.Errorf("failed to write dm-verity metadata: %w", err)
	}

	formatted = true

	finalInfo, statErr := os.Stat(layerBlobPath)
	finalSize := int64(-1)
	if statErr == nil {
		finalSize = finalInfo.Size()
	}

	log.G(ctx).WithFields(log.Fields{
		"tag":          "dmverity_format",
		"event":        "success",
		"path":         layerBlobPath,
		"originalSize": originalSize,
		"finalSize":    finalSize,
		"blockSize":    opts.DataBlockSize,
		"hashOffset":   hashOffset,
		"rootHash":     rootHash,
		"elapsedMs":    time.Since(startedAt).Milliseconds(),
	}).Info("dmverity_format: SUCCESS — layer formatted, .dmverity sidecar written")

	return rootHash, nil
}

// VerifyDevice ensures an existing dm-verity device matches the expected metadata and is healthy.
func VerifyDevice(name string, rootHash string) error {
	rootDigest, err := utils.ParseRootHash(rootHash)
	if err != nil {
		return fmt.Errorf("invalid root hash: %w", err)
	}

	// Use library's Check to verify device status and root hash
	if !verity.Check(name, rootDigest) {
		return fmt.Errorf("dm-verity device %q verification failed", name)
	}

	return nil
}
