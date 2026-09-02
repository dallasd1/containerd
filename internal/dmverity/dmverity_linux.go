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
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/containerd/containerd/v2/core/mount"
	dm "github.com/containerd/go-dmverity/pkg/dm"
	"github.com/containerd/go-dmverity/pkg/keyring"
	"github.com/containerd/go-dmverity/pkg/utils"
	"github.com/containerd/go-dmverity/pkg/verity"
	"github.com/containerd/log"
	"github.com/google/uuid"
)

var signatureSupportCache struct {
	sync.Mutex
	supported bool
}

// IsSupported reports whether the dm-verity target is currently available.
//
// A false return with a nil error means the answer is determinate: dm-verity
// is genuinely unavailable, and callers may skip cleanly. A non-nil error
// means the answer is indeterminate — the check itself could not be
// completed — and callers should treat that as a hard failure rather than
// assume absence.
//
// This check does not load kernel modules. Hosts using a modular target must
// load dm_verity before containerd starts, just as the EROFS snapshotter
// requires erofs to be loaded before plugin initialization.
func IsSupported() (bool, error) {
	// dm-verity may be a loadable module or built into the kernel. Checking
	// only /proc/modules reports unsupported on a CONFIG_DM_VERITY=y kernel and
	// silently disables verification, so consult the built-in target list too.
	if moduleData, err := os.ReadFile("/proc/modules"); err == nil {
		if bytes.Contains(moduleData, []byte("dm_verity")) {
			return true, nil
		}
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("failed to read /proc/modules: %w", err)
	}

	// /sys/module/dm_verity is present for a built-in target as well as a
	// loaded module, so it covers CONFIG_DM_VERITY=y kernels that never
	// appear in /proc/modules.
	if _, err := os.Stat("/sys/module/dm_verity"); err == nil {
		return true, nil
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("failed to stat /sys/module/dm_verity: %w", err)
	}

	// Both probes succeeded and neither found a loaded or built-in dm-verity
	// target, so this is a determinate "not available" rather than a failed
	// check.
	return false, nil
}

// CheckSignatureSupport verifies that the kernel can activate dm-verity
// mappings that require a root-hash signature from a kernel keyring.
func CheckSignatureSupport() error {
	signatureSupportCache.Lock()
	defer signatureSupportCache.Unlock()

	if signatureSupportCache.supported {
		return nil
	}
	if err := checkSignatureSupport(IsSupported, checkVeritySignatureSupport, checkKeyringAccess); err != nil {
		return err
	}
	signatureSupportCache.supported = true
	return nil
}

func checkSignatureSupport(
	checkDmverity func() (bool, error),
	checkTarget func() error,
	checkKeyring func() error,
) error {
	supported, err := checkDmverity()
	if err != nil {
		return fmt.Errorf("check dm-verity support: %w", err)
	}
	if !supported {
		return fmt.Errorf("dm-verity is unavailable")
	}
	if err := checkTarget(); err != nil {
		return fmt.Errorf("check dm-verity signature support: %w", err)
	}
	if err := checkKeyring(); err != nil {
		return fmt.Errorf("check kernel keyring support: %w", err)
	}
	return nil
}

func checkKeyringAccess() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	keyID, err := keyring.AddKeyToThreadKeyring(
		"user",
		"containerd:dmverity-capability-probe",
		[]byte{0},
	)
	if err != nil {
		return err
	}
	if err := keyring.UnlinkKeyFromThreadKeyring(keyID); err != nil {
		return err
	}
	return nil
}

func checkVeritySignatureSupport() error {
	if err := dm.CheckVeritySignatureSupport(); err != nil {
		return err
	}
	const signatureParameter = "/sys/module/dm_verity/parameters/require_signatures"
	if _, err := os.Stat(signatureParameter); err != nil {
		return fmt.Errorf(
			"kernel does not expose %s; signed dm-verity discovery requires CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG and its read-only feature marker: %w",
			signatureParameter,
			err,
		)
	}
	return nil
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
		Readonly: true,
		// The dm-verity target holds the loop devices open. Autoclear detaches
		// them when the mapper is removed, including after a daemon restart.
		Autoclear: true,
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

	// go-dmverity loads the root-hash signature into KEY_SPEC_THREAD_KEYRING and
	// then names it in the device-mapper table, which the kernel resolves against
	// the calling thread's keyrings. Go is free to reschedule this goroutine onto
	// a different OS thread between the add_key and the DM ioctls, and that thread
	// cannot see the key -- so a perfectly valid signature is rejected, and the
	// deferred unlink misses too, leaking the key. Pin the goroutine across the
	// call. verity.Open is fully synchronous, so this covers the whole sequence.
	if signatureFile != "" {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
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
	dataLoop.Close()
	if hashLoop != nil {
		hashLoop.Close()
	}

	return devicePath, nil
}

// OpenWithSignatureData creates a signed dm-verity mapping from signature
// bytes already validated by the caller.
func OpenWithSignatureData(dataDevice string, name string, hashDevice string, rootHash string, hashOffset uint64, opts *DmverityOptions, signature []byte) (string, error) {
	if len(signature) == 0 {
		return "", fmt.Errorf("signature cannot be empty")
	}
	file, err := os.CreateTemp("", "containerd-dmverity-signature-")
	if err != nil {
		return "", fmt.Errorf("create temporary signature file: %w", err)
	}
	path := file.Name()
	defer os.Remove(path)

	if err := file.Chmod(0600); err != nil {
		file.Close()
		return "", fmt.Errorf("set temporary signature file mode: %w", err)
	}
	if _, err := file.Write(signature); err != nil {
		file.Close()
		return "", fmt.Errorf("write temporary signature file: %w", err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		file.Close()
		return "", fmt.Errorf("rewind temporary signature file: %w", err)
	}
	if err := os.Remove(path); err != nil {
		file.Close()
		return "", fmt.Errorf("unlink temporary signature file: %w", err)
	}
	defer file.Close()

	// Keep the validated inode open and let go-dmverity reopen it through procfs.
	// The unlinked file has no replaceable pathname between validation and use.
	fdPath := fmt.Sprintf("/proc/self/fd/%d", file.Fd())
	return OpenWithSignature(dataDevice, name, hashDevice, rootHash, hashOffset, opts, fdPath)
}

// VerifyArtifacts verifies a precomputed EROFS data device and separate
// dm-verity hash device against the expected root hash.
func VerifyArtifacts(dataDevice, hashDevice, rootHash string, blockSize uint32) error {
	rootDigest, err := utils.ParseRootHash(rootHash)
	if err != nil {
		return fmt.Errorf("invalid root hash: %w", err)
	}
	if !utils.IsBlockSizeValid(blockSize) {
		return fmt.Errorf("invalid expected dm-verity block size: %d", blockSize)
	}
	info, err := os.Stat(dataDevice)
	if err != nil {
		return fmt.Errorf("stat precomputed dm-verity data device: %w", err)
	}
	if info.Size() <= 0 || info.Size()%int64(blockSize) != 0 {
		return fmt.Errorf(
			"precomputed dm-verity data size %d is not a positive multiple of block size %d",
			info.Size(),
			blockSize,
		)
	}
	params := verity.DefaultParams()
	params.DataBlockSize = blockSize
	params.HashBlockSize = blockSize
	params.DataBlocks = uint64(info.Size() / int64(blockSize))
	params.Salt = make([]byte, 32)
	params.SaltSize = uint16(len(params.Salt))
	if err := utils.ValidateRootHashSize(rootDigest, params.HashName); err != nil {
		return fmt.Errorf("invalid root hash: %w", err)
	}
	if err := verity.Verify(&params, dataDevice, hashDevice, rootDigest); err != nil {
		return fmt.Errorf("verify precomputed dm-verity artifacts: %w", err)
	}
	return nil
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
	if err := WriteMetadata(layerBlobPath, metadata); err != nil {
		return "", err
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

// InspectDevice returns the kernel open count for an active device.
func InspectDevice(name string) (DeviceInfo, error) {
	control, err := dm.Open()
	if err != nil {
		return DeviceInfo{}, fmt.Errorf("open device-mapper control: %w", err)
	}
	defer control.Close()

	status, err := control.DeviceStatus(name)
	if err != nil {
		return DeviceInfo{}, fmt.Errorf("inspect dm-verity device %q: %w", name, err)
	}
	if !status.ActivePresent {
		return DeviceInfo{Exists: true, OpenCount: status.OpenCount}, fmt.Errorf("dm-verity device %q has no active table", name)
	}
	return DeviceInfo{Exists: true, OpenCount: status.OpenCount}, nil
}

// VerifySignedDevice ensures an existing dm-verity device matches the expected
// signed metadata and is healthy.
func VerifySignedDevice(name string, rootHash string) (DeviceInfo, error) {
	rootDigest, err := utils.ParseRootHash(rootHash)
	if err != nil {
		return DeviceInfo{}, fmt.Errorf("invalid root hash: %w", err)
	}

	control, err := dm.Open()
	if err != nil {
		return DeviceInfo{}, fmt.Errorf("open device-mapper control: %w", err)
	}
	defer control.Close()

	status, err := control.DeviceStatus(name)
	if err != nil {
		return DeviceInfo{}, fmt.Errorf("inspect dm-verity device %q: %w", name, err)
	}
	info := DeviceInfo{Exists: true, OpenCount: status.OpenCount}
	if !status.ActivePresent || status.TargetCount != 1 {
		return info, fmt.Errorf("dm-verity device %q does not have one active target", name)
	}

	verityStatus, err := control.TableStatus(name, false)
	if err != nil {
		return info, fmt.Errorf("read dm-verity device %q status: %w", name, err)
	}
	if !slices.Contains(strings.Fields(verityStatus), "V") {
		return info, fmt.Errorf("dm-verity device %q is not in the verified state", name)
	}

	table, err := control.TableStatus(name, true)
	if err != nil {
		return info, fmt.Errorf("read dm-verity device %q table: %w", name, err)
	}
	if err := verifySignedVerityTable(table, hex.EncodeToString(rootDigest)); err != nil {
		return info, fmt.Errorf("verify dm-verity device %q table: %w", name, err)
	}
	return info, nil
}

func verifySignedVerityTable(table, expectedRootHash string) error {
	fields := strings.Fields(table)
	if len(fields) < 10 {
		return fmt.Errorf("invalid verity table with %d fields", len(fields))
	}
	if !strings.EqualFold(fields[8], expectedRootHash) {
		return fmt.Errorf("root hash is %q, expected %q", fields[8], expectedRootHash)
	}
	if len(fields) == 10 {
		return fmt.Errorf("verity table does not require a root-hash signature")
	}

	optionCount, err := strconv.Atoi(fields[10])
	if err != nil || optionCount < 0 || len(fields) != 11+optionCount {
		return fmt.Errorf("invalid verity optional-argument count %q", fields[10])
	}
	options := fields[11:]
	for i := 0; i+1 < len(options); i++ {
		if options[i] == "root_hash_sig_key_desc" && options[i+1] != "" {
			return nil
		}
	}
	return fmt.Errorf("verity table does not require a root-hash signature")
}
