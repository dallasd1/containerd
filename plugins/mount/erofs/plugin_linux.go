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

package erofs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/containerd/log"
	"github.com/containerd/platforms"
	"github.com/containerd/plugin"
	"github.com/containerd/plugin/registry"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/selinux/go-selinux"

	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/internal/dmverity"
	"github.com/containerd/containerd/v2/internal/fsmount"
	"github.com/containerd/containerd/v2/internal/kmutex"
	"github.com/containerd/containerd/v2/plugins"
	"github.com/containerd/errdefs"

	"golang.org/x/sys/unix"
)

var (
	forceloop                 bool
	signedDmverityDeviceLocks = kmutex.New()
)

const (
	signedDmverityDeviceNamePrefix = "containerd-erofs-signed-"
	maxDmveritySignatureSize       = 4 * 1024 * 1024
	defaultSharedLayerContext      = "system_u:object_r:container_file_t:s0"
	selinuxContextOpt              = "context="
)

type erofsMountHandler struct{}

// NewErofsMountHandler creates a new EROFS mount handler that supports dm-verity
func NewErofsMountHandler() mount.Handler {
	return &erofsMountHandler{}
}

// Signed EROFS mounts reuse one mapper, so every consumer must use the same
// superblock context. The per-container overlay retains its MCS label.
func erofsMountOptions(opts []string, signedDmverity, selinuxEnabled bool) []string {
	filtered := make([]string, 0, len(opts)+1)
	for _, value := range opts {
		if value == "loop" ||
			strings.HasPrefix(value, dmverity.MountOptionModePrefix) ||
			strings.HasPrefix(value, dmverity.MountOptionRootHashPrefix) ||
			strings.HasPrefix(value, dmverity.MountOptionSignatureDigestPrefix) {
			continue
		}
		if signedDmverity && strings.HasPrefix(value, selinuxContextOpt) {
			continue
		}
		filtered = append(filtered, value)
	}
	if signedDmverity && selinuxEnabled {
		filtered = append(filtered, selinuxContextOpt+defaultSharedLayerContext)
	}
	return filtered
}

func (h *erofsMountHandler) Mount(ctx context.Context, m mount.Mount, mp string, _ []mount.ActiveMount) (_ mount.ActiveMount, retErr error) {
	if m.Type != "erofs" {
		return mount.ActiveMount{}, errdefs.ErrNotImplemented
	}

	var (
		metadataPath            string
		metadataOptionSeen      bool
		duplicateMetadataOption bool
		expectedRootHash        string
		rootHashOptionSeen      bool
		expectedSignatureDigest string
		signatureOptionSeen     bool
	)
	for _, opt := range m.Options {
		if value, ok := strings.CutPrefix(opt, dmverity.MountOptionRootHashPrefix); ok {
			if rootHashOptionSeen {
				return mount.ActiveMount{}, fmt.Errorf("duplicate expected dm-verity root hash for layer %q", m.Source)
			}
			rootHashOptionSeen = true
			expectedRootHash = value
			continue
		}
		if value, ok := strings.CutPrefix(opt, dmverity.MountOptionSignatureDigestPrefix); ok {
			if signatureOptionSeen {
				return mount.ActiveMount{}, fmt.Errorf("duplicate expected dm-verity signature digest for layer %q", m.Source)
			}
			signatureOptionSeen = true
			expectedSignatureDigest = value
			continue
		}
		if path, ok := strings.CutPrefix(opt, dmverity.MountOptionModePrefix); ok {
			if metadataOptionSeen {
				duplicateMetadataOption = true
				continue
			}
			metadataOptionSeen = true
			metadataPath = path
		}
	}
	signedDmverity := rootHashOptionSeen || signatureOptionSeen
	if signedDmverity &&
		(!rootHashOptionSeen || !signatureOptionSeen ||
			expectedRootHash == "" || expectedSignatureDigest == "" ||
			!metadataOptionSeen || duplicateMetadataOption || metadataPath == "") {
		return mount.ActiveMount{}, fmt.Errorf("incomplete expected dm-verity materialization for layer %q", m.Source)
	}

	// Set up dm-verity device if metadata path is provided
	if metadataPath != "" {
		log.G(ctx).WithFields(log.Fields{
			"source":        m.Source,
			"metadata-path": metadataPath,
		}).Debug("setting up dm-verity device from mount option")

		metadata, err := dmverity.ReadMetadata(metadataPath)
		if err != nil {
			return mount.ActiveMount{}, fmt.Errorf("failed to read dm-verity metadata from %s: %w", metadataPath, err)
		}
		if expectedRootHash != "" && metadata.RootHash != expectedRootHash {
			return mount.ActiveMount{}, fmt.Errorf(
				"layer %q dm-verity root hash %q does not match expected root hash %q",
				m.Source,
				metadata.RootHash,
				expectedRootHash,
			)
		}

		var devicePath, cleanupName string
		if signedDmverity {
			snapshotID := filepath.Base(filepath.Dir(filepath.Clean(m.Source)))
			materializationID := digest.FromString(expectedRootHash + "\x00" + expectedSignatureDigest).Encoded()[:32]
			deviceName := signedDmverityDeviceNamePrefix + snapshotID + "-" + materializationID
			if err := signedDmverityDeviceLocks.Lock(ctx, deviceName); err != nil {
				return mount.ActiveMount{}, fmt.Errorf("lock dm-verity device %q: %w", deviceName, err)
			}
			defer signedDmverityDeviceLocks.Unlock(deviceName)
			devicePath, cleanupName, err = setupSignedDmVerityDevice(ctx, m.Source, deviceName, metadata, expectedSignatureDigest)
		} else {
			devicePath, cleanupName, err = setupDmVerityDevice(ctx, m.Source, metadata)
		}
		if cleanupName != "" {
			defer func() {
				if retErr != nil {
					dmverity.Close(cleanupName)
				}
			}()
		}
		if err != nil {
			return mount.ActiveMount{}, err
		}
		m.Source = devicePath
	}

	m.Options = erofsMountOptions(m.Options, signedDmverity, selinux.GetEnabled())

	if err := os.MkdirAll(mp, 0700); err != nil {
		return mount.ActiveMount{}, err
	}

	err := error(unix.ENOTBLK)
	if !forceloop || signedDmverity {
		// Try to use file-backed mount feature if available (Linux 6.12+) first
		err = doMount(m, mp)
	}
	if errors.Is(err, unix.ENOTBLK) && !signedDmverity {
		var loops []*os.File

		// Never try to mount with raw files anymore if tried
		forceloop = true
		params := mount.LoopParams{
			Readonly:  true,
			Autoclear: true,
		}
		// set up all loop devices
		loop, err := mount.SetupLoop(m.Source, params)
		if err != nil {
			return mount.ActiveMount{}, err
		}
		m.Source = loop.Name()
		loops = append(loops, loop)
		defer func() {
			for _, loop := range loops {
				loop.Close()
			}
		}()

		for i, v := range m.Options {
			// Convert raw files in `device=` into loop devices too
			if after, ok := strings.CutPrefix(v, "device="); ok {
				loop, err := mount.SetupLoop(after, params)
				if err != nil {
					return mount.ActiveMount{}, err
				}
				m.Options[i] = "device=" + loop.Name()
				loops = append(loops, loop)
			}
		}
		err = doMount(m, mp)
		if err != nil {
			return mount.ActiveMount{}, err
		}
	} else if err != nil {
		return mount.ActiveMount{}, err
	}

	t := time.Now()
	return mount.ActiveMount{
		Mount:      m,
		MountedAt:  &t,
		MountPoint: mp,
	}, nil
}

// setupDmVerityDevice creates or reuses a dm-verity device for the given EROFS source.
// It returns the device path to mount from, and a cleanup name (non-empty only when
// a new device was created, so the caller can close it on error).
func setupDmVerityDevice(ctx context.Context, source string, metadata *dmverity.DmverityMetadata) (devicePath string, cleanupName string, err error) {
	supported, err := dmverity.IsSupported()
	if err != nil || !supported {
		return "", "", fmt.Errorf("layer requires dm-verity but system doesn't support it (dm_verity module not loaded): %w", err)
	}

	// Extract snapshot ID from source path
	// Path format: {root}/snapshots/{id}/layer.erofs
	snapshotID := filepath.Base(filepath.Dir(source))
	deviceName := fmt.Sprintf("containerd-erofs-%s", snapshotID)
	devicePath = dmverity.DevicePath(deviceName)

	log.G(ctx).WithFields(log.Fields{
		"source":      source,
		"device-name": deviceName,
		"hash-offset": metadata.HashOffset,
	}).Debug("opening dm-verity device")

	// Try to create dm-verity device first (avoids TOCTOU race)
	_, err = dmverity.Open(source, deviceName, source, metadata.RootHash, metadata.HashOffset, nil)
	if err == nil {
		// New device created — wait for it to appear and return cleanupName
		// so the caller can close it on error.
		if waitErr := waitForDevice(devicePath); waitErr != nil {
			return "", deviceName, waitErr
		}
		log.G(ctx).WithField("device", devicePath).Debug("dm-verity device created successfully")
		return devicePath, deviceName, nil
	}

	// Open failed — check if the device already exists and can be reused.
	if _, statErr := os.Stat(devicePath); statErr != nil {
		return "", "", fmt.Errorf("failed to open dm-verity device: %w", err)
	}

	if verifyErr := dmverity.VerifyDevice(deviceName, metadata.RootHash); verifyErr != nil {
		return "", "", fmt.Errorf("existing dm-verity device %q verification failed: %w", deviceName, verifyErr)
	}

	log.G(ctx).WithField("device", devicePath).Debug("dm-verity device already exists and verified, reusing")
	return devicePath, "", nil
}

// setupSignedDmVerityDevice creates or reuses one signed mapper for a layer.
// The caller holds its lifecycle lock until the mapper is mounted or rolled back.
func setupSignedDmVerityDevice(ctx context.Context, source, deviceName string, metadata *dmverity.DmverityMetadata, expectedSignatureDigest string) (devicePath string, cleanupName string, err error) {
	supported, err := dmverity.IsSupported()
	if err != nil || !supported {
		return "", "", fmt.Errorf("layer requires dm-verity but system doesn't support it (dm_verity module not loaded): %w", err)
	}

	devicePath = dmverity.DevicePath(deviceName)
	hashDevice := dmverity.ResolveHashDevice(source, metadata)
	signature, err := loadValidatedDmveritySignature(source, expectedSignatureDigest)
	if err != nil {
		return "", "", err
	}

	if _, statErr := os.Stat(devicePath); statErr == nil {
		if verifyErr := dmverity.VerifySignedDevice(deviceName, metadata.RootHash); verifyErr != nil {
			return "", "", fmt.Errorf("existing signed dm-verity device %q verification failed: %w", deviceName, verifyErr)
		}
		log.G(ctx).WithField("device", devicePath).Debug("signed dm-verity device already exists and is verified, reusing")
		return devicePath, "", nil
	} else if !os.IsNotExist(statErr) {
		return "", "", fmt.Errorf("inspect dm-verity device %q: %w", deviceName, statErr)
	}

	if _, err := dmverity.OpenSigned(source, deviceName, hashDevice, metadata.RootHash, metadata.HashOffset, signature); err != nil {
		return "", "", fmt.Errorf("failed to open signed dm-verity device: %w", err)
	}
	if waitErr := waitForDevice(devicePath); waitErr != nil {
		return "", deviceName, waitErr
	}
	log.G(ctx).WithField("device", devicePath).Debug("signed dm-verity device created successfully")
	return devicePath, deviceName, nil
}

func loadValidatedDmveritySignature(source, expectedDigest string) ([]byte, error) {
	signatureFile := dmverity.SignaturePath(source)
	file, err := os.Open(signatureFile)
	if err != nil {
		return nil, fmt.Errorf("layer %q has dm-verity metadata but no usable signature: %w", source, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect dm-verity signature %q: %w", signatureFile, err)
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return nil, fmt.Errorf("layer %q has dm-verity metadata but signature %q is not a non-empty regular file", source, signatureFile)
	}
	if info.Size() > maxDmveritySignatureSize {
		return nil, fmt.Errorf("layer %q dm-verity signature %q exceeds maximum size %d", source, signatureFile, maxDmveritySignatureSize)
	}
	signature, err := io.ReadAll(io.LimitReader(file, maxDmveritySignatureSize+1))
	if err != nil {
		return nil, fmt.Errorf("read dm-verity signature %q: %w", signatureFile, err)
	}
	if int64(len(signature)) != info.Size() {
		return nil, fmt.Errorf("dm-verity signature %q changed while it was read", signatureFile)
	}
	expected, err := digest.Parse(expectedDigest)
	if err != nil {
		return nil, fmt.Errorf("invalid expected dm-verity signature digest %q: %w", expectedDigest, err)
	}
	if actual := expected.Algorithm().FromBytes(signature); actual != expected {
		return nil, fmt.Errorf("dm-verity signature %q digest %s does not match expected digest %s", signatureFile, actual, expected)
	}
	return signature, nil
}

// waitForDevice polls for the device node to appear, returning an error if it
// does not appear within a reasonable timeout.
func waitForDevice(devicePath string) error {
	for range 100 {
		if _, err := os.Stat(devicePath); err == nil {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := os.Stat(devicePath); err != nil {
		return fmt.Errorf("dm-verity device %q not found after creation: %w", devicePath, err)
	}
	return nil
}

func doMount(m mount.Mount, target string) error {
	if err := fsmount.Fsmount(m, target); err != nil {
		// Fall back to traditional mount() if fsmount syscall not available (Linux < 5.2)
		if errors.Is(err, unix.ENOSYS) {
			log.L.WithError(err).Debug("fsmount not available, falling back to traditional mount")
			return m.Mount(target)
		}
		return err
	}
	return nil
}

func (h *erofsMountHandler) Unmount(ctx context.Context, path string) error {
	// Check what's currently mounted to determine if dm-verity device cleanup is needed
	var (
		deviceName     string
		signedDmverity bool
	)
	mountInfo, err := mount.Lookup(path)
	if err == nil {
		source := mountInfo.Source
		if strings.HasPrefix(source, "/dev/mapper/containerd-erofs-") {
			deviceName = strings.TrimPrefix(source, "/dev/mapper/")
			signedDmverity = strings.HasPrefix(source, dmverity.DevicePath(signedDmverityDeviceNamePrefix))
		}
	}

	if signedDmverity {
		if err := signedDmverityDeviceLocks.Lock(context.WithoutCancel(ctx), deviceName); err != nil {
			return fmt.Errorf("lock dm-verity device %q: %w", deviceName, err)
		}
		defer signedDmverityDeviceLocks.Unlock(deviceName)
	}

	err = mount.Unmount(path, 0)
	if signedDmverity && err != nil {
		return err
	}

	if deviceName != "" {
		log.G(ctx).WithFields(log.Fields{
			"mount-point": path,
			"device":      deviceName,
		}).Debug("attempting to close dm-verity device")

		if closeErr := dmverity.Close(deviceName); closeErr != nil {
			log.G(ctx).WithError(closeErr).WithField("device", deviceName).Debug("unable to close dm-verity device")
		} else {
			log.G(ctx).WithField("device", deviceName).Debug("dm-verity device closed successfully")
		}
	}

	return err
}

type Config struct{}

func init() {
	registry.Register(&plugin.Registration{
		Type:   plugins.MountHandlerPlugin,
		ID:     "erofs",
		Config: &Config{},
		InitFn: func(ic *plugin.InitContext) (any, error) {
			p := platforms.DefaultSpec()
			p.OS = runtime.GOOS
			ic.Meta.Platforms = append(ic.Meta.Platforms, p)

			return NewErofsMountHandler(), nil
		},
	})
}
