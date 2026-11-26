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
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/containerd/go-dmverity/pkg/verity"
	"github.com/containerd/log"
	"github.com/containerd/platforms"
	"github.com/containerd/plugin"
	"github.com/containerd/plugin/registry"
	"github.com/moby/locker"
	"github.com/opencontainers/go-digest"

	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/internal/dmverity"
	"github.com/containerd/containerd/v2/internal/fsmount"
	"github.com/containerd/containerd/v2/plugins"
	"github.com/containerd/errdefs"

	"golang.org/x/sys/unix"
)

var forceloop atomic.Bool

const (
	signedDmverityDeviceNamePrefix = "containerd-erofs-signed-"
	ipeSecurityPath                = "/sys/kernel/security/ipe"
)

// Signed mappers are shared across mount paths and handler instances.
var verityMapperLocks locker.Locker

type erofsMountHandler struct{}

// NewErofsMountHandler creates a new EROFS mount handler that supports dm-verity
func NewErofsMountHandler() mount.Handler {
	return &erofsMountHandler{}
}

func (h *erofsMountHandler) Mount(ctx context.Context, m mount.Mount, mp string, _ []mount.ActiveMount) (mount.ActiveMount, error) {
	return mountErofs(ctx, m, mp, ipeSecurityPath, setupSignedDmVerityDevice, mount.SetupLoop, doMount)
}

func mountErofs(
	ctx context.Context,
	m mount.Mount,
	mp, ipePath string,
	setupSignedDevice func(context.Context, string, string, string, uint64, string) (string, string, error),
	setupLoop func(string, mount.LoopParams) (*os.File, error),
	mountFilesystem func(mount.Mount, string) error,
) (_ mount.ActiveMount, retErr error) {
	if m.Type != "erofs" {
		return mount.ActiveMount{}, errdefs.ErrNotImplemented
	}

	var (
		metadataPath            string
		expectedRootHash        string
		expectedSignatureDigest string
		signedDmverity          bool
		auditRejection          error
	)
	// The EROFS snapshotter supplies the local dm-verity metadata path, root hash
	// and signature digest from snapshot labels that are populated during unpack
	// from the selected OCI referrer.
	for _, opt := range m.Options {
		if path, ok := strings.CutPrefix(opt, dmverity.MountOptionMetadataPrefix); ok {
			metadataPath = path
			continue
		}
		if v, ok := strings.CutPrefix(opt, dmverity.MountOptionRootHashPrefix); ok {
			signedDmverity = true
			expectedRootHash = v
			continue
		}
		if v, ok := strings.CutPrefix(opt, dmverity.MountOptionSignatureDigestPrefix); ok {
			signedDmverity = true
			expectedSignatureDigest = v
			continue
		}
	}
	if signedDmverity &&
		(expectedRootHash == "" || expectedSignatureDigest == "" || metadataPath == "") {
		return mount.ActiveMount{}, fmt.Errorf("incomplete expected dm-verity materialization for layer %q", m.Source)
	}
	if signedDmverity {
		for _, opt := range m.Options {
			// If extra devices are requested, EROFS could read from that file without going through the signed mapper
			if strings.HasPrefix(opt, "device=") {
				return mount.ActiveMount{}, fmt.Errorf("signed dm-verity layer %q does not support extra EROFS devices", m.Source)
			}
		}
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

		var devicePath, cleanupName string
		if signedDmverity {
			deviceName := signedMapperName(m.Source, expectedRootHash, expectedSignatureDigest)
			// A mounted filesystem pins the device; keep teardown out until the
			// mount succeeds or the failed attempt cleans up its own device.
			verityMapperLocks.Lock(deviceName)
			defer verityMapperLocks.Unlock(deviceName)
			devicePath, cleanupName, err = setupSignedDevice(ctx, m.Source, deviceName, expectedRootHash, metadata.HashOffset, expectedSignatureDigest)
			if errors.Is(err, verity.ErrSignatureRejected) && ipeInAuditMode(ipePath) {
				auditRejection = err
				log.G(ctx).WithField("source", m.Source).WithError(err).
					Warn("IPE audit mode: mounting EROFS without dm-verity after signature rejection")
				devicePath, err = m.Source, nil
			}
		} else {
			devicePath, cleanupName, err = setupDmVerityDevice(ctx, m.Source, metadata)
		}
		defer func() {
			if retErr != nil && cleanupName != "" {
				dmverity.Close(cleanupName)
			}
		}()
		if err != nil {
			return mount.ActiveMount{}, err
		}
		m.Source = devicePath
	}

	filteredOptions := make([]string, 0, len(m.Options))
	for _, v := range m.Options {
		// Skip loop option (handled by loop device setup) and dmverity options (already processed)
		if v == "loop" ||
			strings.HasPrefix(v, dmverity.MountOptionMetadataPrefix) ||
			strings.HasPrefix(v, dmverity.MountOptionRootHashPrefix) ||
			strings.HasPrefix(v, dmverity.MountOptionSignatureDigestPrefix) {
			continue
		}
		filteredOptions = append(filteredOptions, v)
	}
	m.Options = filteredOptions

	if err := os.MkdirAll(mp, 0700); err != nil {
		return mount.ActiveMount{}, err
	}

	mountLayer := func() error {
		if auditRejection != nil && !ipeInAuditMode(ipePath) {
			return fmt.Errorf("IPE audit mode no longer confirmed before mount: %w", auditRejection)
		}
		return mountFilesystem(m, mp)
	}

	requiresSignedMapper := signedDmverity && auditRejection == nil
	err := error(unix.ENOTBLK)
	if requiresSignedMapper || !forceloop.Load() {
		// Try to use file-backed mount feature if available (Linux 6.12+) first
		err = mountLayer()
	}
	if errors.Is(err, unix.ENOTBLK) && !requiresSignedMapper {
		var loops []*os.File

		// Never try to mount with raw files anymore if tried
		forceloop.Store(true)
		params := mount.LoopParams{
			Readonly:  true,
			Autoclear: true,
		}
		// set up all loop devices
		loop, err := setupLoop(m.Source, params)
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
				loop, err := setupLoop(after, params)
				if err != nil {
					return mount.ActiveMount{}, err
				}
				m.Options[i] = "device=" + loop.Name()
				loops = append(loops, loop)
			}
		}
		err = mountLayer()
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

// IPE also exposes enforce=0 when no policy is active. Require both.
func ipeInAuditMode(root string) bool {
	policies, err := os.ReadDir(filepath.Join(root, "policies"))
	if err != nil {
		return false
	}
	for _, policy := range policies {
		if !policy.IsDir() {
			continue
		}
		active, err := os.ReadFile(filepath.Join(root, "policies", policy.Name(), "active"))
		if err == nil && strings.TrimSpace(string(active)) == "1" {
			enforce, err := os.ReadFile(filepath.Join(root, "enforce"))
			return err == nil && strings.TrimSpace(string(enforce)) == "0"
		}
	}
	return false
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

func signedMapperName(source, expectedRootHash, expectedSignatureDigest string) string {
	snapshotID := filepath.Base(filepath.Dir(filepath.Clean(source)))
	verityIdentity := digest.FromString(expectedRootHash + "-" + expectedSignatureDigest).Encoded()[:32]
	return signedDmverityDeviceNamePrefix + snapshotID + "-" + verityIdentity
}

// setupSignedDmVerityDevice creates or reuses a signed mapper for a layer.
func setupSignedDmVerityDevice(ctx context.Context, source, deviceName, expectedRootHash string, hashOffset uint64, expectedSignatureDigest string) (devicePath string, cleanupName string, err error) {
	supported, err := dmverity.IsSupported()
	if err != nil || !supported {
		return "", "", fmt.Errorf("layer requires dm-verity but system doesn't support it (dm_verity module not loaded): %w", err)
	}

	devicePath = dmverity.DevicePath(deviceName)
	signature, err := dmverity.ReadVerifiedSignature(source, expectedSignatureDigest)
	if err != nil {
		return "", "", err
	}
	_, err = dmverity.OpenSigned(source, deviceName, source, expectedRootHash, hashOffset, signature)
	if errors.Is(err, verity.ErrSignatureRejected) {
		return "", "", fmt.Errorf("failed to open signed dm-verity device: %w", err)
	}

	waited, statErr := statMapperNode(ctx, devicePath, err)
	if err == nil {
		if statErr != nil {
			return "", deviceName, statErr
		}
		log.G(ctx).WithField("device", devicePath).Debug("dm-verity device created successfully")
		return devicePath, deviceName, nil
	}
	if statErr != nil {
		log.G(ctx).WithField("device", devicePath).WithError(statErr).Debug("dm-verity device unavailable for reuse")
		return "", "", fmt.Errorf("failed to open dm-verity device: %w", err)
	}
	if verifyErr := dmverity.VerifySignedDevice(deviceName, expectedRootHash); verifyErr != nil {
		return "", "", fmt.Errorf("existing dm-verity device %q verification failed: %w", deviceName, verifyErr)
	}
	if waited {
		log.G(ctx).WithField("device", devicePath).Info("dm-verity device appeared after create contention and was verified for reuse")
	}
	log.G(ctx).WithField("device", devicePath).Debug("dm-verity device already exists and is verified, reusing")
	return devicePath, "", nil
}

// statMapperNode waits for a missing node only after a successful or duplicate
// create: the kernel can reserve the mapper name before its node is visible.
// The caller still verifies the mapper's root hash and signing mode before reuse.
func statMapperNode(ctx context.Context, devicePath string, openErr error) (waited bool, err error) {
	_, err = os.Stat(devicePath)
	if !errors.Is(err, os.ErrNotExist) || (openErr != nil && !errors.Is(openErr, verity.ErrDeviceCreateBusy)) {
		return false, err
	}

	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
		case <-ticker.C:
		}
		if ctx.Err() != nil {
			return true, fmt.Errorf("wait for mapper node %q: %w: %w", devicePath, ctx.Err(), err)
		}
		if _, err = os.Stat(devicePath); !errors.Is(err, os.ErrNotExist) {
			return true, err
		}
	}
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
			signedDmverity = strings.HasPrefix(deviceName, signedDmverityDeviceNamePrefix)
		}
	}

	if signedDmverity {
		verityMapperLocks.Lock(deviceName)
		defer verityMapperLocks.Unlock(deviceName)
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
