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
	"github.com/containerd/containerd/v2/plugins"
	"github.com/containerd/errdefs"

	"golang.org/x/sys/unix"
)

var forceloop bool

type erofsMountHandler struct {
	// sharedLayerContext is the SELinux label every EROFS layer mount asks
	// for. Configurable because the value is policy-specific and upstream
	// containerd cannot assume a distro's type names.
	sharedLayerContext string
	retainedDmverity   *retainedDmverityDevices
}

// NewErofsMountHandler creates a new EROFS mount handler that supports dm-verity
func NewErofsMountHandler(sharedLayerContext string) mount.Handler {
	return newErofsMountHandler(sharedLayerContext, 0)
}

func newErofsMountHandler(sharedLayerContext string, dmverityCacheSize int) *erofsMountHandler {
	if sharedLayerContext == "" {
		sharedLayerContext = defaultSharedLayerContext
	}
	return &erofsMountHandler{
		sharedLayerContext: sharedLayerContext,
		retainedDmverity:   newRetainedDmverityDevices(dmverityCacheSize),
	}
}

// selinuxContextOpt is the superblock-wide SELinux mount option. Unlike
// defcontext=/rootcontext=, it labels the whole superblock, so every mount of a
// given device must agree on its value.
const selinuxContextOpt = "context="
const maxDmveritySignatureSize = 4 * 1024 * 1024

// sharedLayerContext is the one SELinux label every EROFS layer mount asks for.
//
// EROFS layers are shared by design: one image layer backs every container
// started from that image. Each consumer is a separate mount-manager
// activation, so the same block device is mounted once per consumer and the
// kernel hands out a single superblock for it. "context=" is a property of that
// superblock, so the first mount fixes it and any later mount that disagrees is
// rejected outright:
//
//	SELinux: mount invalid. Same superblock, different security settings
//	         for (dev dm-31, type erofs)
//
// Two containerd paths reach this handler with different settings, and they
// cannot be reconciled by rewriting what the caller passed:
//
//   - container creation activates the layer with no context= at all;
//   - task creation goes through client.getRootFS, which appends the consuming
//     container's mount label, carrying a per-container MCS category pair.
//
// Normalising the label is therefore not sufficient -- an unlabelled mount and a
// labelled one still disagree no matter how the label is rewritten. The two
// paths have to be made to agree on a single value, so the value is synthesised
// here instead of being derived from whatever the caller happened to supply.
//
// Isolation is unaffected. This label applies to the read-only shared layer
// only; the per-container overlay stacked above it still carries the full MCS
// pair, and that overlay, not the layer, is what the container sees. It is also
// what overlayfs already does -- its lowerdirs sit on disk with a single shared
// type and no categories.
//
// The type below is container_file_t rather than the read-only
// container_ro_file_t: EROFS layers are also consumed through paths that expect
// the standard container file type, and this is the value the deployment is
// validated against. Override shared_layer_context to use a stricter type where
// the local policy grants container domains read access to it.
const defaultSharedLayerContext = "system_u:object_r:container_file_t:s0"

// sharedLayerMountOptions returns opts with the mount-manager bookkeeping
// options removed and the per-consumer SELinux label replaced by the single
// shared-layer label, so that every mount of a given layer requests byte
// identical superblock settings.
//
// context= is dropped rather than rewritten because callers disagree on whether
// to supply one at all; it is then re-added unconditionally so that labelled and
// unlabelled callers converge on the same request. It is only re-added when
// SELinux is enabled, since mount(2) rejects the option outright otherwise.
func sharedLayerMountOptions(opts []string, selinuxEnabled bool, sharedLayerContext string) []string {
	filtered := make([]string, 0, len(opts)+1)
	for _, v := range opts {
		// Skip loop and dm-verity bookkeeping options handled by this plugin.
		if v == "loop" ||
			strings.HasPrefix(v, dmverity.MountOptionModePrefix) ||
			strings.HasPrefix(v, dmverity.MountOptionRootHashPrefix) ||
			strings.HasPrefix(v, dmverity.MountOptionSignatureDigestPrefix) {
			continue
		}
		if strings.HasPrefix(v, selinuxContextOpt) {
			continue
		}
		filtered = append(filtered, v)
	}
	if selinuxEnabled {
		filtered = append(filtered, selinuxContextOpt+`"`+sharedLayerContext+`"`)
	}
	return filtered
}

// openOrReuseDmverityDevice returns the /dev/mapper path for a layer, creating
// the device if it does not already exist and validating it if it does.
//
// The caller must hold the keyed lifecycle lock for deviceName until the
// returned device has been mounted or rolled back. Returning while the device
// is merely created would leave a zero-open window in which another unmount
// could remove it before mount(2).
func openOrReuseDmverityDevice(ctx context.Context, source, deviceName string, metadata *dmverity.DmverityMetadata, expectedSignatureDigest string) (string, error) {
	signature, err := requiredDmveritySignature(source, expectedSignatureDigest)
	if err != nil {
		return "", err
	}

	devicePath := dmverity.DevicePath(deviceName)
	deviceInfo, verifyErr := dmverity.VerifySignedDevice(deviceName, metadata.RootHash)
	if verifyErr == nil {
		// A live verity table is identified by its root hash and the kernel's
		// signature requirement. Different trusted PKCS#7 envelopes over the
		// same root hash produce the same protected block device.
		log.G(ctx).WithField("device", devicePath).Debug("dm-verity device already exists, reusing")
		return devicePath, nil
	}
	if deviceInfo.Exists {
		if deviceInfo.OpenCount != 0 {
			return "", fmt.Errorf("refusing to reuse existing dm-verity device %q: %w", deviceName, verifyErr)
		}
		if err := dmverity.Close(deviceName); err != nil && !errors.Is(err, unix.ENXIO) {
			return "", fmt.Errorf("remove invalid idle dm-verity device %q: %w", deviceName, err)
		}
		log.G(ctx).WithError(verifyErr).WithField("device", devicePath).Warn("recreating invalid idle dm-verity device")
	} else if !errors.Is(verifyErr, unix.ENXIO) && !errors.Is(verifyErr, os.ErrNotExist) {
		return "", fmt.Errorf("inspect existing dm-verity device %q: %w", deviceName, verifyErr)
	}

	log.G(ctx).WithField("root_hash", metadata.RootHash).Info("Using signature for dm-verity")

	log.G(ctx).WithFields(log.Fields{
		"source":      source,
		"device-name": deviceName,
		"hash-offset": metadata.HashOffset,
	}).Debug("opening dm-verity device")

	hashDevice := dmverity.ResolveHashDevice(source, metadata)
	devicePath, err = dmverity.OpenWithSignatureData(source, deviceName, hashDevice, metadata.RootHash, metadata.HashOffset, nil, signature)
	if err != nil {
		return "", fmt.Errorf("failed to open dm-verity device: %w", err)
	}

	// Wait for device to appear
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(devicePath); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Verify device exists
	if _, err := os.Stat(devicePath); err != nil {
		dmverity.Close(deviceName)
		return "", fmt.Errorf("dm-verity device %q not found after creation: %w", devicePath, err)
	}

	log.G(ctx).WithField("device", devicePath).Info("dm-verity device created successfully")
	return devicePath, nil
}

func requiredDmveritySignature(source, expectedDigest string) ([]byte, error) {
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
	if expectedDigest != "" {
		expected, err := digest.Parse(expectedDigest)
		if err != nil {
			return nil, fmt.Errorf("invalid expected dm-verity signature digest %q: %w", expectedDigest, err)
		}
		actual := expected.Algorithm().FromBytes(signature)
		if actual != expected {
			return nil, fmt.Errorf(
				"dm-verity signature %q digest %s does not match expected digest %s",
				signatureFile,
				actual,
				expected,
			)
		}
	}
	return signature, nil
}

func (h *erofsMountHandler) Mount(ctx context.Context, m mount.Mount, mp string, _ []mount.ActiveMount) (mount.ActiveMount, error) {
	if m.Type != "erofs" {
		return mount.ActiveMount{}, errdefs.ErrNotImplemented
	}

	var (
		dmverityDevice string
		dmveritySource string
	)

	// Check for dmverity mode in mount options
	dmverityMode := "auto" // default
	var expectedRootHash string
	var expectedSignatureDigest string
	for _, opt := range m.Options {
		switch {
		case strings.HasPrefix(opt, dmverity.MountOptionModePrefix):
			dmverityMode = strings.TrimPrefix(opt, dmverity.MountOptionModePrefix)
		case strings.HasPrefix(opt, dmverity.MountOptionRootHashPrefix):
			expectedRootHash = strings.TrimPrefix(opt, dmverity.MountOptionRootHashPrefix)
		case strings.HasPrefix(opt, dmverity.MountOptionSignatureDigestPrefix):
			expectedSignatureDigest = strings.TrimPrefix(opt, dmverity.MountOptionSignatureDigestPrefix)
		}
	}
	if (expectedRootHash == "") != (expectedSignatureDigest == "") {
		return mount.ActiveMount{}, fmt.Errorf("incomplete expected dm-verity materialization for layer %q", m.Source)
	}
	if expectedRootHash != "" && dmverityMode != "on" {
		return mount.ActiveMount{}, fmt.Errorf("expected signed dm-verity materialization for layer %q requires mode \"on\"", m.Source)
	}

	// Check if this layer has dm-verity metadata.
	//
	// Absent metadata and unusable metadata are deliberately NOT equivalent. A
	// layer with no .dmverity sidecar is an ordinary EROFS layer and mounts
	// plainly under "auto". A layer whose sidecar is present but truncated,
	// malformed, or missing its root hash is a layer whose integrity we were
	// asked to enforce and cannot -- treating that as "no dm-verity" would let
	// anyone downgrade a protected layer to a plain mount by corrupting one
	// file, so it fails closed.
	var metadata *dmverity.DmverityMetadata
	if dmverityMode != "off" {
		md, err := dmverity.ReadMetadata(m.Source)
		switch {
		case err == nil:
			metadata = md
		case errors.Is(err, os.ErrNotExist):
			if dmverityMode == "on" {
				return mount.ActiveMount{}, fmt.Errorf("dm-verity mode is %q but no metadata found for layer %q", dmverityMode, m.Source)
			}
		default:
			return mount.ActiveMount{}, fmt.Errorf("layer %q has unusable dm-verity metadata: %w", m.Source, err)
		}
	}

	if metadata != nil {
		if expectedRootHash != "" && metadata.RootHash != expectedRootHash {
			return mount.ActiveMount{}, fmt.Errorf(
				"layer %q dm-verity root hash %q does not match expected root hash %q",
				m.Source,
				metadata.RootHash,
				expectedRootHash,
			)
		}
		log.G(ctx).WithField("source", m.Source).Debug("detected dm-verity metadata, setting up dm-verity device")

		supported, err := dmverity.IsSupported()
		if err != nil {
			return mount.ActiveMount{}, fmt.Errorf("layer %q requires dm-verity but support could not be determined: %w", m.Source, err)
		}
		if !supported {
			return mount.ActiveMount{}, fmt.Errorf("layer %q requires dm-verity but the system does not provide it", m.Source)
		}

		deviceName := dmverity.ErofsDeviceName(m.Source)

		// Cache setup is reached only for a protected EROFS layer. Overlayfs
		// and plain EROFS mounts never scan or lock the device-mapper namespace.
		h.retainedDmverity.prepare(ctx, m.Source)
		unlock, err := dmverity.LockDevice(ctx, deviceName)
		if err != nil {
			return mount.ActiveMount{}, fmt.Errorf("lock dm-verity device %q: %w", deviceName, err)
		}
		defer unlock()

		wasRetained := h.retainedDmverity.take(deviceName)

		devicePath, err := openOrReuseDmverityDevice(ctx, m.Source, deviceName, metadata, expectedSignatureDigest)
		if err != nil {
			if wasRetained {
				h.retainedDmverity.closeLocked(ctx, deviceName, "failed retained-device reuse")
			}
			return mount.ActiveMount{}, err
		}
		dmverityDevice = deviceName
		dmveritySource = m.Source

		m.Source = devicePath
	}
	// else: no metadata file, proceed with regular EROFS mount

	m.Options = sharedLayerMountOptions(m.Options, selinux.GetEnabled(), h.sharedLayerContext)

	if err := os.MkdirAll(mp, 0700); err != nil {
		if dmverityDevice != "" {
			h.retainedDmverity.closeLocked(ctx, dmverityDevice, "mount rollback")
		}
		return mount.ActiveMount{}, err
	}

	var err error = unix.ENOTBLK
	if !forceloop {
		// Try to use file-backed mount feature if available (Linux 6.12+) first
		err = m.Mount(mp)
	}
	if errors.Is(err, unix.ENOTBLK) {
		var loops []*os.File

		// Never try to mount with raw files anymore if tried
		forceloop = true
		params := mount.LoopParams{
			Readonly:  true,
			Autoclear: true,
		}
		defer func() {
			for _, loop := range loops {
				loop.Close()
			}
		}()

		// A dm-verity mapper is already a block device and needs no loop. Wrapping
		// it would rewrite m.Source to /dev/loopN, and Unmount identifies the device
		// to tear down from the mount source, so the mapper and the loops it holds
		// would leak on every unmount. This is reachable on any kernel without
		// file-backed EROFS mounts (< 6.12) as soon as one plain EROFS layer has
		// latched forceloop.
		if dmverityDevice == "" {
			// set up all loop devices
			loop, err := mount.SetupLoop(m.Source, params)
			if err != nil {
				return mount.ActiveMount{}, err
			}
			m.Source = loop.Name()
			loops = append(loops, loop)
		}

		for i, v := range m.Options {
			// Convert raw files in `device=` into loop devices too
			if strings.HasPrefix(v, "device=") {
				loop, err := mount.SetupLoop(strings.TrimPrefix(v, "device="), params)
				if err != nil {
					if dmverityDevice != "" {
						h.retainedDmverity.closeLocked(ctx, dmverityDevice, "mount rollback")
					}
					return mount.ActiveMount{}, err
				}
				m.Options[i] = "device=" + loop.Name()
			}
		}
		err = m.Mount(mp)
		if err != nil {
			if dmverityDevice != "" {
				h.retainedDmverity.closeLocked(ctx, dmverityDevice, "mount rollback")
			}
			return mount.ActiveMount{}, err
		}
	} else if err != nil {
		if dmverityDevice != "" {
			h.retainedDmverity.closeLocked(ctx, dmverityDevice, "mount rollback")
		}
		return mount.ActiveMount{}, err
	}

	if dmverityDevice != "" {
		h.retainedDmverity.recordMount(dmverityDevice, dmveritySource)
	}

	t := time.Now()
	return mount.ActiveMount{
		Mount:      m,
		MountedAt:  &t,
		MountPoint: mp,
	}, nil
}

func (h *erofsMountHandler) Unmount(ctx context.Context, path string) error {
	// Check what's currently mounted to determine if dm-verity device cleanup is needed
	var deviceName string
	mountInfo, err := mount.Lookup(path)
	if err == nil {
		source := mountInfo.Source
		devicePathPrefix := dmverity.DevicePath(dmverity.ErofsDeviceNamePrefix)
		if strings.HasPrefix(source, devicePathPrefix) {
			deviceName = strings.TrimPrefix(source, dmverity.DevicePath(""))
		}
	}

	if deviceName == "" {
		return mount.Unmount(path, 0)
	}

	if err := mount.Unmount(path, 0); err != nil {
		return err
	}

	unlock, err := dmverity.LockDevice(context.WithoutCancel(ctx), deviceName)
	if err != nil {
		return fmt.Errorf("lock dm-verity device %q: %w", deviceName, err)
	}

	if !h.retainedDmverity.enabled() {
		h.retainedDmverity.closeLocked(ctx, deviceName, "final unmount")
		unlock()
		return nil
	}

	deviceInfo, inspectErr := dmverity.InspectDevice(deviceName)
	if inspectErr != nil {
		h.retainedDmverity.closeLocked(ctx, deviceName, "uninspectable device after unmount")
		h.retainedDmverity.forgetMount(deviceName)
		unlock()
		return nil
	}
	if deviceInfo.OpenCount != 0 {
		unlock()
		return nil
	}

	source, known := h.retainedDmverity.mountedSource(deviceName)
	if !known {
		if h.retainedDmverity.contains(deviceName) {
			unlock()
			return nil
		}
		h.retainedDmverity.closeLocked(ctx, deviceName, "untracked device after restart")
		unlock()
		return nil
	}
	if _, err := os.Stat(source); err != nil {
		log.G(ctx).WithError(err).WithFields(log.Fields{
			"device": deviceName,
			"source": source,
		}).Warn("not retaining dm-verity device with unavailable backing layer")
		h.retainedDmverity.closeLocked(ctx, deviceName, "removed EROFS layer")
		h.retainedDmverity.forgetMount(deviceName)
		unlock()
		return nil
	}

	evicted := h.retainedDmverity.retain(deviceName, source)
	log.G(ctx).WithFields(log.Fields{
		"mount-point": path,
		"device":      deviceName,
	}).Debug("retained idle dm-verity device")
	unlock()

	h.retainedDmverity.close(context.WithoutCancel(ctx), evicted, "idle cache eviction")
	return nil
}

type Config struct {
	// SharedLayerContext overrides the SELinux label applied to shared EROFS
	// layer mounts. Empty uses defaultSharedLayerContext.
	SharedLayerContext string `toml:"shared_layer_context"`

	// DmverityCacheSize bounds the number of verified, idle dm-verity devices
	// retained for sequential EROFS mounts. Zero disables retention.
	DmverityCacheSize int `toml:"dmverity_cache_size"`
}

func init() {
	registry.Register(&plugin.Registration{
		Type:   plugins.MountHandlerPlugin,
		ID:     "erofs",
		Config: &Config{},
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
			p := platforms.DefaultSpec()
			p.OS = runtime.GOOS
			ic.Meta.Platforms = append(ic.Meta.Platforms, p)

			cfg := ic.Config.(*Config)
			if cfg.DmverityCacheSize < 0 {
				return nil, fmt.Errorf("dmverity_cache_size must not be negative")
			}
			return newErofsMountHandler(cfg.SharedLayerContext, cfg.DmverityCacheSize), nil
		},
	})
}
