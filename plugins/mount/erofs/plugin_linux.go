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
	"sync"
	"time"

	"github.com/containerd/log"
	"github.com/containerd/platforms"
	"github.com/containerd/plugin"
	"github.com/containerd/plugin/registry"
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
}

// NewErofsMountHandler creates a new EROFS mount handler that supports dm-verity
func NewErofsMountHandler(sharedLayerContext string) mount.Handler {
	if sharedLayerContext == "" {
		sharedLayerContext = defaultSharedLayerContext
	}
	return &erofsMountHandler{sharedLayerContext: sharedLayerContext}
}

// dmverityLifecycleMu serializes the whole lifetime of a shared dm-verity
// mapper: inspect-or-create and the mount that follows it, against unmount and
// the removal that follows that.
//
// Device-mapper names are derived from the snapshot ID, so two concurrent mounts
// of the same layer -- routine when several pods start from one image -- can both
// observe the device as absent and both call into the create path. The loser's
// DM_DEV_CREATE fails because the name is taken, and its cleanup then removes the
// winner's device out from under a live mount.
//
// Covering only create was not enough, and shipped a bug. The kernel refuses
// DM_DEV_REMOVE with EBUSY while any filesystem holds the mapper open, so a
// mapper with live mounts is safe -- but verification does not open it. Between
// the moment the last mount goes away and the moment a new mount(2) lands, the
// open count is zero and removal succeeds. A starting container that has already
// passed its existence check then finds the device gone mid-verify and fails with
// what reads as an integrity error:
//
//	container A: mount.Unmount(path)                 -- open count drops to 0
//	container B: os.Stat(/dev/mapper/...)            -- present
//	container B: DeviceStatus                        -- ActivePresent
//	container A: RemoveDevice                        -- succeeds, nothing has it open
//	container B: TableStatus                         -- ENXIO
//	container B: "refusing to reuse existing dm-verity device ... verification failed"
//
// Widening the guarded section to include the mount(2) closes that gap: B's mount
// either happens before A's removal is allowed to run, in which case the open
// count is non-zero and the kernel returns EBUSY, or after A has fully removed the
// device, in which case B sees it absent and creates it. There is no longer a
// window where the device is visible, unopened, and about to be removed.
//
// The kernel's open count is the authoritative reference count for a shared
// mapper, which is why there is no userspace count here: a userspace count would
// start at zero after a containerd restart while mounts and mappers are still
// live. EBUSY from Close is the expected outcome for a device someone else is
// using, not an error.
//
// One global lock is enough for now. The guarded section is a handful of ioctls
// plus one mount(2), it is taken only by layers that actually carry dm-verity,
// and same-device operations are the ones that must serialize anyway. If mount
// convoying ever shows up in a burst benchmark, shard it per device name -- the
// invariant is per-mapper, not global.
var dmverityLifecycleMu sync.Mutex

// selinuxContextOpt is the superblock-wide SELinux mount option. Unlike
// defcontext=/rootcontext=, it labels the whole superblock, so every mount of a
// given device must agree on its value.
const selinuxContextOpt = "context="

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
		// Skip loop option (handled by loop device setup) and dmverity mode option (already processed)
		if v == "loop" || strings.HasPrefix(v, "X-containerd.dmverity=") {
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
// The caller must hold dmverityLifecycleMu, and must keep holding it until the
// returned device has been mounted or rolled back. Returning while the device is
// merely created is exactly the zero-open window described on the mutex.
func openOrReuseDmverityDevice(ctx context.Context, source, deviceName string, metadata *dmverity.DmverityMetadata) (string, error) {
	signatureFile, err := requiredDmveritySignature(source)
	if err != nil {
		return "", err
	}

	devicePath := dmverity.DevicePath(deviceName)
	if _, err := os.Stat(devicePath); !os.IsNotExist(err) {
		// Device-mapper names are host-global while snapshot IDs are only
		// unique within a snapshotter root, so an existing device of this
		// name is not necessarily this layer. Confirm the live table's root
		// hash before trusting it.
		if err := dmverity.VerifyDevice(deviceName, metadata.RootHash); err != nil {
			return "", fmt.Errorf("refusing to reuse existing dm-verity device %q: %w", deviceName, err)
		}
		log.G(ctx).WithField("device", devicePath).Debug("dm-verity device already exists, reusing")
		return devicePath, nil
	}

	log.G(ctx).WithField("root_hash", metadata.RootHash).Info("Using signature for dm-verity")

	log.G(ctx).WithFields(log.Fields{
		"source":      source,
		"device-name": deviceName,
		"hash-offset": metadata.HashOffset,
	}).Debug("opening dm-verity device")

	hashDevice := dmverity.ResolveHashDevice(source, metadata)
	devicePath, err = dmverity.OpenWithSignature(source, deviceName, hashDevice, metadata.RootHash, metadata.HashOffset, nil, signatureFile)
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

func requiredDmveritySignature(source string) (string, error) {
	signatureFile := dmverity.SignaturePath(source)
	info, err := os.Stat(signatureFile)
	if err != nil {
		return "", fmt.Errorf("layer %q has dm-verity metadata but no usable signature: %w", source, err)
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return "", fmt.Errorf("layer %q has dm-verity metadata but signature %q is not a non-empty regular file", source, signatureFile)
	}
	return signatureFile, nil
}

func (h *erofsMountHandler) Mount(ctx context.Context, m mount.Mount, mp string, _ []mount.ActiveMount) (mount.ActiveMount, error) {
	if m.Type != "erofs" {
		return mount.ActiveMount{}, errdefs.ErrNotImplemented
	}

	var dmverityDevice string

	// Check for dmverity mode in mount options
	dmverityMode := "auto" // default
	for _, opt := range m.Options {
		if strings.HasPrefix(opt, "X-containerd.dmverity=") {
			dmverityMode = strings.TrimPrefix(opt, "X-containerd.dmverity=")
		}
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
		log.G(ctx).WithField("source", m.Source).Debug("detected dm-verity metadata, setting up dm-verity device")

		// Held until Mount returns, so it covers the mount(2) below and every
		// rollback Close on the way out. Deferred inside this block on purpose:
		// a layer with no dm-verity metadata never contends for it.
		dmverityLifecycleMu.Lock()
		defer dmverityLifecycleMu.Unlock()

		supported, err := dmverity.IsSupported()
		if err != nil {
			return mount.ActiveMount{}, fmt.Errorf("layer %q requires dm-verity but support could not be determined: %w", m.Source, err)
		}
		if !supported {
			return mount.ActiveMount{}, fmt.Errorf("layer %q requires dm-verity but the system does not provide it", m.Source)
		}

		// Extract snapshot ID from source path
		// Path format: {root}/snapshots/{id}/layer.erofs
		snapshotID := filepath.Base(filepath.Dir(m.Source))
		deviceName := fmt.Sprintf("containerd-erofs-%s", snapshotID)

		devicePath, err := openOrReuseDmverityDevice(ctx, m.Source, deviceName, metadata)
		if err != nil {
			return mount.ActiveMount{}, err
		}
		dmverityDevice = deviceName

		m.Source = devicePath
	}
	// else: no metadata file, proceed with regular EROFS mount

	m.Options = sharedLayerMountOptions(m.Options, selinux.GetEnabled(), h.sharedLayerContext)

	if err := os.MkdirAll(mp, 0700); err != nil {
		if dmverityDevice != "" {
			dmverity.Close(dmverityDevice)
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
						dmverity.Close(dmverityDevice)
					}
					return mount.ActiveMount{}, err
				}
				m.Options[i] = "device=" + loop.Name()
			}
		}
		err = m.Mount(mp)
		if err != nil {
			if dmverityDevice != "" {
				dmverity.Close(dmverityDevice)
			}
			return mount.ActiveMount{}, err
		}
	} else if err != nil {
		if dmverityDevice != "" {
			dmverity.Close(dmverityDevice)
		}
		return mount.ActiveMount{}, err
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
		if strings.HasPrefix(source, "/dev/mapper/containerd-erofs-") {
			deviceName = strings.TrimPrefix(source, "/dev/mapper/")
		}
	}

	err = mount.Unmount(path, 0)

	if deviceName != "" {
		// Only the removal needs the lock, not the unmount above. The window
		// that caused the bug was a removal landing between another mounter's
		// verify and its mount(2); holding the lock here and across that whole
		// section on the mount side closes it. Once this lock is acquired the
		// competing mounter has either not started (it will then find the
		// device absent and create it) or has already completed its mount(2)
		// (the open count is non-zero and the kernel returns EBUSY). Leaving
		// mount.Unmount outside avoids serialising unmounts for no gain.
		dmverityLifecycleMu.Lock()
		defer dmverityLifecycleMu.Unlock()

		log.G(ctx).WithFields(log.Fields{
			"mount-point": path,
			"device":      deviceName,
		}).Debug("attempting to close dm-verity device")

		// EBUSY here is the normal outcome when another container still has the
		// layer mounted: the kernel's open count is the reference count, and it
		// is refusing to remove a device in use. Debug, not error.
		if closeErr := dmverity.Close(deviceName); closeErr != nil {
			log.G(ctx).WithError(closeErr).WithField("device", deviceName).Debug("unable to close dm-verity device")
		} else {
			log.G(ctx).WithField("device", deviceName).Debug("dm-verity device closed successfully")
		}
	}

	return err
}

type Config struct {
	// SharedLayerContext overrides the SELinux label applied to shared EROFS
	// layer mounts. Empty uses defaultSharedLayerContext.
	SharedLayerContext string `toml:"shared_layer_context"`
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
			return NewErofsMountHandler(cfg.SharedLayerContext), nil
		},
	})
}
