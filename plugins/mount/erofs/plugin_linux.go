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

	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/internal/dmverity"
	"github.com/containerd/containerd/v2/plugins"
	"github.com/containerd/errdefs"

	"golang.org/x/sys/unix"
)

var forceloop bool

type erofsMountHandler struct{}

// NewErofsMountHandler creates a new EROFS mount handler that supports dm-verity
func NewErofsMountHandler() mount.Handler {
	return &erofsMountHandler{}
}

// dmverityOpenMu serializes the "does this device already exist?" check and the
// creation that follows it.
//
// Device-mapper names are derived from the snapshot ID, so two concurrent mounts
// of the same layer -- routine when several pods start from one image -- can both
// observe the device as absent and both call into the create path. The loser's
// DM_DEV_CREATE fails because the name is taken, and its cleanup then removes the
// winner's device out from under a live mount.
//
// One lock is enough. The guarded section is a handful of ioctls, and the kernel
// already serializes device-mapper creation internally, so there is little
// parallelism to win by sharding this per device name.
var dmverityOpenMu sync.Mutex

// openOrReuseDmverityDevice returns the /dev/mapper path for a layer, creating
// the device if it does not already exist and validating it if it does.
func openOrReuseDmverityDevice(ctx context.Context, source, deviceName string, metadata *dmverity.DmverityMetadata) (string, error) {
	dmverityOpenMu.Lock()
	defer dmverityOpenMu.Unlock()

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

	// Use signature file if it exists (written by the differ during Apply)
	signatureFile := dmverity.SignaturePath(source)
	if _, err := os.Stat(signatureFile); err != nil {
		signatureFile = ""
	} else {
		log.G(ctx).WithField("root_hash", metadata.RootHash).Info("Using signature for dm-verity")
	}

	log.G(ctx).WithFields(log.Fields{
		"source":      source,
		"device-name": deviceName,
		"hash-offset": metadata.HashOffset,
	}).Debug("opening dm-verity device")

	hashDevice := dmverity.ResolveHashDevice(source, metadata)
	devicePath, err := dmverity.OpenWithSignature(source, deviceName, hashDevice, metadata.RootHash, metadata.HashOffset, nil, signatureFile)
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

		supported, err := dmverity.IsSupported()
		if err != nil || !supported {
			return mount.ActiveMount{}, fmt.Errorf("layer requires dm-verity but system doesn't support it (dm_verity module not loaded): %w", err)
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

	filteredOptions := make([]string, 0, len(m.Options))
	for _, v := range m.Options {
		// Skip loop option (handled by loop device setup) and dmverity mode option (already processed)
		if v == "loop" || strings.HasPrefix(v, "X-containerd.dmverity=") {
			continue
		}
		filteredOptions = append(filteredOptions, v)
	}
	m.Options = filteredOptions

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
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
			p := platforms.DefaultSpec()
			p.OS = runtime.GOOS
			ic.Meta.Platforms = append(ic.Meta.Platforms, p)

			return NewErofsMountHandler(), nil
		},
	})
}
