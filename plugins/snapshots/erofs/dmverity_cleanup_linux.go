//go:build linux

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
	"os"

	"github.com/containerd/log"

	"github.com/containerd/containerd/v2/internal/dmverity"

	"golang.org/x/sys/unix"
)

func releaseDmverityDevice(ctx context.Context, layerPath string) {
	if _, err := os.Stat(dmverity.MetadataPath(layerPath)); err != nil {
		if os.IsNotExist(err) {
			return
		}
		log.G(ctx).WithError(err).WithField("layer", layerPath).Warn("failed to inspect dm-verity metadata during snapshot removal")
	}

	deviceName := dmverity.ErofsDeviceName(layerPath)
	unlock, err := dmverity.LockDevice(context.WithoutCancel(ctx), deviceName)
	if err != nil {
		log.G(ctx).WithError(err).WithField("device", deviceName).Warn("failed to lock dm-verity device during snapshot removal")
		return
	}
	defer unlock()

	err = dmverity.Close(deviceName)
	switch {
	case err == nil:
		log.G(ctx).WithField("device", deviceName).Debug("closed idle dm-verity device during snapshot removal")
	case errors.Is(err, unix.EBUSY):
		// A running container still owns the backing inode. Its final unmount
		// closes the mapper instead of retaining a now-removed source.
		log.G(ctx).WithField("device", deviceName).Debug("dm-verity device remains active during snapshot removal")
	case errors.Is(err, unix.ENXIO), errors.Is(err, os.ErrNotExist):
	default:
		log.G(ctx).WithError(err).WithField("device", deviceName).Warn("failed to close dm-verity device during snapshot removal")
	}
}
