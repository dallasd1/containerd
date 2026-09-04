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
	"context"
	"crypto/sha256"
	"fmt"
	"path/filepath"

	"github.com/containerd/containerd/v2/internal/kmutex"
)

const ErofsDeviceNamePrefix = "containerd-erofs-"

var deviceLocks = kmutex.New()

// ErofsDevicePrefix scopes device-mapper names to one snapshotter root.
func ErofsDevicePrefix(layerPath string) string {
	root := filepath.Dir(filepath.Dir(filepath.Dir(filepath.Clean(layerPath))))
	sum := sha256.Sum256([]byte(root))
	return fmt.Sprintf("%s%x-", ErofsDeviceNamePrefix, sum[:16])
}

// ErofsDeviceName returns the stable mapper name for an EROFS layer.
func ErofsDeviceName(layerPath string) string {
	snapshotID := filepath.Base(filepath.Dir(filepath.Clean(layerPath)))
	return ErofsDevicePrefix(layerPath) + snapshotID
}

// LockDevice serializes lifecycle operations for one host-global mapper name.
func LockDevice(ctx context.Context, deviceName string) (func(), error) {
	if err := deviceLocks.Lock(ctx, deviceName); err != nil {
		return nil, err
	}
	return func() {
		deviceLocks.Unlock(deviceName)
	}, nil
}
