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
	"errors"
	"strings"
	"testing"
)

func TestErofsDeviceNameScopesSnapshotterRoot(t *testing.T) {
	first := ErofsDeviceName("/var/lib/containerd/erofs-a/snapshots/42/layer.erofs")
	second := ErofsDeviceName("/var/lib/containerd/erofs-b/snapshots/42/layer.erofs")

	if first == second {
		t.Fatalf("different snapshotter roots produced the same device name %q", first)
	}
	if !strings.HasSuffix(first, "-42") {
		t.Fatalf("device name %q does not preserve snapshot ID", first)
	}
	if !strings.HasPrefix(first, ErofsDeviceNamePrefix) {
		t.Fatalf("device name %q does not use prefix %q", first, ErofsDeviceNamePrefix)
	}
}

func TestDeviceLocksAreKeyed(t *testing.T) {
	unlockFirst, err := LockDevice(context.Background(), "first")
	if err != nil {
		t.Fatal(err)
	}
	defer unlockFirst()

	unlockSecond, err := LockDevice(context.Background(), "second")
	if err != nil {
		t.Fatalf("different device lock contended: %v", err)
	}
	unlockSecond()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := LockDevice(ctx, "first"); !errors.Is(err, context.Canceled) {
		t.Fatalf("same device lock returned %v, want context cancellation", err)
	}
}
