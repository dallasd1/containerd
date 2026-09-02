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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/internal/dmverity"
	"github.com/opencontainers/go-digest"
)

func TestRequiredDmveritySignature(t *testing.T) {
	layer := filepath.Join(t.TempDir(), "layer.erofs")

	_, err := requiredDmveritySignature(layer, "")
	if err == nil {
		t.Fatal("expected a missing signature to fail")
	}

	signaturePath := dmverity.SignaturePath(layer)
	if err := os.WriteFile(signaturePath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = requiredDmveritySignature(layer, "")
	if err == nil {
		t.Fatal("expected an empty signature to fail")
	}

	if err := os.WriteFile(signaturePath, []byte("signature"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := requiredDmveritySignature(layer, "")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "signature" {
		t.Fatalf("requiredDmveritySignature() = %q, want %q", got, "signature")
	}

	expectedDigest := digest.FromBytes(got).String()
	if _, err := requiredDmveritySignature(layer, expectedDigest); err != nil {
		t.Fatalf("expected matching digest to pass: %v", err)
	}
	if _, err := requiredDmveritySignature(layer, digest.FromString("different").String()); err == nil {
		t.Fatal("expected mismatched signature digest to fail")
	}
}

func TestSharedLayerMountOptions(t *testing.T) {
	const shared = `context="` + defaultSharedLayerContext + `"`

	for _, tc := range []struct {
		name           string
		opts           []string
		selinuxEnabled bool
		expected       []string
	}{
		{
			// The task-creation path: client.getRootFS appends the consuming
			// container's mount label, quoted because the MCS pair contains a
			// comma that would otherwise split into a second mount option.
			name:           "per-container label is replaced by the shared one",
			opts:           []string{"ro", "loop", `context="system_u:object_r:container_file_t:s0:c262,c637"`},
			selinuxEnabled: true,
			expected:       []string{"ro", shared},
		},
		{
			// The container-creation path, which supplies no label at all. This
			// is the case that a rewrite-only fix cannot reconcile.
			name:           "unlabelled mount is given the shared label",
			opts:           []string{"ro", "loop"},
			selinuxEnabled: true,
			expected:       []string{"ro", shared},
		},
		{
			// The two paths above have to end up byte identical, which is the
			// whole point: the kernel compares superblock settings exactly.
			name:           "unquoted label is replaced too",
			opts:           []string{"ro", "context=system_u:object_r:container_file_t:s0:c262,c637"},
			selinuxEnabled: true,
			expected:       []string{"ro", shared},
		},
		{
			name:           "already shared label is preserved",
			opts:           []string{"ro", shared},
			selinuxEnabled: true,
			expected:       []string{"ro", shared},
		},
		{
			// mount(2) rejects context= when SELinux is off, so it must not be
			// synthesised there.
			name:           "no label is added when selinux is disabled",
			opts:           []string{"ro", "loop"},
			selinuxEnabled: false,
			expected:       []string{"ro"},
		},
		{
			name:           "stale label is dropped when selinux is disabled",
			opts:           []string{"ro", `context="system_u:object_r:container_file_t:s0:c1,c2"`},
			selinuxEnabled: false,
			expected:       []string{"ro"},
		},
		{
			// Bookkeeping options consumed earlier in Mount must not reach the
			// kernel.
			name: "loop and dmverity options are dropped",
			opts: []string{
				"ro",
				"loop",
				dmverity.MountOptionModePrefix + "on",
				dmverity.MountOptionRootHashPrefix + strings.Repeat("ab", 32),
				dmverity.MountOptionSignatureDigestPrefix + digest.FromString("signature").String(),
			},
			selinuxEnabled: false,
			expected:       []string{"ro"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := sharedLayerMountOptions(tc.opts, tc.selinuxEnabled, defaultSharedLayerContext)
			if !slices.Equal(got, tc.expected) {
				t.Errorf("sharedLayerMountOptions(%q, %v) = %q, want %q",
					tc.opts, tc.selinuxEnabled, got, tc.expected)
			}
		})
	}
}

// TestSharedLayerMountOptionsConverge is the regression this exists for: the
// labelled and unlabelled callers of the same layer must produce identical
// options, or the kernel rejects the second mount with "Same superblock,
// different security settings" and only one pod per image can start.
func TestSharedLayerMountOptionsConverge(t *testing.T) {
	taskPath := sharedLayerMountOptions(
		[]string{"ro", "loop", `context="system_u:object_r:container_file_t:s0:c646,c927"`}, true, defaultSharedLayerContext)
	containerPath := sharedLayerMountOptions([]string{"ro", "loop"}, true, defaultSharedLayerContext)
	otherPod := sharedLayerMountOptions(
		[]string{"ro", "loop", `context="system_u:object_r:container_file_t:s0:c154,c335"`}, true, defaultSharedLayerContext)

	if !slices.Equal(taskPath, containerPath) {
		t.Errorf("task path %q and container path %q disagree", taskPath, containerPath)
	}
	if !slices.Equal(taskPath, otherPod) {
		t.Errorf("two pods disagree: %q vs %q", taskPath, otherPod)
	}
}

// TestOpenOrReuseDmverityDeviceDoesNotSelfLock guards the reentrancy hazard
// introduced when the lifecycle lock was widened from "guard the create" to
// "guard the whole mount lifecycle".
//
// The keyed lock is taken by Mount above the helper and held until Mount
// returns. It is not reentrant, so the helper must not acquire it again.
//
// This reproduces the caller's contract: acquire the lock, then call the helper.
// The call is expected to fail (there is no such device and no privilege to
// create one); all that matters is that it returns at all.
func TestOpenOrReuseDmverityDeviceDoesNotSelfLock(t *testing.T) {
	const deviceName = "containerd-erofs-selflock-probe-does-not-exist"
	unlock, err := dmverity.LockDevice(context.Background(), deviceName)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Name is deliberately one that cannot exist, so the reuse branch is
		// skipped and the create path is reached without touching real devices.
		_, _ = openOrReuseDmverityDevice(
			context.Background(),
			filepath.Join(t.TempDir(), "layer.erofs"),
			deviceName,
			&dmverity.DmverityMetadata{RootHash: strings.Repeat("00", 32)},
			"",
		)
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("openOrReuseDmverityDevice blocked while the caller held its keyed lifecycle lock: " +
			"it must not lock the mutex itself, the caller already holds it")
	}
}
