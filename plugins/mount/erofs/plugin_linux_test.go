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
	"slices"
	"testing"
)

func TestSharedLayerMountOptions(t *testing.T) {
	const shared = `context="` + sharedLayerContext + `"`

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
			name:           "loop and dmverity options are dropped",
			opts:           []string{"ro", "loop", "X-containerd.dmverity=auto"},
			selinuxEnabled: false,
			expected:       []string{"ro"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := sharedLayerMountOptions(tc.opts, tc.selinuxEnabled)
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
		[]string{"ro", "loop", `context="system_u:object_r:container_file_t:s0:c646,c927"`}, true)
	containerPath := sharedLayerMountOptions([]string{"ro", "loop"}, true)
	otherPod := sharedLayerMountOptions(
		[]string{"ro", "loop", `context="system_u:object_r:container_file_t:s0:c154,c335"`}, true)

	if !slices.Equal(taskPath, containerPath) {
		t.Errorf("task path %q and container path %q disagree", taskPath, containerPath)
	}
	if !slices.Equal(taskPath, otherPod) {
		t.Errorf("two pods disagree: %q vs %q", taskPath, otherPod)
	}
}
