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
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/internal/dmverity"
	"github.com/containerd/containerd/v2/internal/fsmount"
	"github.com/containerd/containerd/v2/pkg/testutil"
	snapshotserofs "github.com/containerd/containerd/v2/plugins/snapshots/erofs"
	"github.com/containerd/go-dmverity/pkg/verity"
	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestMountAuditFallback(t *testing.T) {
	originalForceloop := forceloop.Load()
	t.Cleanup(func() { forceloop.Store(originalForceloop) })
	rejected := fmt.Errorf("load table: %w: %w", verity.ErrSignatureRejected, unix.ENOKEY)
	signatureDigest := digest.FromString("signature").String()

	for _, tc := range []struct {
		name        string
		openErr     error
		enforcing   bool
		inactive    bool
		mountErr    error
		forceLoop   bool
		needsLoop   bool
		enforceLoop bool
		wantErr     error
		wantSources []string
	}{
		{name: "verified signature uses mapper even when loop is forced", forceLoop: true, wantSources: []string{"signed-mapper"}},
		{name: "signed mount failure does not fall back", mountErr: unix.ENOTBLK, wantErr: unix.ENOTBLK, wantSources: []string{"signed-mapper"}},
		{name: "audit mounts existing layer", openErr: rejected, wantSources: []string{"layer.erofs"}},
		{name: "audit can mount through a loop", openErr: rejected, needsLoop: true, wantSources: []string{"layer.erofs", "loop-device"}},
		{name: "enforcing rejects fallback", openErr: rejected, enforcing: true, wantErr: rejected},
		{name: "inactive policy rejects fallback", openErr: rejected, inactive: true, wantErr: rejected},
		{name: "unclassified key error rejects fallback", openErr: unix.ENOKEY, wantErr: unix.ENOKEY},
		{name: "audit stopped before loop mount", openErr: rejected, needsLoop: true, enforceLoop: true, wantErr: rejected, wantSources: []string{"layer.erofs"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			forceloop.Store(tc.forceLoop)
			dir := t.TempDir()
			source := filepath.Join(dir, "layer.erofs")
			require.NoError(t, os.WriteFile(dmverity.MetadataPath(source), []byte(`{"roothash":"abcd"}`), 0600))
			request := mount.Mount{Type: "erofs", Source: source, Options: []string{
				"ro", "loop",
				dmverity.MountOptionMetadataPrefix + dmverity.MetadataPath(source),
				dmverity.MountOptionRootHashPrefix + "abcd",
				dmverity.MountOptionSignatureDigestPrefix + signatureDigest,
			}}

			ipePath := filepath.Join(dir, "ipe")
			policy := filepath.Join(ipePath, "policies", "test-policy")
			require.NoError(t, os.MkdirAll(policy, 0700))
			active := "1"
			if tc.inactive {
				active = "0"
			}
			require.NoError(t, os.WriteFile(filepath.Join(policy, "active"), []byte(active), 0600))
			enforcePath := filepath.Join(ipePath, "enforce")
			mode := "0"
			if tc.enforcing {
				mode = "1"
			}
			require.NoError(t, os.WriteFile(enforcePath, []byte(mode), 0600))

			var signedAttempts int
			setupSigned := func(_ context.Context, gotSource, _, _ string, _ uint64, gotDigest string) (string, string, error) {
				signedAttempts++
				require.Equal(t, source, gotSource)
				require.Equal(t, signatureDigest, gotDigest)
				if tc.openErr != nil {
					return "", "", tc.openErr
				}
				return filepath.Join(dir, "signed-mapper"), "", nil
			}
			setupLoop := func(gotSource string, params mount.LoopParams) (*os.File, error) {
				require.True(t, tc.needsLoop, "unexpected loop setup")
				require.Equal(t, source, gotSource)
				require.True(t, params.Readonly)
				require.True(t, params.Autoclear)
				if tc.enforceLoop {
					require.NoError(t, os.WriteFile(enforcePath, []byte("1"), 0600))
				}
				return os.Create(filepath.Join(dir, "loop-device"))
			}
			var sources []string
			mountFilesystem := func(m mount.Mount, _ string) error {
				sources = append(sources, m.Source)
				require.Equal(t, []string{"ro"}, m.Options)
				if tc.needsLoop && m.Source == source {
					return unix.ENOTBLK
				}
				return tc.mountErr
			}

			activeMount, err := mountErofs(t.Context(), request, filepath.Join(dir, "mount"), ipePath, setupSigned, setupLoop, mountFilesystem)
			require.ErrorIs(t, err, tc.wantErr)
			require.Equal(t, 1, signedAttempts)
			var wantSources []string
			for _, name := range tc.wantSources {
				wantSources = append(wantSources, filepath.Join(dir, name))
			}
			require.Equal(t, wantSources, sources)
			if tc.wantErr == nil {
				require.Equal(t, wantSources[len(wantSources)-1], activeMount.Source)
			}
		})
	}
}

func TestStatMapperNode(t *testing.T) {
	busy := fmt.Errorf("open failed: %w: %w", verity.ErrDeviceCreateBusy, unix.EBUSY)

	for _, tc := range []struct {
		name    string
		openErr error
	}{
		{"new device", nil},
		{"create busy", busy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "mapper-node")
			synctest.Test(t, func(t *testing.T) {
				go func() {
					time.Sleep(25 * time.Millisecond)
					if err := os.WriteFile(path, nil, 0600); err != nil {
						t.Error(err)
					}
				}()
				waited, err := statMapperNode(t.Context(), path, tc.openErr)
				require.NoError(t, err)
				require.True(t, waited)
				waited, err = statMapperNode(t.Context(), path, tc.openErr)
				require.NoError(t, err)
				require.False(t, waited)
			})
		})
	}

	t.Run("missing node has a bounded wait", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing")
		synctest.Test(t, func(t *testing.T) {
			start := time.Now()
			waited, err := statMapperNode(t.Context(), path, busy)
			require.True(t, waited)
			require.ErrorIs(t, err, context.DeadlineExceeded)
			require.ErrorIs(t, err, os.ErrNotExist)
			require.LessOrEqual(t, time.Since(start), time.Second)
		})
	})

	t.Run("caller cancellation ends wait", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing")
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			go func() {
				time.Sleep(25 * time.Millisecond)
				cancel()
			}()
			waited, err := statMapperNode(ctx, path, busy)
			require.True(t, waited)
			require.ErrorIs(t, err, context.Canceled)
		})
	})

	t.Run("other open failures do not wait", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing")
		for _, openErr := range []error{
			fmt.Errorf("load table: %w", unix.EBUSY),
			unix.EACCES,
		} {
			waited, err := statMapperNode(t.Context(), path, openErr)
			require.False(t, waited)
			require.ErrorIs(t, err, os.ErrNotExist)
		}
	})

	t.Run("other stat errors do not wait", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "invalid-link")
		require.NoError(t, os.Symlink(filepath.Base(path), path))
		waited, err := statMapperNode(t.Context(), path, busy)
		require.False(t, waited)
		require.ErrorIs(t, err, unix.ELOOP)
	})
}

func TestReadVerifiedSignature(t *testing.T) {
	for _, tc := range []struct {
		name           string
		data           []byte
		expectedDigest string
		wantErr        string
		missing        bool
	}{
		{name: "selected bytes", data: []byte("signature")},
		{name: "at maximum", data: make([]byte, verity.MaxSignatureSize)},
		{name: "empty", data: nil, wantErr: "cannot be empty"},
		{name: "oversized", data: make([]byte, verity.MaxSignatureSize+1), wantErr: "exceeds maximum size"},
		{name: "missing", wantErr: "open signature file", missing: true},
		{name: "digest mismatch", data: []byte("signature"), expectedDigest: digest.FromString("different signature").String(), wantErr: "does not match signed identity"},
		{name: "invalid digest", data: []byte("signature"), expectedDigest: "invalid", wantErr: "parse dm-verity signature digest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := filepath.Join(t.TempDir(), "layer.erofs")
			if !tc.missing {
				require.NoError(t, os.WriteFile(dmverity.SignaturePath(source), tc.data, 0600))
			}
			expectedDigest := tc.expectedDigest
			if expectedDigest == "" {
				expectedDigest = digest.FromBytes(tc.data).String()
			}
			got, err := dmverity.ReadVerifiedSignature(source, expectedDigest)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				require.NotErrorIs(t, err, verity.ErrSignatureRejected)
				require.Nil(t, got)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.data, got)
		})
	}
}

func TestIPEInAuditMode(t *testing.T) {
	for _, tc := range []struct {
		name        string
		enforce     string
		active      string
		wantAllowed bool
	}{
		{name: "active audit", enforce: "0\n", active: "1\n", wantAllowed: true},
		{name: "enforcing", enforce: "1\n", active: "1\n"},
		{name: "inactive policy", enforce: "0\n", active: "0\n"},
		{name: "no policies", enforce: "0\n"},
		{name: "missing mode", active: "1\n"},
		{name: "unknown mode", enforce: "unexpected\n", active: "1\n"},
		{name: "IPE unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if tc.enforce != "" {
				require.NoError(t, os.WriteFile(filepath.Join(root, "enforce"), []byte(tc.enforce), 0600))
			}
			if tc.active != "" {
				policy := filepath.Join(root, "policies", "test-policy")
				require.NoError(t, os.MkdirAll(policy, 0700))
				require.NoError(t, os.WriteFile(filepath.Join(policy, "active"), []byte(tc.active), 0600))
			}

			require.Equal(t, tc.wantAllowed, ipeInAuditMode(root))
		})
	}
}

// TestFsmountLoopDevice tests fsmount with loop device
func TestFsmountLoopDevice(t *testing.T) {
	testutil.RequiresRoot(t)

	if _, err := exec.LookPath("mkfs.erofs"); err != nil {
		t.Skipf("mkfs.erofs not found: %v", err)
	}

	if !snapshotserofs.FindErofs() {
		t.Skip("erofs kernel support not available")
	}

	if !fsmount.SupportsFsmount() {
		t.Skip("fsmount syscall not available (requires Linux 5.2+)")
	}

	tempDir := t.TempDir()

	layerPath := filepath.Join(tempDir, "test.erofs")
	layerDir := filepath.Join(tempDir, "layer_dir")
	if err := os.MkdirAll(layerDir, 0755); err != nil {
		t.Fatalf("failed to create layer dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(layerDir, "test.txt"), []byte("hello"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	cmd := exec.Command("mkfs.erofs", layerPath, layerDir)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to create erofs image: %v, output: %s", err, output)
	}

	loopFile, err := mount.SetupLoop(layerPath, mount.LoopParams{
		Readonly:  true,
		Autoclear: true,
	})
	if err != nil {
		t.Fatalf("failed to setup loop device: %v", err)
	}
	loopDev := loopFile.Name()
	defer func() {
		loopFile.Close()
		mount.DetachLoopDevice(loopDev)
	}()

	mountPoint := filepath.Join(tempDir, "mnt")
	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		t.Fatalf("failed to create mount point: %v", err)
	}

	m := mount.Mount{
		Type:    "erofs",
		Source:  loopDev,
		Options: []string{"ro"},
	}

	err = fsmount.Fsmount(m, mountPoint)
	if err != nil {
		t.Fatalf("fsmount with loop device failed: %v", err)
	}
	defer mount.Unmount(mountPoint, 0)

	content, err := os.ReadFile(filepath.Join(mountPoint, "test.txt"))
	if err != nil {
		t.Fatalf("failed to read test file: %v", err)
	}
	if string(content) != "hello" {
		t.Fatalf("unexpected content: %s", content)
	}
}

// TestMountOptionsPageSizeLimit tests that when mount options exceed the kernel's
// PAGE_SIZE limit (typically 4KB), the traditional mount() syscall fails but
// fsmount API succeeds.
func TestMountOptionsPageSizeLimit(t *testing.T) {
	testutil.RequiresRoot(t)

	if _, err := exec.LookPath("mkfs.erofs"); err != nil {
		t.Skipf("mkfs.erofs not found: %v", err)
	}

	if !snapshotserofs.FindErofs() {
		t.Skip("erofs kernel support not available")
	}

	if !fsmount.SupportsFsmount() {
		t.Skip("fsmount syscall not available (requires Linux 5.2+)")
	}

	tempDir := t.TempDir()

	layerPath := filepath.Join(tempDir, "test.erofs")
	layerDir := filepath.Join(tempDir, "layer_dir")
	if err := os.MkdirAll(layerDir, 0755); err != nil {
		t.Fatalf("failed to create layer dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(layerDir, "test.txt"), []byte("hello"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	cmd := exec.Command("mkfs.erofs", layerPath, layerDir)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to create erofs image: %v, output: %s", err, output)
	}

	loopFile, err := mount.SetupLoop(layerPath, mount.LoopParams{
		Readonly:  true,
		Autoclear: true,
	})
	if err != nil {
		t.Fatalf("failed to setup loop device: %v", err)
	}
	loopDev := loopFile.Name()
	defer func() {
		loopFile.Close()
		mount.DetachLoopDevice(loopDev)
	}()

	// Build mount options that exceed PAGE_SIZE (4096 bytes)
	options := []string{"ro"}
	var optionsBuilder strings.Builder
	optionsBuilder.WriteString("ro")

	for range 100 {
		fakeDevice := filepath.Join(tempDir, strings.Repeat("x", 50), "fake_device_"+strings.Repeat("0", 10))
		opt := "device=" + fakeDevice
		options = append(options, opt)
		optionsBuilder.WriteString(",")
		optionsBuilder.WriteString(opt)
	}

	optionsLen := optionsBuilder.Len()
	if optionsLen <= 4096 {
		t.Fatalf("Test setup error: options string (%d bytes) should exceed PAGE_SIZE (4096)", optionsLen)
	}

	mountPoint := filepath.Join(tempDir, "mnt")
	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		t.Fatalf("failed to create mount point: %v", err)
	}

	m := mount.Mount{
		Type:    "erofs",
		Source:  loopDev,
		Options: options,
	}

	// Test 1: Traditional mount should fail due to PAGE_SIZE limit
	t.Run("traditional_mount_fails", func(t *testing.T) {
		err := m.Mount(mountPoint)
		if err == nil {
			mount.Unmount(mountPoint, 0)
			t.Fatal("Expected traditional mount to fail due to PAGE_SIZE limit, but it succeeded")
		}
		if !strings.Contains(err.Error(), "mount options is too long") {
			t.Fatalf("Expected 'mount options is too long' error, got: %v", err)
		}
	})

	// Test 2: fsmount should succeed
	t.Run("fsmount_succeeds", func(t *testing.T) {
		simpleMount := mount.Mount{
			Type:    "erofs",
			Source:  loopDev,
			Options: []string{"ro"},
		}

		err := fsmount.Fsmount(simpleMount, mountPoint)
		if err != nil {
			if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
				t.Skipf("fsmount failed due to permission restrictions: %v", err)
			}
			t.Fatalf("fsmount failed: %v", err)
		}

		content, err := os.ReadFile(filepath.Join(mountPoint, "test.txt"))
		if err != nil {
			t.Fatalf("failed to read test file: %v", err)
		}
		if string(content) != "hello" {
			t.Fatalf("unexpected content: %s", content)
		}

		if err := mount.Unmount(mountPoint, 0); err != nil {
			t.Fatalf("failed to unmount: %v", err)
		}
	})

	// Test 3: Verify that fsmount can handle many options without PAGE_SIZE limit
	t.Run("fsmount_many_options", func(t *testing.T) {
		manyOptions := []string{"ro"}
		var builder strings.Builder
		builder.WriteString("ro")

		for range 100 {
			manyOptions = append(manyOptions, "dax=always")
			builder.WriteString(",dax=always")
		}

		manyOptionsMount := mount.Mount{
			Type:    "erofs",
			Source:  loopDev,
			Options: manyOptions,
		}

		err := fsmount.Fsmount(manyOptionsMount, mountPoint)
		if err != nil {
			if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
				t.Skipf("fsmount failed due to permission restrictions: %v", err)
			}
			return
		}

		mount.Unmount(mountPoint, 0)
	})
}
