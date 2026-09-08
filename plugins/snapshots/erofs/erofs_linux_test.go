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
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	continuityfs "github.com/containerd/continuity/fs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/mount"
	mountmanager "github.com/containerd/containerd/v2/core/mount/manager"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/core/snapshots/storage"
	"github.com/containerd/containerd/v2/core/snapshots/testsuite"
	"github.com/containerd/containerd/v2/internal/dmverity"
	"github.com/containerd/containerd/v2/internal/erofsutils"
	"github.com/containerd/containerd/v2/internal/fsverity"
	"github.com/containerd/containerd/v2/pkg/archive/tartest"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	snpkg "github.com/containerd/containerd/v2/pkg/snapshotters"
	"github.com/containerd/containerd/v2/pkg/testutil"
	"github.com/containerd/containerd/v2/plugins/content/local"
	erofsdiffer "github.com/containerd/containerd/v2/plugins/diff/erofs"
	erofsmount "github.com/containerd/containerd/v2/plugins/mount/erofs"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	testFileContent       = "Hello, this is content for testing the EROFS Snapshotter!"
	testNestedFileContent = "Nested file content"
	testDmverityMetadata  = `{
  "roothash": "fedcba098765432109876543210987654321098765432109876543210987",
  "hashoffset": 4096
}`
)

func newSnapshotter(t *testing.T, opts ...Opt) func(ctx context.Context, root string) (snapshots.Snapshotter, func() error, error) {
	_, err := exec.LookPath("mkfs.erofs")
	if err != nil {
		t.Skipf("could not find mkfs.erofs: %v", err)
	}

	if !findErofs() {
		t.Skip("check for erofs kernel support failed, skipping test")
	}
	return func(ctx context.Context, root string) (snapshots.Snapshotter, func() error, error) {
		snapshotter, err := NewSnapshotter(root, opts...)
		if err != nil {
			return nil, nil, err
		}

		return snapshotter, func() error { return snapshotter.Close() }, nil
	}
}

func testMount(t *testing.T, scratchFile string) error {
	root, err := os.MkdirTemp(t.TempDir(), "")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)

	m := []mount.Mount{
		{
			Type:    "ext4",
			Source:  scratchFile,
			Options: []string{"loop", "direct-io", "sync"},
		},
	}

	if err := mount.All(m, root); err != nil {
		return fmt.Errorf("failed to mount device %s: %w", scratchFile, err)
	}

	if err := os.Remove(filepath.Join(root, "lost+found")); err != nil {
		return err
	}
	if err := os.Mkdir(filepath.Join(root, "work"), 0755); err != nil {
		return err
	}
	if err := os.Mkdir(filepath.Join(root, "upper"), 0755); err != nil {
		return err
	}
	return mount.UnmountAll(root, 0)
}

func TestErofs(t *testing.T) {
	testutil.RequiresRoot(t)
	testsuite.SnapshotterSuite(t, "erofs", newSnapshotter(t))
}

func TestErofsWithQuota(t *testing.T) {
	testutil.RequiresRoot(t)
	testsuite.SnapshotterSuite(t, "erofs", newSnapshotter(t, WithDefaultSize(16*1024*1024)))
}

func TestErofsFsverity(t *testing.T) {
	testutil.RequiresRoot(t)
	ctx := context.Background()

	root := t.TempDir()

	// Skip if fsverity is not supported
	supported, err := fsverity.IsSupported(root)
	if !supported || err != nil {
		t.Skip("fsverity not supported, skipping test")
	}

	// Create snapshotter with fsverity enabled
	s, err := NewSnapshotter(root, WithFsverity())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Create a test snapshot
	key := "test-snapshot"
	mounts, err := s.Prepare(ctx, key, "")
	if err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(root, key)
	if err := os.MkdirAll(target, 0755); err != nil {
		t.Fatal(err)
	}
	if err := mount.All(mounts, target); err != nil {
		t.Fatal(err)
	}
	defer testutil.Unmount(t, target)

	// Write test data
	if err := os.WriteFile(filepath.Join(target, "foo"), []byte("test data"), 0777); err != nil {
		t.Fatal(err)
	}

	// Commit the snapshot
	commitKey := "test-commit"
	if err := s.Commit(ctx, commitKey, key); err != nil {
		t.Fatal(err)
	}

	snap := s.(*snapshotter)

	// Get the internal ID from the snapshotter
	var id string
	if err := snap.ms.WithTransaction(ctx, false, func(ctx context.Context) error {
		id, _, _, err = storage.GetInfo(ctx, commitKey)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	// Verify fsverity is enabled on the EROFS layer

	layerPath := snap.layerBlobPath(id)

	enabled, err := fsverity.IsEnabled(layerPath)
	if err != nil {
		t.Fatalf("Failed to check fsverity status: %v", err)
	}
	if !enabled {
		t.Fatal("Expected fsverity to be enabled on committed layer")
	}

	// Try to modify the layer file directly (should fail)
	if err := os.WriteFile(layerPath, []byte("tampered data"), 0666); err == nil {
		t.Fatal("Expected direct write to fsverity-enabled layer to fail")
	}
}

func TestErofsDifferWithTarIndexMode(t *testing.T) {
	testutil.RequiresRoot(t)
	ctx := context.Background()

	if !findErofs() {
		t.Skip("check for erofs kernel support failed, skipping test")
	}

	// Check if mkfs.erofs supports tar index mode
	supported, err := erofsutils.SupportGenerateFromTar()
	if err != nil || !supported {
		t.Skip("mkfs.erofs does not support tar mode, skipping tar index test")
	}

	tempDir := t.TempDir()

	// Create content store for the differ
	contentStore, err := local.NewStore(filepath.Join(tempDir, "content"))
	if err != nil {
		t.Fatal(err)
	}

	// Create EROFS differ with tar index mode enabled
	differ := erofsdiffer.NewErofsDiffer(contentStore, erofsdiffer.WithTarIndexMode())

	// Create EROFS snapshotter
	snapshotRoot := filepath.Join(tempDir, "snapshots")
	s, err := NewSnapshotter(snapshotRoot)
	require.NoError(t, err)
	t.Cleanup(func() { s.Close() })

	// Create test tar content
	tarReader := createTestTarContent()
	defer tarReader.Close()

	// Read the tar content into a buffer for digest calculation and writing
	tarContent, err := io.ReadAll(tarReader)
	if err != nil {
		t.Fatal(err)
	}

	// Write tar content to content store
	desc := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageLayerGzip,
		Digest:    digest.FromBytes(tarContent),
		Size:      int64(len(tarContent)),
	}

	writer, err := contentStore.Writer(ctx,
		content.WithRef("test-layer"),
		content.WithDescriptor(desc))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := writer.Write(tarContent); err != nil {
		writer.Close()
		t.Fatal(err)
	}

	if err := writer.Commit(ctx, desc.Size, desc.Digest); err != nil {
		writer.Close()
		t.Fatal(err)
	}
	writer.Close()

	// Prepare a snapshot using the snapshotter
	snapshotKey := "test-snapshot"
	mounts, err := s.Prepare(ctx, snapshotKey, "")
	if err != nil {
		t.Fatal(err)
	}

	// Apply the tar content using the EROFS differ with tar index mode
	appliedDesc, err := differ.Apply(ctx, desc, mounts)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Applied layer using EROFS differ with tar index mode:")
	t.Logf("  Original: %s (%d bytes)", desc.Digest, desc.Size)
	t.Logf("  Applied:  %s (%d bytes)", appliedDesc.Digest, appliedDesc.Size)
	t.Logf("  MediaType: %s", appliedDesc.MediaType)

	// Commit the snapshot to finalize the EROFS layer creation
	commitKey := "test-commit"
	if err := s.Commit(ctx, commitKey, snapshotKey); err != nil {
		t.Fatal(err)
	}

	// Get the internal snapshot ID to check the EROFS layer file
	snap := s.(*snapshotter)
	var id string
	if err := snap.ms.WithTransaction(ctx, false, func(ctx context.Context) error {
		id, _, _, err = storage.GetInfo(ctx, commitKey)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	// Verify the EROFS layer file was created
	layerPath := snap.layerBlobPath(id)
	if _, err := os.Stat(layerPath); err != nil {
		t.Fatalf("EROFS layer file should exist: %v", err)
	}

	// Verify the layer file is not empty
	stat, err := os.Stat(layerPath)
	if err != nil {
		t.Fatal(err)
	}
	if stat.Size() == 0 {
		t.Fatal("EROFS layer file should not be empty")
	}

	t.Logf("EROFS layer file created with tar index mode: %s (%d bytes)", layerPath, stat.Size())

	// Create a view to verify the content
	viewKey := "test-view"
	viewMounts, err := s.View(ctx, viewKey, commitKey)
	if err != nil {
		t.Fatal(err)
	}

	viewTarget := filepath.Join(tempDir, viewKey)
	if err := os.MkdirAll(viewTarget, 0755); err != nil {
		t.Fatal(err)
	}
	if err := mount.All(viewMounts, viewTarget); err != nil {
		t.Fatal(err)
	}
	defer testutil.Unmount(t, viewTarget)

	// Verify we can read the original test data
	testData, err := os.ReadFile(filepath.Join(viewTarget, "test-file.txt"))
	if err != nil {
		t.Fatal(err)
	}
	expected := testFileContent
	if string(testData) != expected {
		t.Fatalf("Expected %q, got %q", expected, string(testData))
	}

	// Verify nested file
	nestedData, err := os.ReadFile(filepath.Join(viewTarget, "testdir", "nested.txt"))
	if err != nil {
		t.Fatal(err)
	}
	expectedNested := testNestedFileContent
	if string(nestedData) != expectedNested {
		t.Fatalf("Expected %q, got %q", expectedNested, string(nestedData))
	}

	t.Logf("Successfully verified EROFS Snapshotter using the differ with tar index mode")
}

// Helper function to create test tar content using tartest
func createTestTarContent() io.ReadCloser {
	// Create a tar context with current time for consistency
	tc := tartest.TarContext{}.WithModTime(time.Now())

	// Create the tar with our test files and directories
	tarWriter := tartest.TarAll(
		tc.File("test-file.txt", []byte(testFileContent), 0644),
		tc.Dir("testdir", 0755),
		tc.File("testdir/nested.txt", []byte(testNestedFileContent), 0644),
	)

	// Return the tar as a ReadCloser
	return tartest.TarFromWriterTo(tarWriter)
}

// Helper to create a dm-verity metadata file for testing
func createDmverityMetadata(t *testing.T, layerBlob string) {
	t.Helper()
	metadataPath := layerBlob + ".dmverity"
	err := os.WriteFile(metadataPath, []byte(testDmverityMetadata), 0644)
	require.NoError(t, err)
	signaturePath := dmverity.SignaturePath(layerBlob)
	require.NoError(t, os.WriteFile(signaturePath, []byte("signature"), 0644))
	t.Cleanup(func() {
		os.Remove(metadataPath)
		os.Remove(signaturePath)
	})
}

func signedMaterializationLabels(rootHash string, signature []byte) map[string]string {
	return map[string]string{
		snpkg.DmverityMaterializationVersionLabel:         snpkg.DmverityMaterializationVersion,
		snpkg.DmverityMaterializationStateLabel:           snpkg.DmverityMaterializationStateSigned,
		snpkg.DmverityMaterializationRootHashLabel:        rootHash,
		snpkg.DmverityMaterializationSignatureDigestLabel: digest.FromBytes(signature).String(),
	}
}

// Helper to create a test layer blob file
func createTestLayerBlob(t *testing.T, dir string) string {
	t.Helper()
	layerBlob := filepath.Join(dir, "layer.erofs")
	err := os.WriteFile(layerBlob, []byte{}, 0644)
	require.NoError(t, err)
	return layerBlob
}

// TestCreateErofsMount tests mount creation without dm-verity
func TestCreateErofsMount(t *testing.T) {
	tmpDir := t.TempDir()
	layerBlob := createTestLayerBlob(t, tmpDir)

	s := &snapshotter{
		root:         tmpDir,
		dmverityMode: "off",
	}

	t.Run("creates regular erofs mount", func(t *testing.T) {
		m, err := s.createErofsMount(layerBlob, nil)
		require.NoError(t, err)

		assert.Equal(t, "erofs", m.Type)
		assert.Equal(t, layerBlob, m.Source)
		// No X-containerd.dmverity option needed since no .dmverity metadata exists
		assert.Equal(t, []string{"ro", "loop", "X-containerd.dmverity=off"}, m.Options)
	})

	t.Run("always returns erofs mount type", func(t *testing.T) {
		s.dmverityMode = "on"
		createDmverityMetadata(t, layerBlob)

		m, err := s.createErofsMount(layerBlob, nil)
		require.NoError(t, err)
		// Mount type is always "erofs" - dm-verity detection happens in mount handler
		assert.Equal(t, "erofs", m.Type)
		assert.Equal(t, layerBlob, m.Source)
		assert.Contains(t, m.Options, "ro")
		assert.Contains(t, m.Options, "loop")
	})

	t.Run("mode off skips dm-verity even when metadata exists", func(t *testing.T) {
		metadataFile := layerBlob + ".dmverity"
		metadataContent := `{
  "roothash": "fedcba098765432109876543210987654321098765432109876543210987",
  "hashoffset": 4096
}`
		require.NoError(t, os.WriteFile(metadataFile, []byte(metadataContent), 0644))

		s.dmverityMode = "off"

		m, err := s.createErofsMount(layerBlob, nil)
		require.NoError(t, err)

		assert.Equal(t, "erofs", m.Type)
		assert.Equal(t, layerBlob, m.Source)
		// X-containerd.dmverity=off overrides auto-detection when metadata exists
		assert.Contains(t, m.Options, "X-containerd.dmverity=off")
	})
}

// TestOptionalDmverityUnsignedEndToEnd verifies that enabling dm-verity
// discovery does not materialize or mount dm-verity for an unsigned image.
func TestOptionalDmverityUnsignedEndToEnd(t *testing.T) {
	testutil.RequiresRoot(t)

	t.Run("with regular mode", func(t *testing.T) {
		testOptionalDmverityUnsignedEndToEndWithMode(t, false)
	})

	tarSupported, err := erofsutils.SupportGenerateFromTar()
	if err == nil && tarSupported {
		t.Run("with tar index mode", func(t *testing.T) {
			testOptionalDmverityUnsignedEndToEndWithMode(t, true)
		})
	} else {
		t.Logf("Skipping tar index mode test: mkfs.erofs does not support tar mode")
	}
}

func testOptionalDmverityUnsignedEndToEndWithMode(t *testing.T, useTarIndex bool) {
	ctx := context.Background()
	ctx = namespaces.WithNamespace(ctx, "test")
	tempDir := t.TempDir()

	metadb := filepath.Join(tempDir, "mounts.db")
	db, err := bolt.Open(metadb, 0600, nil)
	require.NoError(t, err)
	defer db.Close()

	mountTargetDir := filepath.Join(tempDir, "mount-manager")
	mgr, err := mountmanager.NewManager(db, mountTargetDir,
		mountmanager.WithMountHandler("erofs", erofsmount.NewErofsMountHandler("")))
	require.NoError(t, err)

	contentStore, err := local.NewStore(filepath.Join(tempDir, "content"))
	require.NoError(t, err)

	var differOpts []erofsdiffer.DifferOpt
	differOpts = append(differOpts, erofsdiffer.WithDmverity())
	if useTarIndex {
		differOpts = append(differOpts, erofsdiffer.WithTarIndexMode())
	}
	differ := erofsdiffer.NewErofsDiffer(contentStore, differOpts...)

	snapshotRoot := filepath.Join(tempDir, "snapshots")
	sn, err := NewSnapshotter(snapshotRoot, WithDmverityMode("auto"))
	require.NoError(t, err)
	defer sn.Close()

	s := sn.(*snapshotter)

	tarReader := createTestTarContent()
	defer tarReader.Close()

	tarContent, err := io.ReadAll(tarReader)
	require.NoError(t, err)

	desc := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageLayerGzip,
		Digest:    digest.FromBytes(tarContent),
		Size:      int64(len(tarContent)),
	}

	writer, err := contentStore.Writer(ctx,
		content.WithRef("test-layer"),
		content.WithDescriptor(desc))
	require.NoError(t, err)

	_, err = writer.Write(tarContent)
	require.NoError(t, err)

	err = writer.Commit(ctx, desc.Size, desc.Digest)
	require.NoError(t, err)
	writer.Close()

	// Prepare snapshot
	snapshotKey := "test-snapshot"
	mounts, err := sn.Prepare(ctx, snapshotKey, "")
	require.NoError(t, err)

	_, err = differ.Apply(ctx, desc, mounts)
	require.NoError(t, err)

	commitKey := "test-commit"
	err = sn.Commit(ctx, commitKey, snapshotKey)
	require.NoError(t, err)

	var snapshotID string
	err = s.ms.WithTransaction(ctx, false, func(ctx context.Context) error {
		var err error
		snapshotID, _, _, err = storage.GetInfo(ctx, commitKey)
		return err
	})
	require.NoError(t, err)

	// The unsigned layer must remain ordinary EROFS even though discovery is
	// enabled.
	layerPath := s.layerBlobPath(snapshotID)
	_, err = os.Stat(dmverity.MetadataPath(layerPath))
	assert.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Stat(dmverity.SignaturePath(layerPath))
	assert.ErrorIs(t, err, os.ErrNotExist)

	viewKey := "test-view"
	viewMounts, err := sn.View(ctx, viewKey, commitKey)
	require.NoError(t, err)

	// The mount handler receives an ordinary EROFS layer.
	require.Len(t, viewMounts, 1)
	assert.Equal(t, "erofs", viewMounts[0].Type)
	assert.Contains(t, viewMounts[0].Options, "ro")
	assert.Contains(t, viewMounts[0].Options, "loop")

	viewTarget := filepath.Join(tempDir, "view-mount")
	require.NoError(t, os.MkdirAll(viewTarget, 0755))

	mountID := "test-view-mount"
	activateInfo, err := mgr.Activate(ctx, mountID, viewMounts)
	require.NoError(t, err)

	// EROFS handler mounts directly, check Active mounts for the actual mount point
	require.Len(t, activateInfo.Active, 1, "should have one active mount from EROFS handler")
	actualMountPoint := activateInfo.Active[0].MountPoint
	require.NotEmpty(t, actualMountPoint, "mount point should be set by EROFS handler")

	testData, err := os.ReadFile(filepath.Join(actualMountPoint, "test-file.txt"))
	require.NoError(t, err, "should be able to read test file from EROFS mount")
	assert.Equal(t, testFileContent, string(testData))

	nestedData, err := os.ReadFile(filepath.Join(actualMountPoint, "testdir", "nested.txt"))
	require.NoError(t, err, "should be able to read nested file from dm-verity mount")
	assert.Equal(t, testNestedFileContent, string(nestedData))

	err = mgr.Deactivate(ctx, mountID)
	require.NoError(t, err)

	err = sn.Remove(ctx, viewKey)
	require.NoError(t, err)

	err = sn.Remove(ctx, commitKey)
	require.NoError(t, err)

	err = s.ms.WithTransaction(ctx, false, func(ctx context.Context) error {
		_, err := storage.GetSnapshot(ctx, commitKey)
		return err
	})
	assert.Error(t, err, "snapshot should be removed from metadata")
}

// TestDmverityModeValidation tests dm-verity mode validation during snapshotter creation
func TestDmverityModeValidation(t *testing.T) {
	testutil.RequiresRoot(t)
	tmpDir := t.TempDir()

	t.Run("rejects invalid dmverity mode", func(t *testing.T) {
		_, err := NewSnapshotter(tmpDir, WithDmverityMode("invalid-mode"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid dmverity_mode")
		assert.Contains(t, err.Error(), `must be "auto", "on", or "off"`)
	})

	t.Run("accepts valid auto mode", func(t *testing.T) {
		root := filepath.Join(tmpDir, "auto")
		s, err := NewSnapshotter(root, WithDmverityMode("auto"))
		require.NoError(t, err)
		assert.NotNil(t, s)
		s.Close()
	})

	t.Run("accepts valid on mode when dm-verity is supported", func(t *testing.T) {
		if err := dmverity.CheckSignatureSupport(); err != nil {
			t.Skip("signed dm-verity mappings not supported, skipping")
		}

		root := filepath.Join(tmpDir, "on")
		s, err := NewSnapshotter(root, WithDmverityMode("on"))
		require.NoError(t, err)
		assert.NotNil(t, s)
		s.Close()
	})

	t.Run("accepts valid off mode", func(t *testing.T) {
		root := filepath.Join(tmpDir, "off")
		s, err := NewSnapshotter(root, WithDmverityMode("off"))
		require.NoError(t, err)
		assert.NotNil(t, s)
		s.Close()
	})

	t.Run("defaults to auto mode when not specified", func(t *testing.T) {
		root := filepath.Join(tmpDir, "default")
		s, err := NewSnapshotter(root)
		require.NoError(t, err)
		snap := s.(*snapshotter)
		assert.Equal(t, "auto", snap.dmverityMode)
		s.Close()
	})
}

func TestParentSnapshotInfos(t *testing.T) {
	ctx := context.Background()
	sn, err := NewSnapshotter(t.TempDir())
	require.NoError(t, err)
	s := sn.(*snapshotter)
	t.Cleanup(func() { require.NoError(t, s.Close()) })

	var snap storage.Snapshot
	var info snapshots.Info
	err = s.ms.WithTransaction(ctx, true, func(ctx context.Context) error {
		if _, err := storage.CreateSnapshot(ctx, snapshots.KindActive, "base-active", ""); err != nil {
			return err
		}
		if _, err := storage.CommitActive(ctx, "base-active", "base", snapshots.Usage{},
			snapshots.WithLabels(map[string]string{"layer": "base"})); err != nil {
			return err
		}
		if _, err := storage.CreateSnapshot(ctx, snapshots.KindActive, "top-active", "base"); err != nil {
			return err
		}
		if _, err := storage.CommitActive(ctx, "top-active", "top", snapshots.Usage{},
			snapshots.WithLabels(map[string]string{"layer": "top"})); err != nil {
			return err
		}
		var err error
		snap, err = storage.CreateSnapshot(ctx, snapshots.KindView, "view", "top")
		if err != nil {
			return err
		}
		_, info, _, err = storage.GetInfo(ctx, "view")
		return err
	})
	require.NoError(t, err)

	infos, err := s.parentSnapshotInfos(ctx, info, snap.ParentIDs)
	require.NoError(t, err)
	require.Len(t, infos, 2)
	assert.Equal(t, "top", infos[0].Labels["layer"])
	assert.Equal(t, "base", infos[1].Labels["layer"])
}

func TestCommitUsageIncludesDmverityArtifacts(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(root, "snapshots"), 0700))
	ms, err := storage.NewMetaStore(filepath.Join(root, "metadata.db"))
	require.NoError(t, err)
	s := &snapshotter{
		root:            root,
		ms:              ms,
		dmverityMode:    "auto",
		defaultWritable: defaultWritableSize,
	}
	t.Cleanup(func() { require.NoError(t, s.Close()) })

	var id string
	err = s.ms.WithTransaction(ctx, true, func(ctx context.Context) error {
		snap, err := storage.CreateSnapshot(ctx, snapshots.KindActive, "active", "")
		if err != nil {
			return err
		}
		id = snap.ID
		return nil
	})
	require.NoError(t, err)

	snapshotDir := filepath.Join(root, "snapshots", id)
	require.NoError(t, os.MkdirAll(snapshotDir, 0700))
	layerBlob := s.layerBlobPath(id)
	artifactPaths := []string{
		layerBlob,
		dmverity.HashDevicePath(layerBlob),
		dmverity.MetadataPath(layerBlob),
		dmverity.SignaturePath(layerBlob),
		dmverity.SignatureRequiredPath(layerBlob),
	}
	for i, artifactPath := range artifactPaths {
		require.NoError(t, os.WriteFile(artifactPath, make([]byte, (i+1)*4096), 0600))
	}
	expected, err := continuityfs.DiskUsage(ctx, artifactPaths...)
	require.NoError(t, err)

	require.NoError(t, s.Commit(ctx, "committed", "active"))
	actual, err := s.Usage(ctx, "committed")
	require.NoError(t, err)
	assert.Equal(t, snapshots.Usage(expected), actual)
}

// TestApplyDmverityPolicy tests the dm-verity policy application logic
func TestApplyDmverityPolicy(t *testing.T) {
	tmpDir := t.TempDir()
	layerBlob := createTestLayerBlob(t, tmpDir)

	t.Run("mode on requires metadata to exist", func(t *testing.T) {
		s := &snapshotter{
			dmverityMode: "on",
		}

		_, err := s.applyDmverityPolicy(layerBlob, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "dm-verity mode is 'on' but .dmverity metadata not found")
	})

	t.Run("mode auto returns empty string when no metadata", func(t *testing.T) {
		s := &snapshotter{
			dmverityMode: "auto",
		}

		opt, err := s.applyDmverityPolicy(layerBlob, nil)
		require.NoError(t, err)
		assert.Empty(t, opt)
	})

	t.Run("mode off returns dmverity=off when metadata exists", func(t *testing.T) {
		createDmverityMetadata(t, layerBlob)

		s := &snapshotter{
			dmverityMode: "off",
		}

		opt, err := s.applyDmverityPolicy(layerBlob, nil)
		require.NoError(t, err)
		assert.Equal(t, "X-containerd.dmverity=off", opt)
	})

	t.Run("mode off ignores malformed metadata", func(t *testing.T) {
		malformedLayer := filepath.Join(tmpDir, "malformed.erofs")
		require.NoError(t, os.WriteFile(dmverity.MetadataPath(malformedLayer), []byte("{"), 0644))

		s := &snapshotter{dmverityMode: "off"}
		opt, err := s.applyDmverityPolicy(malformedLayer, nil)
		require.NoError(t, err)
		assert.Equal(t, "X-containerd.dmverity=off", opt)
	})

	t.Run("mode on returns dmverity=on when metadata exists", func(t *testing.T) {
		createDmverityMetadata(t, layerBlob)

		s := &snapshotter{
			dmverityMode: "on",
		}

		opt, err := s.applyDmverityPolicy(layerBlob, nil)
		require.NoError(t, err)
		assert.Equal(t, "X-containerd.dmverity=on", opt)
	})

	t.Run("mode auto returns empty string when metadata exists", func(t *testing.T) {
		createDmverityMetadata(t, layerBlob)

		s := &snapshotter{
			dmverityMode: "auto",
		}

		opt, err := s.applyDmverityPolicy(layerBlob, nil)
		require.NoError(t, err)
		assert.Empty(t, opt) // auto mode doesn't add explicit option
	})

	t.Run("protected metadata without signature fails closed", func(t *testing.T) {
		metadataPath := dmverity.MetadataPath(layerBlob)
		require.NoError(t, os.WriteFile(metadataPath, []byte(testDmverityMetadata), 0644))
		t.Cleanup(func() { os.Remove(metadataPath) })
		requiredPath := dmverity.SignatureRequiredPath(layerBlob)
		require.NoError(t, os.WriteFile(requiredPath, []byte("1\n"), 0644))
		t.Cleanup(func() { os.Remove(requiredPath) })

		s := &snapshotter{dmverityMode: "auto"}
		_, err := s.applyDmverityPolicy(layerBlob, nil)
		require.ErrorContains(t, err, "no usable signature")
	})

	t.Run("legacy unsigned metadata mounts plain in auto mode", func(t *testing.T) {
		legacyLayer := filepath.Join(tmpDir, "legacy.erofs")
		require.NoError(t, os.WriteFile(dmverity.MetadataPath(legacyLayer), []byte(testDmverityMetadata), 0644))

		s := &snapshotter{dmverityMode: "auto"}
		opt, err := s.applyDmverityPolicy(legacyLayer, nil)
		require.NoError(t, err)
		assert.Equal(t, "X-containerd.dmverity=off", opt)
	})

	t.Run("signature without metadata fails closed", func(t *testing.T) {
		signaturePath := dmverity.SignaturePath(layerBlob)
		require.NoError(t, os.WriteFile(signaturePath, []byte("signature"), 0644))
		t.Cleanup(func() { os.Remove(signaturePath) })

		s := &snapshotter{dmverityMode: "auto"}
		_, err := s.applyDmverityPolicy(layerBlob, nil)
		require.ErrorContains(t, err, "signature state but no metadata")
	})

	t.Run("recorded signed materialization requires sidecars", func(t *testing.T) {
		signedLayer := createTestLayerBlob(t, t.TempDir())
		labels := signedMaterializationLabels("recorded-root", []byte("signature"))

		s := &snapshotter{dmverityMode: "auto"}
		_, err := s.applyDmverityPolicy(signedLayer, labels)
		require.ErrorContains(t, err, "signature state but no metadata")
	})

	t.Run("recorded signed materialization requires signature", func(t *testing.T) {
		signedLayer := createTestLayerBlob(t, t.TempDir())
		require.NoError(t, os.WriteFile(dmverity.MetadataPath(signedLayer), []byte(testDmverityMetadata), 0644))
		labels := signedMaterializationLabels(
			"fedcba098765432109876543210987654321098765432109876543210987",
			[]byte("signature"),
		)

		s := &snapshotter{dmverityMode: "auto"}
		_, err := s.applyDmverityPolicy(signedLayer, labels)
		require.ErrorContains(t, err, "no usable signature")
	})

	t.Run("recorded signed materialization binds root hash", func(t *testing.T) {
		signedLayer := createTestLayerBlob(t, t.TempDir())
		createDmverityMetadata(t, signedLayer)
		labels := signedMaterializationLabels("different-root", []byte("signature"))

		s := &snapshotter{dmverityMode: "auto"}
		_, err := s.applyDmverityPolicy(signedLayer, labels)
		require.ErrorContains(t, err, "does not match recorded root hash")
	})

	t.Run("recorded signed materialization binds signature", func(t *testing.T) {
		signedLayer := createTestLayerBlob(t, t.TempDir())
		createDmverityMetadata(t, signedLayer)
		labels := signedMaterializationLabels(
			"fedcba098765432109876543210987654321098765432109876543210987",
			[]byte("different signature"),
		)

		s := &snapshotter{dmverityMode: "auto"}
		_, err := s.applyDmverityPolicy(signedLayer, labels)
		require.ErrorContains(t, err, "does not match recorded digest")
	})

	t.Run("recorded signed materialization accepts matching sidecars", func(t *testing.T) {
		signedLayer := createTestLayerBlob(t, t.TempDir())
		createDmverityMetadata(t, signedLayer)
		labels := signedMaterializationLabels(
			"fedcba098765432109876543210987654321098765432109876543210987",
			[]byte("signature"),
		)

		s := &snapshotter{dmverityMode: "auto"}
		opt, err := s.applyDmverityPolicy(signedLayer, labels)
		require.NoError(t, err)
		assert.Equal(t, dmverity.MountOptionModePrefix+"on", opt)

		m, err := s.createErofsMount(signedLayer, labels)
		require.NoError(t, err)
		assert.Contains(t, m.Options, dmverity.MountOptionModePrefix+"on")
		assert.Contains(t, m.Options, dmverity.MountOptionRootHashPrefix+labels[snpkg.DmverityMaterializationRootHashLabel])
		assert.Contains(t, m.Options, dmverity.MountOptionSignatureDigestPrefix+labels[snpkg.DmverityMaterializationSignatureDigestLabel])
	})

	t.Run("partial materialization labels fail closed", func(t *testing.T) {
		labels := map[string]string{
			snpkg.DmverityMaterializationVersionLabel: snpkg.DmverityMaterializationVersion,
			snpkg.DmverityMaterializationStateLabel:   snpkg.DmverityMaterializationStateSigned,
		}

		s := &snapshotter{dmverityMode: "auto"}
		_, err := s.applyDmverityPolicy(layerBlob, labels)
		require.ErrorContains(t, err, "missing its dm-verity root hash label")
	})
}
