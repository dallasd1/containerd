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
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/internal/dmverity"
	"github.com/containerd/containerd/v2/pkg/snapshotters"
	"github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/google/uuid"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplyPrecomputedArtifacts(t *testing.T) {
	ctx := context.Background()
	sourceDigest := digest.FromString("source layer")
	index := testEROFSData(sourceDigest)
	tarData := bytes.Repeat([]byte("source tar payload\n"), 257)
	data := combinedTarIndexData(index, tarData)
	sourceDataPath := filepath.Join(t.TempDir(), "source.erofs")
	sourceTreePath := filepath.Join(t.TempDir(), "source.hashtree")
	require.NoError(t, os.WriteFile(sourceDataPath, data, 0600))
	sourceTree, err := os.OpenFile(sourceTreePath, os.O_CREATE|os.O_RDWR, 0600)
	require.NoError(t, err)
	sourceTree.Close()

	opts := testPrecomputedVerityOptions()
	opts.UUID = "11111111-1111-1111-1111-111111111111"
	rootHash, err := dmverity.Format(sourceDataPath, sourceTreePath, opts)
	require.NoError(t, err)
	tree, err := os.ReadFile(sourceTreePath)
	require.NoError(t, err)

	cs, err := local.NewStore(t.TempDir())
	require.NoError(t, err)
	metadataDesc := writeTestBlob(t, ctx, cs, index, snapshotters.EROFSMetadataArtifactMediaType)
	treeDesc := writeTestBlob(t, ctx, cs, tree, snapshotters.MerkleTreeArtifactMediaType)
	sourceDesc := descriptorWithPrecomputedArtifacts(t, sourceDigest, metadataDesc, treeDesc, rootHash)

	layerBlobPath := filepath.Join(t.TempDir(), "layer.erofs")
	differ := erofsDiff{store: cs, enableDmverity: true}
	used, err := differ.applyPrecomputedArtifacts(ctx, sourceDesc, layerBlobPath, bytes.NewReader(tarData))
	require.NoError(t, err)
	assert.True(t, used)

	gotData, err := os.ReadFile(layerBlobPath)
	require.NoError(t, err)
	assert.Equal(t, data, gotData)
	gotTree, err := os.ReadFile(dmverity.HashDevicePath(layerBlobPath))
	require.NoError(t, err)
	assert.Equal(t, tree, gotTree)
	require.NoError(t, dmverity.VerifyArtifacts(
		layerBlobPath,
		dmverity.HashDevicePath(layerBlobPath),
		rootHash,
		uint32(verityBlockSize),
	))

	metadataBytes, err := os.ReadFile(dmverity.MetadataPath(layerBlobPath))
	require.NoError(t, err)
	var metadata dmverity.DmverityMetadata
	require.NoError(t, json.Unmarshal(metadataBytes, &metadata))
	assert.Equal(t, filepath.Base(dmverity.HashDevicePath(layerBlobPath)), metadata.HashDevice)
	assert.Zero(t, metadata.HashOffset)
	_, err = os.Stat(dmverity.SignaturePath(layerBlobPath))
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestApplyPrecomputedArtifactsRejectsWrongRootHash(t *testing.T) {
	ctx := context.Background()
	sourceDigest := digest.FromString("source layer")
	index := testEROFSData(sourceDigest)
	tarData := []byte("source tar payload")
	data := combinedTarIndexData(index, tarData)
	sourceDataPath := filepath.Join(t.TempDir(), "source.erofs")
	sourceTreePath := filepath.Join(t.TempDir(), "source.hashtree")
	require.NoError(t, os.WriteFile(sourceDataPath, data, 0600))
	require.NoError(t, os.WriteFile(sourceTreePath, nil, 0600))
	opts := testPrecomputedVerityOptions()
	opts.UUID = "11111111-1111-1111-1111-111111111111"
	_, err := dmverity.Format(sourceDataPath, sourceTreePath, opts)
	require.NoError(t, err)
	tree, err := os.ReadFile(sourceTreePath)
	require.NoError(t, err)

	cs, err := local.NewStore(t.TempDir())
	require.NoError(t, err)
	metadataDesc := writeTestBlob(t, ctx, cs, index, snapshotters.EROFSMetadataArtifactMediaType)
	treeDesc := writeTestBlob(t, ctx, cs, tree, snapshotters.MerkleTreeArtifactMediaType)
	sourceDesc := descriptorWithPrecomputedArtifacts(t, sourceDigest, metadataDesc, treeDesc, digest.FromString("wrong root").Hex())

	layerBlobPath := filepath.Join(t.TempDir(), "layer.erofs")
	differ := erofsDiff{store: cs, enableDmverity: true}
	_, err = differ.applyPrecomputedArtifacts(ctx, sourceDesc, layerBlobPath, bytes.NewReader(tarData))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed dm-verity verification")
	_, statErr := os.Stat(layerBlobPath)
	assert.ErrorIs(t, statErr, os.ErrNotExist)
	_, statErr = os.Stat(dmverity.HashDevicePath(layerBlobPath))
	assert.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestApplyPrecomputedArtifactsRejectsOverlongRootHash(t *testing.T) {
	ctx := context.Background()
	sourceDigest := digest.FromString("source layer")
	index := testEROFSData(sourceDigest)
	tarData := []byte("source tar payload")
	data := combinedTarIndexData(index, tarData)
	sourceDataPath := filepath.Join(t.TempDir(), "source.erofs")
	sourceTreePath := filepath.Join(t.TempDir(), "source.hashtree")
	require.NoError(t, os.WriteFile(sourceDataPath, data, 0600))
	require.NoError(t, os.WriteFile(sourceTreePath, nil, 0600))
	opts := testPrecomputedVerityOptions()
	opts.UUID = "11111111-1111-1111-1111-111111111111"
	rootHash, err := dmverity.Format(sourceDataPath, sourceTreePath, opts)
	require.NoError(t, err)
	tree, err := os.ReadFile(sourceTreePath)
	require.NoError(t, err)

	cs, err := local.NewStore(t.TempDir())
	require.NoError(t, err)
	metadataDesc := writeTestBlob(t, ctx, cs, index, snapshotters.EROFSMetadataArtifactMediaType)
	treeDesc := writeTestBlob(t, ctx, cs, tree, snapshotters.MerkleTreeArtifactMediaType)
	sourceDesc := descriptorWithPrecomputedArtifacts(
		t,
		sourceDigest,
		metadataDesc,
		treeDesc,
		rootHash+"00",
	)

	layerBlobPath := filepath.Join(t.TempDir(), "layer.erofs")
	differ := erofsDiff{store: cs, enableDmverity: true}
	_, err = differ.applyPrecomputedArtifacts(
		ctx,
		sourceDesc,
		layerBlobPath,
		bytes.NewReader(tarData),
	)
	require.ErrorContains(t, err, "invalid root hash size")
	for _, path := range []string{
		layerBlobPath,
		dmverity.HashDevicePath(layerBlobPath),
		dmverity.MetadataPath(layerBlobPath),
		dmverity.SignaturePath(layerBlobPath),
	} {
		_, statErr := os.Stat(path)
		assert.ErrorIs(t, statErr, os.ErrNotExist)
	}
}

func TestApplyPrecomputedArtifactsRejectsUnexpectedVerityBlockSize(t *testing.T) {
	ctx := context.Background()
	sourceDigest := digest.FromString("source layer")
	index := testEROFSData(sourceDigest)
	tarData := []byte("source tar payload")
	data := combinedTarIndexData(index, tarData)
	sourceDataPath := filepath.Join(t.TempDir(), "source.erofs")
	sourceTreePath := filepath.Join(t.TempDir(), "source.hashtree")
	require.NoError(t, os.WriteFile(sourceDataPath, data, 0600))
	require.NoError(t, os.WriteFile(sourceTreePath, nil, 0600))
	opts := dmverity.DefaultDmverityOptions()
	opts.DataBlockSize = uint32(deviceAlignment)
	opts.HashBlockSize = uint32(deviceAlignment)
	opts.HashOffset = uint64(deviceAlignment)
	opts.UUID = "11111111-1111-1111-1111-111111111111"
	rootHash, err := dmverity.Format(sourceDataPath, sourceTreePath, opts)
	require.NoError(t, err)
	tree, err := os.ReadFile(sourceTreePath)
	require.NoError(t, err)

	cs, err := local.NewStore(t.TempDir())
	require.NoError(t, err)
	metadataDesc := writeTestBlob(t, ctx, cs, index, snapshotters.EROFSMetadataArtifactMediaType)
	treeDesc := writeTestBlob(t, ctx, cs, tree, snapshotters.MerkleTreeArtifactMediaType)
	sourceDesc := descriptorWithPrecomputedArtifacts(t, sourceDigest, metadataDesc, treeDesc, rootHash)

	differ := erofsDiff{store: cs, enableDmverity: true}
	_, err = differ.applyPrecomputedArtifacts(
		ctx,
		sourceDesc,
		filepath.Join(t.TempDir(), "layer.erofs"),
		bytes.NewReader(tarData),
	)
	require.ErrorContains(t, err, "data block size mismatch")
}

func TestApplyPrecomputedArtifactsRejectsTreeCoveringOnlyPrefix(t *testing.T) {
	ctx := context.Background()
	sourceDigest := digest.FromString("source layer")
	index := testEROFSData(sourceDigest)
	tarData := bytes.Repeat([]byte("source tar payload\n"), 300)
	data := combinedTarIndexData(index, tarData)
	require.Greater(t, len(data), int(verityBlockSize))
	sourceDataPath := filepath.Join(t.TempDir(), "source.erofs")
	sourceTreePath := filepath.Join(t.TempDir(), "source.hashtree")
	require.NoError(t, os.WriteFile(sourceDataPath, data[:verityBlockSize], 0600))
	require.NoError(t, os.WriteFile(sourceTreePath, nil, 0600))
	opts := testPrecomputedVerityOptions()
	opts.UUID = "11111111-1111-1111-1111-111111111111"
	rootHash, err := dmverity.Format(sourceDataPath, sourceTreePath, opts)
	require.NoError(t, err)
	tree, err := os.ReadFile(sourceTreePath)
	require.NoError(t, err)

	cs, err := local.NewStore(t.TempDir())
	require.NoError(t, err)
	metadataDesc := writeTestBlob(t, ctx, cs, index, snapshotters.EROFSMetadataArtifactMediaType)
	treeDesc := writeTestBlob(t, ctx, cs, tree, snapshotters.MerkleTreeArtifactMediaType)
	sourceDesc := descriptorWithPrecomputedArtifacts(t, sourceDigest, metadataDesc, treeDesc, rootHash)

	differ := erofsDiff{store: cs, enableDmverity: true}
	_, err = differ.applyPrecomputedArtifacts(
		ctx,
		sourceDesc,
		filepath.Join(t.TempDir(), "layer.erofs"),
		bytes.NewReader(tarData),
	)
	require.ErrorContains(t, err, "data blocks mismatch")
}

func TestApplyPrecomputedArtifactsRejectsSourceLayerSubstitution(t *testing.T) {
	ctx := context.Background()
	artifactSourceDigest := digest.FromString("artifact source layer")
	requestedSourceDigest := digest.FromString("requested source layer")
	index := testEROFSData(artifactSourceDigest)
	tarData := []byte("source tar payload")
	data := combinedTarIndexData(index, tarData)
	sourceDataPath := filepath.Join(t.TempDir(), "source.erofs")
	sourceTreePath := filepath.Join(t.TempDir(), "source.hashtree")
	require.NoError(t, os.WriteFile(sourceDataPath, data, 0600))
	require.NoError(t, os.WriteFile(sourceTreePath, nil, 0600))
	opts := testPrecomputedVerityOptions()
	opts.UUID = "11111111-1111-1111-1111-111111111111"
	rootHash, err := dmverity.Format(sourceDataPath, sourceTreePath, opts)
	require.NoError(t, err)
	tree, err := os.ReadFile(sourceTreePath)
	require.NoError(t, err)

	cs, err := local.NewStore(t.TempDir())
	require.NoError(t, err)
	metadataDesc := writeTestBlob(t, ctx, cs, index, snapshotters.EROFSMetadataArtifactMediaType)
	treeDesc := writeTestBlob(t, ctx, cs, tree, snapshotters.MerkleTreeArtifactMediaType)
	sourceDesc := descriptorWithPrecomputedArtifacts(t, requestedSourceDigest, metadataDesc, treeDesc, rootHash)

	differ := erofsDiff{store: cs, enableDmverity: true}
	_, err = differ.applyPrecomputedArtifacts(
		ctx,
		sourceDesc,
		filepath.Join(t.TempDir(), "layer.erofs"),
		bytes.NewReader(tarData),
	)
	require.ErrorContains(t, err, "does not match expected source-layer UUID")
}

func TestApplyPrecomputedArtifactsRejectsModifiedSourceTar(t *testing.T) {
	ctx := context.Background()
	sourceDigest := digest.FromString("source layer")
	index := testEROFSData(sourceDigest)
	tarData := []byte("expected source tar payload")
	data := combinedTarIndexData(index, tarData)
	sourceDataPath := filepath.Join(t.TempDir(), "source.erofs")
	sourceTreePath := filepath.Join(t.TempDir(), "source.hashtree")
	require.NoError(t, os.WriteFile(sourceDataPath, data, 0600))
	require.NoError(t, os.WriteFile(sourceTreePath, nil, 0600))
	opts := testPrecomputedVerityOptions()
	opts.UUID = "11111111-1111-1111-1111-111111111111"
	rootHash, err := dmverity.Format(sourceDataPath, sourceTreePath, opts)
	require.NoError(t, err)
	tree, err := os.ReadFile(sourceTreePath)
	require.NoError(t, err)

	cs, err := local.NewStore(t.TempDir())
	require.NoError(t, err)
	metadataDesc := writeTestBlob(t, ctx, cs, index, snapshotters.EROFSMetadataArtifactMediaType)
	treeDesc := writeTestBlob(t, ctx, cs, tree, snapshotters.MerkleTreeArtifactMediaType)
	sourceDesc := descriptorWithPrecomputedArtifacts(t, sourceDigest, metadataDesc, treeDesc, rootHash)

	layerBlobPath := filepath.Join(t.TempDir(), "layer.erofs")
	differ := erofsDiff{store: cs, enableDmverity: true}
	_, err = differ.applyPrecomputedArtifacts(
		ctx,
		sourceDesc,
		layerBlobPath,
		bytes.NewReader([]byte("modified source tar payload")),
	)
	require.ErrorContains(t, err, "failed dm-verity verification")
	_, statErr := os.Stat(layerBlobPath)
	assert.ErrorIs(t, statErr, os.ErrNotExist)
}

func writeTestBlob(t *testing.T, ctx context.Context, cs content.Store, data []byte, mediaType string) ocispec.Descriptor {
	t.Helper()
	desc := ocispec.Descriptor{
		MediaType: mediaType,
		Digest:    digest.FromBytes(data),
		Size:      int64(len(data)),
	}
	require.NoError(t, content.WriteBlob(ctx, cs, "precomputed-"+desc.Digest.Encoded()[:12], bytes.NewReader(data), desc))
	return desc
}

func descriptorWithPrecomputedArtifacts(t *testing.T, sourceDigest digest.Digest, metadataDesc, treeDesc ocispec.Descriptor, rootHash string) ocispec.Descriptor {
	t.Helper()
	encodedMetadataBytes, err := json.Marshal(metadataDesc)
	require.NoError(t, err)
	encodedTreeBytes, err := json.Marshal(treeDesc)
	require.NoError(t, err)
	return ocispec.Descriptor{
		Digest: sourceDigest,
		Annotations: map[string]string{
			snapshotters.TargetLayerEROFSMetadataDescriptorLabel: string(encodedMetadataBytes),
			snapshotters.TargetLayerMerkleTreeDescriptorLabel:    string(encodedTreeBytes),
			snapshotters.TargetLayerRootHashLabel:                rootHash,
		},
	}
}

func combinedTarIndexData(index, tarData []byte) []byte {
	data := append([]byte(nil), index...)
	data = append(data, tarData...)
	if remainder := len(data) % int(deviceAlignment); remainder != 0 {
		data = append(data, make([]byte, int(deviceAlignment)-remainder)...)
	}
	return data
}

func testPrecomputedVerityOptions() *dmverity.DmverityOptions {
	opts := dmverity.DefaultDmverityOptions()
	opts.DataBlockSize = uint32(verityBlockSize)
	opts.HashBlockSize = uint32(verityBlockSize)
	opts.HashOffset = uint64(verityBlockSize)
	return opts
}

func testEROFSData(sourceDigest digest.Digest) []byte {
	// Real mkfs.erofs tar indexes are 512-byte aligned but are not
	// necessarily aligned to the final 4096-byte device boundary.
	data := make([]byte, int(3*tarIndexAlignment))
	binary.LittleEndian.PutUint32(data[erofsSuperOffset:], erofsMagic)
	expectedUUID := uuid.NewSHA1(uuid.NameSpaceURL, []byte("erofs:blobs/"+sourceDigest.String()))
	copy(data[erofsSuperOffset+erofsUUIDOffset:erofsSuperOffset+erofsUUIDEnd], expectedUUID[:])
	return data
}
