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
	data := testEROFSData(sourceDigest)
	sourceDataPath := filepath.Join(t.TempDir(), "source.erofs")
	sourceTreePath := filepath.Join(t.TempDir(), "source.hashtree")
	require.NoError(t, os.WriteFile(sourceDataPath, data, 0600))
	sourceTree, err := os.OpenFile(sourceTreePath, os.O_CREATE|os.O_RDWR, 0600)
	require.NoError(t, err)
	sourceTree.Close()

	opts := dmverity.DefaultDmverityOptions()
	opts.DataBlockSize = 512
	opts.HashBlockSize = 512
	opts.HashOffset = 512
	opts.UUID = "11111111-1111-1111-1111-111111111111"
	rootHash, err := dmverity.Format(sourceDataPath, sourceTreePath, opts)
	require.NoError(t, err)
	tree, err := os.ReadFile(sourceTreePath)
	require.NoError(t, err)

	cs, err := local.NewStore(t.TempDir())
	require.NoError(t, err)
	erofsDesc := writeTestBlob(t, ctx, cs, data, snapshotters.EROFSArtifactMediaType)
	treeDesc := writeTestBlob(t, ctx, cs, tree, snapshotters.MerkleTreeArtifactMediaType)
	sourceDesc := descriptorWithPrecomputedArtifacts(t, sourceDigest, erofsDesc, treeDesc, rootHash)

	layerBlobPath := filepath.Join(t.TempDir(), "layer.erofs")
	differ := erofsDiff{store: cs, enableDmverity: true}
	used, err := differ.applyPrecomputedArtifacts(ctx, sourceDesc, layerBlobPath)
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
	data := testEROFSData(sourceDigest)
	sourceDataPath := filepath.Join(t.TempDir(), "source.erofs")
	sourceTreePath := filepath.Join(t.TempDir(), "source.hashtree")
	require.NoError(t, os.WriteFile(sourceDataPath, data, 0600))
	require.NoError(t, os.WriteFile(sourceTreePath, nil, 0600))
	opts := dmverity.DefaultDmverityOptions()
	opts.DataBlockSize = 512
	opts.HashBlockSize = 512
	opts.HashOffset = 512
	opts.UUID = "11111111-1111-1111-1111-111111111111"
	_, err := dmverity.Format(sourceDataPath, sourceTreePath, opts)
	require.NoError(t, err)
	tree, err := os.ReadFile(sourceTreePath)
	require.NoError(t, err)

	cs, err := local.NewStore(t.TempDir())
	require.NoError(t, err)
	erofsDesc := writeTestBlob(t, ctx, cs, data, snapshotters.EROFSArtifactMediaType)
	treeDesc := writeTestBlob(t, ctx, cs, tree, snapshotters.MerkleTreeArtifactMediaType)
	sourceDesc := descriptorWithPrecomputedArtifacts(t, sourceDigest, erofsDesc, treeDesc, digest.FromString("wrong root").Hex())

	layerBlobPath := filepath.Join(t.TempDir(), "layer.erofs")
	differ := erofsDiff{store: cs, enableDmverity: true}
	_, err = differ.applyPrecomputedArtifacts(ctx, sourceDesc, layerBlobPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed dm-verity verification")
	_, statErr := os.Stat(layerBlobPath)
	assert.ErrorIs(t, statErr, os.ErrNotExist)
	_, statErr = os.Stat(dmverity.HashDevicePath(layerBlobPath))
	assert.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestApplyPrecomputedArtifactsRejectsSourceLayerSubstitution(t *testing.T) {
	ctx := context.Background()
	artifactSourceDigest := digest.FromString("artifact source layer")
	requestedSourceDigest := digest.FromString("requested source layer")
	data := testEROFSData(artifactSourceDigest)
	sourceDataPath := filepath.Join(t.TempDir(), "source.erofs")
	sourceTreePath := filepath.Join(t.TempDir(), "source.hashtree")
	require.NoError(t, os.WriteFile(sourceDataPath, data, 0600))
	require.NoError(t, os.WriteFile(sourceTreePath, nil, 0600))
	opts := dmverity.DefaultDmverityOptions()
	opts.DataBlockSize = 512
	opts.HashBlockSize = 512
	opts.HashOffset = 512
	opts.UUID = "11111111-1111-1111-1111-111111111111"
	rootHash, err := dmverity.Format(sourceDataPath, sourceTreePath, opts)
	require.NoError(t, err)
	tree, err := os.ReadFile(sourceTreePath)
	require.NoError(t, err)

	cs, err := local.NewStore(t.TempDir())
	require.NoError(t, err)
	erofsDesc := writeTestBlob(t, ctx, cs, data, snapshotters.EROFSArtifactMediaType)
	treeDesc := writeTestBlob(t, ctx, cs, tree, snapshotters.MerkleTreeArtifactMediaType)
	sourceDesc := descriptorWithPrecomputedArtifacts(t, requestedSourceDigest, erofsDesc, treeDesc, rootHash)

	differ := erofsDiff{store: cs, enableDmverity: true}
	_, err = differ.applyPrecomputedArtifacts(ctx, sourceDesc, filepath.Join(t.TempDir(), "layer.erofs"))
	require.ErrorContains(t, err, "does not match expected source-layer UUID")
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

func descriptorWithPrecomputedArtifacts(t *testing.T, sourceDigest digest.Digest, erofsDesc, treeDesc ocispec.Descriptor, rootHash string) ocispec.Descriptor {
	t.Helper()
	encodedEROFSBytes, err := json.Marshal(erofsDesc)
	require.NoError(t, err)
	encodedTreeBytes, err := json.Marshal(treeDesc)
	require.NoError(t, err)
	return ocispec.Descriptor{
		Digest: sourceDigest,
		Annotations: map[string]string{
			snapshotters.TargetLayerEROFSDescriptorLabel:      string(encodedEROFSBytes),
			snapshotters.TargetLayerMerkleTreeDescriptorLabel: string(encodedTreeBytes),
			snapshotters.TargetLayerRootHashLabel:             rootHash,
		},
	}
}

func testEROFSData(sourceDigest digest.Digest) []byte {
	data := bytes.Repeat([]byte("precomputed-erofs-"), 4096)
	binary.LittleEndian.PutUint32(data[erofsSuperOffset:], erofsMagic)
	expectedUUID := uuid.NewSHA1(uuid.NameSpaceURL, []byte("erofs:blobs/"+sourceDigest.String()))
	copy(data[erofsSuperOffset+erofsUUIDOffset:erofsSuperOffset+erofsUUIDEnd], expectedUUID[:])
	return data
}
