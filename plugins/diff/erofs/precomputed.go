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
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/internal/dmverity"
	snpkg "github.com/containerd/containerd/v2/pkg/snapshotters"
	"github.com/containerd/log"
	"github.com/google/uuid"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	erofsSuperOffset  = 1024
	erofsMagic        = 0xE0F5E1E2
	erofsUUIDOffset   = 48
	erofsUUIDEnd      = erofsUUIDOffset + 16
	tarIndexAlignment = int64(512)
	deviceAlignment   = int64(4096)
	verityBlockSize   = int64(512)
)

func (s erofsDiff) applyPrecomputedArtifacts(ctx context.Context, sourceDesc ocispec.Descriptor, layerBlobPath string, sourceTar io.Reader) (bool, error) {
	metadataValue := sourceDesc.Annotations[snpkg.TargetLayerEROFSMetadataDescriptorLabel]
	treeValue := sourceDesc.Annotations[snpkg.TargetLayerMerkleTreeDescriptorLabel]
	if metadataValue == "" && treeValue == "" {
		return false, nil
	}
	if !s.enableDmverity {
		// These annotations can arrive straight off the image manifest, with
		// no referrer discovery involved, so a registry must not be able to
		// fail a pull on a node that never opted into dm-verity. Ignore them
		// and convert the tar layer the ordinary way.
		log.G(ctx).WithField("layer", sourceDesc.Digest).
			Debug("ignoring precomputed dm-verity artifacts: dm-verity is disabled")
		return false, nil
	}
	if metadataValue == "" || treeValue == "" {
		return false, fmt.Errorf("incomplete precomputed artifact annotations for layer %s", sourceDesc.Digest)
	}
	metadataDesc, err := snpkg.ParseTargetDescriptor(metadataValue)
	if err != nil {
		return false, err
	}
	if metadataDesc.MediaType != snpkg.EROFSMetadataArtifactMediaType {
		return false, fmt.Errorf("unexpected precomputed EROFS metadata media type %q", metadataDesc.MediaType)
	}
	if metadataDesc.Size%tarIndexAlignment != 0 {
		return false, fmt.Errorf(
			"precomputed EROFS metadata for layer %s has unaligned size %d",
			sourceDesc.Digest,
			metadataDesc.Size,
		)
	}
	treeDesc, err := snpkg.ParseTargetDescriptor(treeValue)
	if err != nil {
		return false, err
	}
	if treeDesc.MediaType != snpkg.MerkleTreeArtifactMediaType {
		return false, fmt.Errorf("unexpected precomputed Merkle-tree media type %q", treeDesc.MediaType)
	}
	rootHash := sourceDesc.Annotations[snpkg.TargetLayerRootHashLabel]
	if rootHash == "" {
		return false, fmt.Errorf("precomputed artifacts missing root hash for layer %s", sourceDesc.Digest)
	}

	hashDevicePath := dmverity.HashDevicePath(layerBlobPath)
	cleanup := true
	defer func() {
		if !cleanup {
			return
		}
		os.Remove(layerBlobPath)
		os.Remove(hashDevicePath)
		os.Remove(dmverity.MetadataPath(layerBlobPath))
		os.Remove(dmverity.SignaturePath(layerBlobPath))
	}()

	if err := copyContentDescriptor(ctx, s.store, metadataDesc, layerBlobPath); err != nil {
		return false, fmt.Errorf("materialize precomputed EROFS metadata for layer %s: %w", sourceDesc.Digest, err)
	}
	if err := appendTarPayload(layerBlobPath, sourceTar); err != nil {
		return false, fmt.Errorf("append source tar for layer %s: %w", sourceDesc.Digest, err)
	}
	if err := verifyEROFSUUID(layerBlobPath, sourceDesc.Digest.String()); err != nil {
		return false, fmt.Errorf("verify precomputed EROFS metadata source binding for layer %s: %w", sourceDesc.Digest, err)
	}
	if err := copyContentDescriptor(ctx, s.store, treeDesc, hashDevicePath); err != nil {
		return false, fmt.Errorf("materialize precomputed Merkle tree for layer %s: %w", sourceDesc.Digest, err)
	}

	if err := dmverity.VerifyArtifacts(
		layerBlobPath,
		hashDevicePath,
		rootHash,
		uint32(verityBlockSize),
	); err != nil {
		return false, fmt.Errorf("precomputed artifacts failed dm-verity verification for layer %s: %w", sourceDesc.Digest, err)
	}
	if err := dmverity.WriteMetadata(layerBlobPath, dmverity.DmverityMetadata{
		RootHash:   rootHash,
		HashOffset: 0,
		HashDevice: filepath.Base(hashDevicePath),
	}); err != nil {
		return false, err
	}
	if err := s.writeLayerSignature(ctx, sourceDesc, layerBlobPath, rootHash); err != nil {
		return false, err
	}

	cleanup = false
	log.G(ctx).WithFields(log.Fields{
		"layer":          sourceDesc.Digest,
		"erofs_metadata": metadataDesc.Digest,
		"merkle_tree":    treeDesc.Digest,
		"root_hash":      rootHash,
	}).Info("Materialized verified precomputed EROFS dm-verity artifacts")
	return true, nil
}

func appendTarPayload(layerBlobPath string, sourceTar io.Reader) (retErr error) {
	if sourceTar == nil {
		return fmt.Errorf("source tar reader is nil")
	}
	file, err := os.OpenFile(layerBlobPath, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := file.Close(); retErr == nil && closeErr != nil {
			retErr = closeErr
		}
	}()

	if _, err := io.Copy(file, sourceTar); err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if remainder := info.Size() % deviceAlignment; remainder != 0 {
		if _, err := file.Write(make([]byte, deviceAlignment-remainder)); err != nil {
			return err
		}
	}
	return file.Sync()
}

func verifyEROFSUUID(path, sourceDigest string) error {
	parsedDigest, err := digest.Parse(sourceDigest)
	if err != nil {
		return fmt.Errorf("invalid source layer digest: %w", err)
	}
	if parsedDigest.String() != sourceDigest {
		return fmt.Errorf("source layer digest is not canonical: %q", sourceDigest)
	}

	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	superblock := make([]byte, erofsUUIDEnd)
	if _, err := file.ReadAt(superblock, erofsSuperOffset); err != nil {
		return fmt.Errorf("read EROFS superblock: %w", err)
	}
	if magic := binary.LittleEndian.Uint32(superblock[:4]); magic != erofsMagic {
		return fmt.Errorf("invalid EROFS superblock magic 0x%x", magic)
	}
	actualUUID, err := uuid.FromBytes(superblock[erofsUUIDOffset:erofsUUIDEnd])
	if err != nil {
		return fmt.Errorf("parse EROFS UUID: %w", err)
	}
	expectedUUID := uuid.NewSHA1(uuid.NameSpaceURL, []byte("erofs:blobs/"+sourceDigest))
	if actualUUID != expectedUUID {
		return fmt.Errorf("EROFS UUID %s does not match expected source-layer UUID %s", actualUUID, expectedUUID)
	}
	return nil
}

func copyContentDescriptor(ctx context.Context, store content.Store, desc ocispec.Descriptor, target string) error {
	ra, err := store.ReaderAt(ctx, desc)
	if err != nil {
		return fmt.Errorf("open content %s: %w", desc.Digest, err)
	}
	defer ra.Close()

	tmp, err := os.CreateTemp(filepath.Dir(target), "."+filepath.Base(target)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpPath)
	}()

	verifier := desc.Digest.Verifier()
	written, err := io.Copy(io.MultiWriter(tmp, verifier), content.NewReader(ra))
	if err != nil {
		return err
	}
	if written != desc.Size {
		return fmt.Errorf("content %s size mismatch: wrote %d, expected %d", desc.Digest, written, desc.Size)
	}
	if !verifier.Verified() {
		return fmt.Errorf("content %s digest verification failed", desc.Digest)
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, target); err != nil {
		return err
	}
	return nil
}
