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
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/internal/dmverity"
	snpkg "github.com/containerd/containerd/v2/pkg/snapshotters"
	"github.com/containerd/log"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	deviceAlignment = int64(4096)
)

// applySignedTarIndexArtifacts writes the signed EROFS metadata, dm-verity tree,
// and signature around the source tar payload.
func (s erofsDiff) applySignedTarIndexArtifacts(
	ctx context.Context,
	sourceDesc ocispec.Descriptor,
	layerBlobPath string,
	sourceTar io.Reader,
) error {
	targetValue := sourceDesc.Annotations[snpkg.TargetLayerDmverityLabel]
	target, err := snpkg.ParseDmverityTarget(targetValue)
	if err != nil {
		return err
	}

	if err := copyContentDescriptor(
		ctx,
		s.store,
		target.Metadata,
		layerBlobPath,
		os.O_CREATE|os.O_TRUNC,
	); err != nil {
		return fmt.Errorf(
			"materialize signed EROFS metadata for layer %s: %w",
			sourceDesc.Digest,
			err,
		)
	}
	if err := appendTarPayload(layerBlobPath, sourceTar); err != nil {
		return fmt.Errorf("append source tar for layer %s: %w", sourceDesc.Digest, err)
	}
	// Preserve the signed data bytes and append the published superblock/tree.
	// HashOffset represents the end of the padded data, not the final file size.
	dataInfo, err := os.Stat(layerBlobPath)
	if err != nil {
		return fmt.Errorf("stat signed EROFS data for layer %s: %w", sourceDesc.Digest, err)
	}
	if err := copyContentDescriptor(ctx, s.store, target.Tree, layerBlobPath, os.O_APPEND); err != nil {
		return fmt.Errorf(
			"materialize dm-verity tree for layer %s: %w",
			sourceDesc.Digest,
			err,
		)
	}
	if err := copyContentDescriptor(
		ctx,
		s.store,
		target.Signature,
		dmverity.SignaturePath(layerBlobPath),
		os.O_CREATE|os.O_TRUNC,
	); err != nil {
		return fmt.Errorf(
			"materialize dm-verity signature for layer %s: %w",
			sourceDesc.Digest,
			err,
		)
	}
	metadata, err := json.Marshal(dmverity.DmverityMetadata{
		RootHash:   target.RootHash,
		HashOffset: uint64(dataInfo.Size()),
	})
	if err != nil {
		return fmt.Errorf("marshal dm-verity metadata: %w", err)
	}
	if err := os.WriteFile(dmverity.MetadataPath(layerBlobPath), metadata, 0644); err != nil {
		return fmt.Errorf("write dm-verity metadata: %w", err)
	}

	log.G(ctx).WithFields(log.Fields{
		"layer":          sourceDesc.Digest,
		"erofs_metadata": target.Metadata.Digest,
		"merkle_tree":    target.Tree.Digest,
		"signature":      target.Signature.Digest,
		"root_hash":      target.RootHash,
	}).Info("Materialized signed EROFS tar-index layer")
	return nil
}

func appendTarPayload(layerBlobPath string, sourceTar io.Reader) (retErr error) {
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
	return nil
}

// copyContentDescriptor copies desc's content to target, opened with flags.
func copyContentDescriptor(
	ctx context.Context,
	store content.Store,
	desc ocispec.Descriptor,
	target string,
	flags int,
) (retErr error) {
	ra, err := store.ReaderAt(ctx, desc)
	if err != nil {
		return fmt.Errorf("open content %s: %w", desc.Digest, err)
	}
	defer ra.Close()

	file, err := os.OpenFile(target, os.O_WRONLY|flags, 0666)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := file.Close(); retErr == nil && closeErr != nil {
			retErr = closeErr
		}
	}()

	_, err = io.Copy(file, content.NewReader(ra))
	return err
}
