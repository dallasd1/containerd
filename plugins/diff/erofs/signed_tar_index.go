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
	"path/filepath"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/internal/dmverity"
	snpkg "github.com/containerd/containerd/v2/pkg/snapshotters"
	"github.com/containerd/log"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	deviceAlignment = int64(4096)
)

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
	hashDevicePath := layerBlobPath + ".hashtree"
	if err := copyContentDescriptor(ctx, s.store, target.Tree, hashDevicePath); err != nil {
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
	); err != nil {
		return fmt.Errorf(
			"materialize dm-verity signature for layer %s: %w",
			sourceDesc.Digest,
			err,
		)
	}
	metadata, err := json.Marshal(dmverity.DmverityMetadata{
		RootHash:   target.RootHash,
		HashOffset: 0,
		HashDevice: filepath.Base(hashDevicePath),
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

func copyContentDescriptor(
	ctx context.Context,
	store content.Store,
	desc ocispec.Descriptor,
	target string,
) (retErr error) {
	ra, err := store.ReaderAt(ctx, desc)
	if err != nil {
		return fmt.Errorf("open content %s: %w", desc.Digest, err)
	}
	defer ra.Close()

	file, err := os.Create(target)
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
