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
	"path"
	"runtime"
	"strings"
	"time"

	"github.com/containerd/log"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/diff"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/internal/dmverity"
	"github.com/containerd/containerd/v2/internal/erofsutils"
	snpkg "github.com/containerd/containerd/v2/pkg/snapshotters"

	"github.com/google/uuid"
)

var emptyDesc = ocispec.Descriptor{}

type differ interface {
	diff.Applier
	diff.Comparer
}

// erofsDiff does erofs comparison and application
type erofsDiff struct {
	store         content.Store
	mkfsExtraOpts []string
	// enableTarIndex enables generating tar index for tar content
	// instead of fully converting the tar to EROFS format
	enableTarIndex bool
	// enableDmverity enables consuming signed dm-verity layer metadata.
	enableDmverity bool
	// requireSignatures requires dm-verity signatures to be present on layers
	// when dm-verity is enabled. If true, Apply will fail if a layer lacks a signature.
	requireSignatures bool
}

// DifferOpt is an option for configuring the erofs differ
type DifferOpt func(d *erofsDiff)

// WithMkfsOptions sets extra options for mkfs.erofs
func WithMkfsOptions(opts []string) DifferOpt {
	return func(d *erofsDiff) {
		d.mkfsExtraOpts = opts
	}
}

// WithTarIndexMode enables tar index mode for EROFS layers
func WithTarIndexMode() DifferOpt {
	return func(d *erofsDiff) {
		d.enableTarIndex = true
	}
}

// WithDmverity enables dm-verity for layers carrying signed metadata.
func WithDmverity() DifferOpt {
	return func(d *erofsDiff) {
		d.enableDmverity = true
	}
}

// WithRequireSignatures requires dm-verity signatures to be present on layers.
// This option only has effect when dm-verity is enabled.
func WithRequireSignatures() DifferOpt {
	return func(d *erofsDiff) {
		d.requireSignatures = true
	}
}

// NewErofsDiffer creates a new EROFS differ with the provided options
func NewErofsDiffer(store content.Store, opts ...DifferOpt) differ {
	d := &erofsDiff{
		store: store,
	}

	// Apply all options
	for _, opt := range opts {
		opt(d)
	}

	// Add default block size on darwin if not already specified
	d.mkfsExtraOpts = addDefaultMkfsOpts(d.mkfsExtraOpts)

	return d
}

// A valid EROFS native layer media type should end with ".erofs".
//
// Please avoid using any +suffix to list the algorithms used inside EROFS
// blobs, since:
//   - Each EROFS layer can use multiple compression algorithms;
//   - The suffixes should only indicate the corresponding preprocessor for
//     `images.DiffCompression`.
//
// Since `images.DiffCompression` doesn't support arbitrary media types,
// disallow non-empty suffixes for now.
func isErofsMediaType(mt string) bool {
	mediaType, _, hasExt := strings.Cut(mt, "+")
	if hasExt {
		return false
	}
	return strings.HasSuffix(mediaType, ".erofs")
}

func (s erofsDiff) Apply(ctx context.Context, desc ocispec.Descriptor, mounts []mount.Mount, opts ...diff.ApplyOpt) (d ocispec.Descriptor, err error) {
	t1 := time.Now()
	defer func() {
		if err == nil {
			log.G(ctx).WithFields(log.Fields{
				"d":      time.Since(t1),
				"digest": desc.Digest,
				"size":   desc.Size,
				"media":  desc.MediaType,
			}).Debugf("diff applied")
		}
	}()

	native := false
	if isErofsMediaType(desc.MediaType) {
		native = true
	} else if _, err := images.DiffCompression(ctx, desc.MediaType); err != nil {
		return emptyDesc, fmt.Errorf("currently unsupported media type: %s", desc.MediaType)
	}

	var config diff.ApplyConfig
	for _, o := range opts {
		if err := o(ctx, desc, &config); err != nil {
			return emptyDesc, fmt.Errorf("failed to apply config opt: %w", err)
		}
	}

	layer, err := erofsutils.MountsToLayer(mounts)
	if err != nil {
		return emptyDesc, err
	}

	ra, err := s.store.ReaderAt(ctx, desc)
	if err != nil {
		return emptyDesc, fmt.Errorf("failed to get reader from content store: %w", err)
	}
	defer ra.Close()

	layerBlobPath := path.Join(layer, "layer.erofs")
	useDmverity, err := s.dmverityForLayer(desc)
	if err != nil {
		return emptyDesc, err
	}
	if native {
		f, err := os.Create(layerBlobPath)
		if err != nil {
			return emptyDesc, err
		}
		_, err = io.Copy(f, content.NewReader(ra))
		f.Close()
		if err != nil {
			return emptyDesc, err
		}
		// Native EROFS layers follow the same signed-metadata policy as tar
		// layers. A valid signature still covers the root hash computed from
		// the native blob; an unsigned layer remains ordinary EROFS.
		if useDmverity {
			rootHash, err := s.formatDmverityLayer(ctx, layerBlobPath)
			if err != nil {
				return emptyDesc, fmt.Errorf("failed to format dm-verity layer: %w", err)
			}
			if err := s.writeLayerSignature(ctx, desc, layerBlobPath, rootHash); err != nil {
				return emptyDesc, err
			}
		}
		return desc, nil
	}

	processor := diff.NewProcessorChain(desc.MediaType, content.NewReader(ra))
	for {
		if processor, err = diff.GetProcessor(ctx, processor, config.ProcessorPayloads); err != nil {
			return emptyDesc, fmt.Errorf("failed to get stream processor for %s: %w", desc.MediaType, err)
		}
		if processor.MediaType() == ocispec.MediaTypeImageLayer {
			break
		}
	}
	defer processor.Close()

	digester := digest.Canonical.Digester()
	rc := &readCounter{
		r: io.TeeReader(processor, digester.Hash()),
	}

	if useDmverity {
		if used, err := s.applyPrecomputedArtifacts(ctx, desc, layerBlobPath, rc); err != nil {
			return emptyDesc, err
		} else if used {
			return ocispec.Descriptor{
				MediaType: ocispec.MediaTypeImageLayer,
				Size:      rc.c,
				Digest:    digester.Digest(),
			}, nil
		}
	}

	// Choose between tar index or tar conversion mode
	// Generate deterministic UUID from layer digest
	u := uuid.NewSHA1(uuid.NameSpaceURL, []byte("erofs:blobs/"+desc.Digest))
	if s.enableTarIndex {
		// Use the tar index method: generate tar index and append tar
		err = erofsutils.GenerateTarIndexAndAppendTar(ctx, rc, layerBlobPath, u.String(), s.mkfsExtraOpts)
		if err != nil {
			return emptyDesc, fmt.Errorf("failed to generate tar index: %w", err)
		}
		log.G(ctx).WithField("path", layerBlobPath).Debug("Applied layer using tar index mode")
	} else {
		// Use the tar method: fully convert tar to EROFS
		err = erofsutils.ConvertTarErofs(ctx, rc, layerBlobPath, u.String(), s.mkfsExtraOpts)
		if err != nil {
			return emptyDesc, fmt.Errorf("failed to convert tar to erofs: %w", err)
		}
		log.G(ctx).WithField("path", layerBlobPath).Debug("Applied layer using tar conversion mode")
	}

	// Read any trailing data
	if _, err := io.Copy(io.Discard, rc); err != nil {
		return emptyDesc, err
	}

	// Locally format only a layer carrying signed dm-verity metadata. Merely
	// enabling referrer support must not impose mapper overhead on unsigned
	// images.
	if useDmverity {
		rootHash, err := s.formatDmverityLayer(ctx, layerBlobPath)
		if err != nil {
			return emptyDesc, fmt.Errorf("failed to format dm-verity layer: %w", err)
		}

		if err := s.writeLayerSignature(ctx, desc, layerBlobPath, rootHash); err != nil {
			return emptyDesc, err
		}
	}

	return ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageLayer,
		Size:      rc.c,
		Digest:    digester.Digest(),
	}, nil
}

func (s erofsDiff) dmverityForLayer(desc ocispec.Descriptor) (bool, error) {
	if !s.enableDmverity {
		return false, nil
	}
	labels, err := snpkg.DmveritySnapshotLabels(desc, s.requireSignatures)
	if err != nil {
		return false, err
	}
	return labels[snpkg.DmverityMaterializationStateLabel] == snpkg.DmverityMaterializationStateSigned, nil
}

func (s erofsDiff) writeLayerSignature(ctx context.Context, desc ocispec.Descriptor, layerBlobPath, actualRootHash string) error {
	sig := desc.Annotations[snpkg.TargetLayerSignatureLabel]
	switch {
	case sig != "":
		expectedRootHash := desc.Annotations[snpkg.TargetLayerRootHashLabel]
		if expectedRootHash == "" {
			return fmt.Errorf("dm-verity signature present but missing expected root hash for layer %s", desc.Digest)
		}
		if actualRootHash != expectedRootHash {
			return fmt.Errorf("dm-verity root hash mismatch for layer %s: actual %q, expected %q", desc.Digest, actualRootHash, expectedRootHash)
		}
		if err := dmverity.WriteSignature(layerBlobPath, sig); err != nil {
			return err
		}
		log.G(ctx).WithField("path", dmverity.SignaturePath(layerBlobPath)).Debug("Wrote dm-verity signature file")
	case s.requireSignatures:
		return fmt.Errorf("dm-verity signature required but not present on layer %s", desc.Digest)
	}
	return nil
}

type readCounter struct {
	r io.Reader
	c int64
}

func (rc *readCounter) Read(p []byte) (n int, err error) {
	n, err = rc.r.Read(p)
	rc.c += int64(n)
	return
}

// addDefaultMkfsOpts adds default options for mkfs.erofs
func addDefaultMkfsOpts(mkfsExtraOpts []string) []string {
	if runtime.GOOS != "darwin" {
		return mkfsExtraOpts
	}

	// Check if -b argument is already present
	for _, opt := range mkfsExtraOpts {
		if strings.HasPrefix(opt, "-b") {
			return mkfsExtraOpts
		}
	}

	// Add -b4096 as the first option to prevent unusable block
	// size from being used on macOS.
	return append([]string{"-b4096"}, mkfsExtraOpts...)
}
