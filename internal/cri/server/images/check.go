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

package images

import (
	"context"
	"fmt"
	"slices"
	"sync"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/images"
	snpkg "github.com/containerd/containerd/v2/pkg/snapshotters"
	"github.com/containerd/containerd/v2/plugins"
	"github.com/containerd/errdefs"
	"github.com/containerd/log"
	"github.com/containerd/platforms"
	"github.com/opencontainers/image-spec/identity"
)

// CheckImages checks all existing images to ensure they are ready to
// be used for CRI. It may try to recover images which are not ready
// but will only log errors, not return any.
func (c *CRIImageService) CheckImages(ctx context.Context) error {
	// TODO: Move way from `client.ListImages` to directly using image store
	cImages, err := c.client.ListImages(ctx)
	if err != nil {
		return fmt.Errorf("unable to list images: %w", err)
	}

	// TODO: Support all snapshotter
	snapshotter := c.config.Snapshotter
	var wg sync.WaitGroup
	for _, i := range cImages {
		wg.Go(func() {
			// TODO: Check platform/snapshot combination. Snapshot check should come first
			ok, _, _, _, err := images.Check(ctx, i.ContentStore(), i.Target(), platforms.Default())
			if err != nil {
				log.G(ctx).WithError(err).Errorf("Failed to check image content readiness for %q", i.Name())
				return
			}
			if !ok {
				log.G(ctx).Warnf("The image content readiness for %q is not ok", i.Name())
				return
			}
			// Checking existence of top-level snapshot for each image being recovered.
			// TODO: This logic should be done elsewhere and owned by the image service
			unpacked, err := c.imageIsUnpacked(ctx, i, snapshotter)
			if err != nil {
				log.G(ctx).WithError(err).Warnf("Failed to check whether image is unpacked for image %s", i.Name())
				return
			}

			if !unpacked {
				log.G(ctx).Warnf("The image %s is not unpacked.", i.Name())
				// TODO(random-liu): Consider whether we should try unpack here.
			}
			if err := c.UpdateImage(ctx, i.Name()); err != nil {
				log.G(ctx).WithError(err).Warnf("Failed to update reference for image %q", i.Name())
				return
			}
			log.G(ctx).Debugf("Loaded image %q", i.Name())
		})
	}
	wg.Wait()
	return nil
}

func (c *CRIImageService) imageIsUnpacked(ctx context.Context, i containerd.Image, snapshotter string) (bool, error) {
	signed, err := snpkg.ImageHasDmverityReferrer(ctx, i.ContentStore(), i.Target(), platforms.Default())
	if err != nil {
		return false, fmt.Errorf("inspect signed dm-verity image %q: %w", i.Name(), err)
	}
	if signed {
		capabilities, err := c.client.GetSnapshotterCapabilities(ctx, snapshotter)
		if err != nil {
			return false, fmt.Errorf("get snapshotter %q capabilities: %w", snapshotter, err)
		}
		if slices.Contains(capabilities, plugins.CapabilityDmverityReferrers) {
			diffIDs, err := i.RootFS(ctx)
			if err != nil {
				return false, fmt.Errorf("get image rootfs for %q: %w", i.Name(), err)
			}
			key, err := snpkg.DmveritySnapshotKey(identity.ChainID(diffIDs).String())
			if err != nil {
				return false, err
			}
			if _, err := c.client.SnapshotService(snapshotter).Stat(ctx, key); err != nil {
				if errdefs.IsNotFound(err) {
					return false, nil
				}
				return false, fmt.Errorf("stat signed snapshot %q for image %q: %w", key, i.Name(), err)
			}
			return true, nil
		}
	}
	return i.IsUnpacked(ctx, snapshotter)
}
