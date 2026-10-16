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

package server

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/leases"
	"github.com/containerd/containerd/v2/core/mount"
	snpkg "github.com/containerd/containerd/v2/pkg/snapshotters"
	"github.com/containerd/containerd/v2/plugins"
	"github.com/containerd/errdefs"
	"github.com/containerd/log"
	"github.com/containerd/platforms"
	"github.com/opencontainers/image-spec/identity"
	imagespec "github.com/opencontainers/image-spec/specs-go/v1"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
	crierrors "k8s.io/cri-api/pkg/errors"
)

func (c *criService) mutateMounts(
	ctx context.Context,
	extraMounts []*runtime.Mount,
	snapshotter string,
	sandboxID string,
	platform imagespec.Platform,
) error {
	if err := c.ensureLeaseExist(ctx, sandboxID); err != nil {
		return fmt.Errorf("failed to ensure lease %v for sandbox: %w", sandboxID, err)
	}

	ctx = leases.WithLease(ctx, sandboxID)
	for _, m := range extraMounts {
		err := c.mutateImageMount(ctx, m, snapshotter, sandboxID, platform)
		if err != nil {
			return fmt.Errorf("%w: %w", crierrors.ErrImageVolumeMountFailed, err)
		}
	}
	return nil
}

func (c *criService) ensureLeaseExist(ctx context.Context, sandboxID string) error {
	leaseSvc := c.client.LeasesService()
	_, err := leaseSvc.Create(ctx, leases.WithID(sandboxID))
	if err != nil {
		if errdefs.IsAlreadyExists(err) {
			err = nil
		}
	}
	return err
}

func (c *criService) mutateImageMount(
	ctx context.Context,
	extraMount *runtime.Mount,
	snapshotter string,
	sandboxID string,
	platform imagespec.Platform,
) (retErr error) {
	imageSpec := extraMount.GetImage()
	if imageSpec == nil {
		return nil
	}
	if extraMount.GetHostPath() != "" {
		return fmt.Errorf("hostpath must be empty while mount image: %+v", extraMount)
	}
	if !extraMount.GetReadonly() {
		return fmt.Errorf("readonly must be true while mount image: %+v", extraMount)
	}

	ref := imageSpec.GetImage()
	if ref == "" {
		return fmt.Errorf("image not specified in: %+v", imageSpec)
	}
	image, err := c.LocalResolve(ref)
	if err != nil {
		return fmt.Errorf("failed to resolve image %q: %w", ref, err)
	}
	containerdImage, err := c.toContainerdImage(ctx, image)
	if err != nil {
		return fmt.Errorf("failed to get image from containerd %q: %w", image.ID, err)
	}

	// This is a digest of the manifest
	imageID := containerdImage.Target().Digest.Encoded()
	target := c.getImageVolumeHostPath(sandboxID, imageID)

	mounted, err := ensureImageVolumeMounted(target)
	if err != nil {
		return fmt.Errorf("failed to ensure %s is mounted: %w", target, err)
	}
	if mounted {
		capable, err := c.dmverityReferrersEnabled(ctx, snapshotter)
		if err != nil {
			return err
		}
		if !capable {
			return setImageMountPath(extraMount, target)
		}
	}

	img, err := c.client.ImageService().Get(ctx, ref)
	if err != nil {
		return fmt.Errorf("failed to get image volume ref %q: %w", ref, err)
	}

	i := containerd.NewImageWithPlatform(c.client, img, platforms.Only(platform))
	diffIDs, err := i.RootFS(ctx)
	if err != nil {
		return fmt.Errorf("failed to get diff IDs for image volume %q: %w", ref, err)
	}
	chainID := identity.ChainID(diffIDs).String()
	if err := c.rejectSignedImageVolume(ctx, i, snapshotter, platforms.Only(platform)); err != nil {
		return err
	}
	if !mounted {
		if err := i.Unpack(ctx, snapshotter); err != nil {
			return fmt.Errorf("failed to unpack image volume: %w", err)
		}

		// Get snapshot options with user namespace idmap labels if needed
		snapshotOpts, err := c.getImageVolumeSnapshotOpts(ctx, extraMount)
		if err != nil {
			return fmt.Errorf("failed to get snapshot options for image volume: %w", err)
		}

		s := c.client.SnapshotService(snapshotter)
		mounts, err := s.Prepare(ctx, target, chainID, snapshotOpts...)
		if err != nil {
			if errdefs.IsAlreadyExists(err) {
				mounts, err = s.Mounts(ctx, target)
			}
		}
		if err != nil {
			return fmt.Errorf("failed to prepare for image volume %q: %w", ref, err)
		}
		defer func() {
			if retErr != nil {
				_ = s.Remove(ctx, target)
			}
		}()

		err = os.MkdirAll(target, 0755)
		if err != nil {
			return fmt.Errorf("failed to create directory to image volume target path %q: %w", target, err)
		}

		mounts = addVolatileOptionOnImageVolumeMount(mounts)
		if err := mount.All(mounts, target); err != nil {
			return fmt.Errorf("failed to mount image volume component %q: %w", target, err)
		}
	}

	return setImageMountPath(extraMount, target)
}

func setImageMountPath(extraMount *runtime.Mount, target string) error {
	if imageSubPath := extraMount.GetImageSubPath(); imageSubPath != "" {
		mountPoint, err := ensureImageSubPath(target, imageSubPath)
		if err != nil {
			return fmt.Errorf("failed to ensure image subpath %q in %q: %w", imageSubPath, target, err)
		}
		target = mountPoint
	}
	extraMount.HostPath = target
	// Clear UID/GID mappings from the mount to prevent the OCI runtime from
	// attempting idmap on the bind mount. The idmap is already applied to the
	// overlay lower layers via the snapshotter when the image volume is prepared.
	// This must be done regardless of whether the image volume was already mounted
	// (e.g., by another container in the same pod).
	extraMount.UidMappings = nil
	extraMount.GidMappings = nil
	return nil
}

func (c *criService) cleanupImageMounts(
	ctx context.Context,
	sandboxID string,
) (retErr error) {
	// Some checks to avoid affecting old pods.
	ociRuntime, err := c.getPodSandboxRuntime(sandboxID)
	if err != nil {
		log.G(ctx).WithError(err).Errorf("failed to get sandbox runtime handler %q", sandboxID)
		return nil
	}
	snapshotter := c.RuntimeSnapshotter(ctx, ociRuntime)
	s := c.client.SnapshotService(snapshotter)
	if s == nil {
		return nil
	}
	targetBase := c.getImageVolumeBaseDir(sandboxID)
	entries, err := os.ReadDir(targetBase)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read directory: %w", err)
	}

	for _, entry := range entries {
		target := filepath.Join(targetBase, entry.Name())

		err = mount.UnmountAll(target, 0)
		if err != nil {
			return fmt.Errorf("failed to unmount image volume component %q: %w", target, err)
		}
		err = s.Remove(ctx, target)
		if err != nil && !errdefs.IsNotFound(err) {
			return fmt.Errorf("failed to removing snapshot: %w", err)
		}
		err = os.Remove(target)
		if err != nil && !errdefs.IsNotFound(err) {
			return fmt.Errorf("failed to removing mounts directory: %w", err)
		}
	}

	err = os.Remove(targetBase)
	if err != nil && !errdefs.IsNotFound(err) {
		return fmt.Errorf("failed to remove directory to cleanup image volume mounts: %w", err)
	}
	return nil
}

// ensureImageSubPath ensures the subPath exists **within** the mountPoint (i.e.
// not escape outside of mountPoint) and it's a directory.
// It returns the final absolute path of `subPath`.
func ensureImageSubPath(mountPoint, subPath string) (string, error) {
	if subPath == "" {
		return mountPoint, nil
	}

	file, err := os.OpenInRoot(mountPoint, subPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return "", err
	}

	if !stat.IsDir() {
		// the current OCI volume source treats mounting a single file as non-goal
		// and limits the mount output to directories.
		// https://github.com/kubernetes/enhancements/tree/f3fa3a12d303a6b749efd072987a39aab159f9d5/keps/sig-node/4639-oci-volume-source#non-goals
		return "", fmt.Errorf("only directory subpath is supported, subpath: %q, mountpoint: %q ", subPath, mountPoint)
	}

	return file.Name(), nil
}

// rejectSignedImageVolume refuses signed dm-verity images, which image volumes
// cannot mount yet, rather than materializing them unsigned.
func (c *criService) rejectSignedImageVolume(
	ctx context.Context,
	i containerd.Image,
	snapshotter string,
	platform platforms.MatchComparer,
) error {
	capable, err := c.dmverityReferrersEnabled(ctx, snapshotter)
	if err != nil {
		return err
	}
	if !capable {
		return nil
	}
	signed, err := snpkg.ImageHasDmverityReferrer(ctx, i.ContentStore(), i.Target(), platform)
	if err != nil {
		return fmt.Errorf("failed to inspect dm-verity observation for image volume %q: %w", i.Name(), err)
	}
	if signed {
		return fmt.Errorf("image volume %q is a signed dm-verity image, which image volumes do not support: %w", i.Name(), errdefs.ErrNotImplemented)
	}
	return nil
}

func (c *criService) dmverityReferrersEnabled(ctx context.Context, snapshotter string) (bool, error) {
	c.dmverityCapabilityMu.Lock()
	defer c.dmverityCapabilityMu.Unlock()
	if capable, ok := c.dmverityCapabilities[snapshotter]; ok {
		return capable, nil
	}
	capabilities, err := c.client.GetSnapshotterCapabilities(ctx, snapshotter)
	if err != nil {
		return false, fmt.Errorf("failed to get capabilities of snapshotter %q: %w", snapshotter, err)
	}
	capable := slices.Contains(capabilities, plugins.CapabilityDmverityReferrers)
	if c.dmverityCapabilities == nil {
		c.dmverityCapabilities = make(map[string]bool)
	}
	c.dmverityCapabilities[snapshotter] = capable
	return capable, nil
}
