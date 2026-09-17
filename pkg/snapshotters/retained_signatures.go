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

package snapshotters

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/errdefs"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const retainedDmverityReferrerLabel = "containerd.io/gc.ref.content.dmverity-referrer"

func loadRetainedDmverityBundle(
	ctx context.Context,
	store content.Store,
	subject ocispec.Descriptor,
	imageLayers map[string]struct{},
) (map[string]*DmverityTarget, error) {
	subjectInfo, err := store.Info(ctx, subject.Digest)
	if err != nil {
		if errdefs.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("inspect retained dm-verity subject %s: %w", subject.Digest, err)
	}

	value := subjectInfo.Labels[retainedDmverityReferrerLabel]
	if value == "" {
		return nil, nil
	}
	referrerDigest, err := digest.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("invalid retained dm-verity referrer on %s: %w", subject.Digest, err)
	}
	info, err := store.Info(ctx, referrerDigest)
	if err != nil {
		return nil, fmt.Errorf("inspect retained dm-verity referrer %s: %w", referrerDigest, err)
	}
	desc := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageManifest,
		Digest:    referrerDigest,
		Size:      info.Size,
	}
	data, err := content.ReadBlob(ctx, store, desc)
	if err != nil {
		return nil, fmt.Errorf("read retained dm-verity referrer %s: %w", referrerDigest, err)
	}
	var manifest ocispec.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parse retained dm-verity referrer %s: %w", referrerDigest, err)
	}
	if err := validateDmverityManifest(&manifest, subject); err != nil {
		return nil, fmt.Errorf("invalid retained dm-verity referrer %s: %w", referrerDigest, err)
	}
	return parseDmverityBundle(&manifest, imageLayers)
}

func updateRetainedDmverityReferrer(
	ctx context.Context,
	store content.Store,
	subject digest.Digest,
	referrer digest.Digest,
) error {
	_, err := store.Update(ctx, content.Info{
		Digest: subject,
		Labels: map[string]string{
			retainedDmverityReferrerLabel: referrer.String(),
		},
	}, "labels."+retainedDmverityReferrerLabel)
	return err
}

func clearRetainedDmverityReferrer(ctx context.Context, store content.Store, subject digest.Digest) error {
	info, err := store.Info(ctx, subject)
	if err != nil {
		return err
	}
	if info.Labels[retainedDmverityReferrerLabel] == "" {
		return nil
	}
	return updateRetainedDmverityReferrer(ctx, store, subject, "")
}
