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
	"io"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/log"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// maxManifestSize bounds the per-blob read attempted by the content-store
// referrer scan. Manifests are small JSON documents (tens to a few hundred
// kilobytes at most). Skipping anything larger keeps us from slurping
// arbitrary image-layer payloads off disk during a scan.
const maxManifestSize = 4 * 1024 * 1024 // 4 MiB

// ContentStoreFetcher exposes a content.Store as a remotes.Fetcher and
// remotes.ReferrersFetcher so handler chains that were originally written
// against a registry-backed fetcher (e.g. AppendSignatureHandlerWrapper)
// can be used during local OCI-layout imports.
//
// FetchReferrers walks the content store, parses each candidate blob as an
// OCI manifest, and returns the descriptors whose `subject.digest` matches
// the request. When FetchReferrersConfig.ArtifactTypes is non-empty the
// results are filtered to manifests whose artifactType is in the set.
//
// This is intentionally an O(n) scan over the content store: it is meant to
// run once per imported image during a transfer.Import, when n is small
// (the freshly-imported OCI layout's manifests + layers + config blobs).
// If a use case appears that needs sub-linear lookup, switch to a labeled
// index (e.g. write a "containerd.io/manifest.subject" label at ingest
// time and look up by label filter); the interface stays the same.
type ContentStoreFetcher struct {
	store content.Store
}

// NewContentStoreFetcher constructs a ContentStoreFetcher backed by store.
func NewContentStoreFetcher(store content.Store) *ContentStoreFetcher {
	return &ContentStoreFetcher{store: store}
}

// Fetch implements remotes.Fetcher by reading the blob identified by desc
// out of the content store.
func (f *ContentStoreFetcher) Fetch(ctx context.Context, desc ocispec.Descriptor) (io.ReadCloser, error) {
	ra, err := f.store.ReaderAt(ctx, desc)
	if err != nil {
		return nil, fmt.Errorf("content store fetch %s: %w", desc.Digest, err)
	}
	return &readerAtCloser{
		Reader: content.NewReader(ra),
		closer: ra,
	}, nil
}

// FetchReferrers implements remotes.ReferrersFetcher by scanning the content
// store for manifests whose `subject.digest` equals dgst, optionally filtered
// by artifactType.
func (f *ContentStoreFetcher) FetchReferrers(ctx context.Context, dgst digest.Digest, opts ...remotes.FetchReferrersOpt) ([]ocispec.Descriptor, error) {
	var cfg remotes.FetchReferrersConfig
	for _, o := range opts {
		if err := o(ctx, &cfg); err != nil {
			return nil, fmt.Errorf("apply FetchReferrersOpt: %w", err)
		}
	}

	allowed := make(map[string]struct{}, len(cfg.ArtifactTypes))
	for _, t := range cfg.ArtifactTypes {
		allowed[t] = struct{}{}
	}

	var result []ocispec.Descriptor
	walkErr := f.store.Walk(ctx, func(info content.Info) error {
		if info.Size <= 0 || info.Size > maxManifestSize {
			return nil
		}
		desc := ocispec.Descriptor{
			Digest: info.Digest,
			Size:   info.Size,
		}
		ra, err := f.store.ReaderAt(ctx, desc)
		if err != nil {
			log.G(ctx).WithError(err).WithField("digest", info.Digest).
				Debug("content-store referrer scan: skip blob, ReaderAt failed")
			return nil
		}
		buf := make([]byte, info.Size)
		_, readErr := ra.ReadAt(buf, 0)
		ra.Close()
		if readErr != nil && readErr != io.EOF {
			log.G(ctx).WithError(readErr).WithField("digest", info.Digest).
				Debug("content-store referrer scan: skip blob, read failed")
			return nil
		}

		var probe struct {
			MediaType    string              `json:"mediaType"`
			ArtifactType string              `json:"artifactType"`
			Subject      *ocispec.Descriptor `json:"subject"`
		}
		if err := json.Unmarshal(buf, &probe); err != nil {
			return nil
		}
		if probe.Subject == nil || probe.Subject.Digest != dgst {
			return nil
		}
		if !images.IsManifestType(probe.MediaType) {
			return nil
		}
		if len(allowed) > 0 {
			if _, ok := allowed[probe.ArtifactType]; !ok {
				return nil
			}
		}

		result = append(result, ocispec.Descriptor{
			MediaType:    probe.MediaType,
			ArtifactType: probe.ArtifactType,
			Digest:       info.Digest,
			Size:         info.Size,
		})
		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("walk content store for referrers of %s: %w", dgst, walkErr)
	}
	return result, nil
}

type readerAtCloser struct {
	io.Reader
	closer io.Closer
}

func (r *readerAtCloser) Close() error {
	return r.closer.Close()
}

// Compile-time assertions that ContentStoreFetcher satisfies the interfaces
// expected by AppendSignatureHandlerWrapper.
var (
	_ remotes.Fetcher          = (*ContentStoreFetcher)(nil)
	_ remotes.ReferrersFetcher = (*ContentStoreFetcher)(nil)
)
