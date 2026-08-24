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
	"bytes"
	"context"
	"encoding/json"
	"io"
	"sort"
	"sync"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type memoryLabelStore struct {
	mu     sync.Mutex
	labels map[digest.Digest]map[string]string
}

func newMemoryLabelStore() *memoryLabelStore {
	return &memoryLabelStore{labels: map[digest.Digest]map[string]string{}}
}

func (s *memoryLabelStore) Get(dgst digest.Digest) (map[string]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.labels[dgst], nil
}

func (s *memoryLabelStore) Set(dgst digest.Digest, labels map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.labels[dgst] = labels
	return nil
}

func (s *memoryLabelStore) Update(dgst digest.Digest, update map[string]string) (map[string]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	labels := s.labels[dgst]
	if labels == nil {
		labels = map[string]string{}
	}
	for key, value := range update {
		if value == "" {
			delete(labels, key)
		} else {
			labels[key] = value
		}
	}
	s.labels[dgst] = labels
	return labels, nil
}

// writeBlob writes data into cs and returns its descriptor.
func writeBlob(t *testing.T, ctx context.Context, cs content.Store, mediaType string, data []byte) ocispec.Descriptor {
	t.Helper()
	dgst := digest.FromBytes(data)
	desc := ocispec.Descriptor{
		MediaType: mediaType,
		Digest:    dgst,
		Size:      int64(len(data)),
	}
	err := content.WriteBlob(ctx, cs, "test-"+dgst.Hex()[:12], bytes.NewReader(data), desc)
	require.NoError(t, err)
	return desc
}

// writeManifest marshals m as JSON and writes it to cs, returning the descriptor.
func writeManifest(t *testing.T, ctx context.Context, cs content.Store, m any) ocispec.Descriptor {
	t.Helper()
	data, err := json.Marshal(m)
	require.NoError(t, err)
	return writeBlob(t, ctx, cs, ocispec.MediaTypeImageManifest, data)
}

// TestContentStoreFetcherFetch verifies Fetch returns the exact bytes of a
// blob previously written to the content store.
func TestContentStoreFetcherFetch(t *testing.T) {
	ctx := context.Background()
	cs, err := local.NewStore(t.TempDir())
	require.NoError(t, err)
	f := NewContentStoreFetcher(cs)

	payload := []byte("hello dm-verity world")
	desc := writeBlob(t, ctx, cs, "application/octet-stream", payload)

	rc, err := f.Fetch(ctx, desc)
	require.NoError(t, err)
	defer rc.Close()
	got, err := io.ReadAll(rc)
	require.NoError(t, err)
	assert.Equal(t, payload, got)
}

// TestContentStoreFetcherFetchReferrers verifies FetchReferrers walks the
// store, finds manifests whose subject points at the requested digest, and
// filters by artifactType when requested.
func TestContentStoreFetcherFetchReferrers(t *testing.T) {
	ctx := context.Background()
	cs, err := local.NewStore(t.TempDir())
	require.NoError(t, err)
	f := NewContentStoreFetcher(cs)

	// Seed an image manifest (the "subject") and a tiny layer blob.
	layer := writeBlob(t, ctx, cs, ocispec.MediaTypeImageLayerGzip, []byte("fake layer payload"))
	imgManifest := writeManifest(t, ctx, cs, ocispec.Manifest{
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    layer, // bogus but well-formed
		Layers:    []ocispec.Descriptor{layer},
	})

	// Sig referrer: subject = image manifest, artifactType = dm-verity.
	dmveritySig := writeManifest(t, ctx, cs, ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: SignatureArtifactType,
		Subject:      &imgManifest,
		Layers:       []ocispec.Descriptor{},
	})

	// Sig referrer: subject = image manifest, artifactType = notary signature.
	notarySig := writeManifest(t, ctx, cs, ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: "application/vnd.cncf.notary.signature",
		Subject:      &imgManifest,
		Layers:       []ocispec.Descriptor{},
	})

	// Decoy: subject points elsewhere, must NOT be returned.
	otherImg := writeManifest(t, ctx, cs, ocispec.Manifest{
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    layer,
		Layers:    []ocispec.Descriptor{layer},
	})
	_ = writeManifest(t, ctx, cs, ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: SignatureArtifactType,
		Subject:      &otherImg,
		Layers:       []ocispec.Descriptor{},
	})

	// Without an artifactType filter, both real referrers come back.
	got, err := f.FetchReferrers(ctx, imgManifest.Digest)
	require.NoError(t, err)
	gotDigests := descDigests(got)
	sort.Strings(gotDigests)
	want := []string{dmveritySig.Digest.String(), notarySig.Digest.String()}
	sort.Strings(want)
	assert.Equal(t, want, gotDigests, "expected both referrers")

	// With dm-verity artifactType filter, only that one comes back.
	got, err = f.FetchReferrers(ctx, imgManifest.Digest,
		remotes.WithReferrerArtifactTypes(SignatureArtifactType))
	require.NoError(t, err)
	gotDigests = descDigests(got)
	assert.Equal(t, []string{dmveritySig.Digest.String()}, gotDigests,
		"expected only the dm-verity referrer")
	if len(got) == 1 {
		assert.Equal(t, SignatureArtifactType, got[0].ArtifactType)
		assert.Equal(t, ocispec.MediaTypeImageManifest, got[0].MediaType)
	}
}

func TestContentStoreFetcherSeparatesCachedLookupFromImportDiscovery(t *testing.T) {
	ctx := context.Background()
	cs, err := local.NewLabeledStore(t.TempDir(), newMemoryLabelStore())
	require.NoError(t, err)

	config := writeBlob(t, ctx, cs, ocispec.MediaTypeImageConfig, []byte("{}"))
	subject := writeManifest(t, ctx, cs, ocispec.Manifest{
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    config,
	})
	selected := writeManifest(t, ctx, cs, ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: SignatureArtifactType,
		Subject:      &subject,
		Config:       config,
		Annotations:  map[string]string{ociAnnotationCreated: "2026-07-20T01:00:00Z"},
	})
	newer := writeManifest(t, ctx, cs, ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: SignatureArtifactType,
		Subject:      &subject,
		Config:       config,
		Annotations:  map[string]string{ociAnnotationCreated: "2026-07-20T02:00:00Z"},
	})
	_, err = cs.Update(ctx, content.Info{
		Digest: subject.Digest,
		Labels: map[string]string{DmverityReferrerLabel: selected.Digest.String()},
	}, "labels."+DmverityReferrerLabel)
	require.NoError(t, err)

	cached, err := newCachedContentStoreFetcher(cs).FetchReferrers(ctx, subject.Digest,
		remotes.WithReferrerArtifactTypes(SignatureArtifactType))
	require.NoError(t, err)
	require.Len(t, cached, 1)
	assert.Equal(t, selected.Digest, cached[0].Digest)

	discovered, err := NewContentStoreFetcher(cs).FetchReferrers(ctx, subject.Digest,
		remotes.WithReferrerArtifactTypes(SignatureArtifactType))
	require.NoError(t, err)
	require.Len(t, discovered, 2)
	assert.ElementsMatch(t, []digest.Digest{selected.Digest, newer.Digest},
		[]digest.Digest{discovered[0].Digest, discovered[1].Digest})
}

// TestContentStoreFetcherFetchReferrersEmpty verifies a store with no
// matching referrers returns no results and no error.
func TestContentStoreFetcherFetchReferrersEmpty(t *testing.T) {
	ctx := context.Background()
	cs, err := local.NewStore(t.TempDir())
	require.NoError(t, err)
	// Seed one unrelated blob so the local store's blobs/ directory exists
	// (local.NewStore creates it lazily on first write).
	writeBlob(t, ctx, cs, "application/octet-stream", []byte("unrelated"))
	f := NewContentStoreFetcher(cs)

	got, err := f.FetchReferrers(ctx,
		digest.FromBytes([]byte("nonexistent")))
	require.NoError(t, err)
	assert.Empty(t, got)
}

// TestContentStoreFetcherSkipsNonManifestBlobs verifies that ordinary blobs
// (random bytes that don't parse as a manifest, oversize blobs) don't cause
// errors and aren't returned as referrers.
func TestContentStoreFetcherSkipsNonManifestBlobs(t *testing.T) {
	ctx := context.Background()
	cs, err := local.NewStore(t.TempDir())
	require.NoError(t, err)
	f := NewContentStoreFetcher(cs)

	// Write a non-JSON blob.
	junk := bytes.Repeat([]byte{0xff, 0x00, 0x42}, 100)
	junkDesc := writeBlob(t, ctx, cs, "application/octet-stream", junk)

	// A manifest with the subject we'll query for.
	subject := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageManifest,
		Digest:    digest.FromBytes([]byte("imaginary subject manifest")),
		Size:      123,
	}
	sigDesc := writeManifest(t, ctx, cs, ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: SignatureArtifactType,
		Subject:      &subject,
	})

	got, err := f.FetchReferrers(ctx, subject.Digest)
	require.NoError(t, err)
	gotDigests := descDigests(got)
	assert.Equal(t, []string{sigDesc.Digest.String()}, gotDigests)
	assert.NotContains(t, gotDigests, junkDesc.Digest.String())
}

func descDigests(descs []ocispec.Descriptor) []string {
	out := make([]string, len(descs))
	for i, d := range descs {
		out[i] = d.Digest.String()
	}
	return out
}
