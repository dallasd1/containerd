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

package docker

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/errdefs"
	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestFetchReferrersPagination(t *testing.T) {
	const (
		name          = "paginated"
		signatureType = "application/vnd.test.sig"
	)
	signature1 := newContent(ocispec.MediaTypeImageManifest, []byte("signature one"), withArtifactType(signatureType))
	sbom := newContent(ocispec.MediaTypeImageManifest, []byte("sbom"), withArtifactType("application/vnd.test.sbom"))
	signature2 := newContent(ocispec.MediaTypeImageManifest, []byte("signature two"), withArtifactType(signatureType))
	firstPage := newIndex(signature1, sbom).OCIManifest()
	secondPage := newIndex(signature2).OCIManifest()

	var requests atomic.Int32
	fetcher, subject := newReferrersFetcher(t, name, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		query := r.URL.Query()
		if query.Get("artifactType") != signatureType || query.Get("channel") != "stable" {
			http.Error(w, "pagination request lost fixed filters", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", ocispec.MediaTypeImageIndex)
		switch query.Get("last") {
		case "":
			w.Header().Set("Link", `<?last=first>; rel="next"; title="page, two; retained"`)
			w.Write(firstPage)
		case "first":
			w.Write(secondPage)
		default:
			http.Error(w, "unexpected pagination cursor", http.StatusBadRequest)
		}
	}))

	refs, err := fetcher.FetchReferrers(
		context.Background(),
		subject,
		remotes.WithReferrerArtifactTypes(signatureType),
		remotes.WithReferrerQueryFilter("channel", "stable"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 2 {
		t.Fatalf("referrers requests = %d, want 2", requests.Load())
	}
	if len(refs) != 2 || refs[0].Digest != signature1.Digest() || refs[1].Digest != signature2.Digest() {
		t.Fatalf("paginated referrers = %+v, want signature descriptors from both pages", refs)
	}
}

func TestFetchReferrersPaginationLoop(t *testing.T) {
	const name = "pagination-loop"
	emptyPage := newIndex().OCIManifest()
	var requests atomic.Int32
	fetcher, subject := newReferrersFetcher(t, name, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", ocispec.MediaTypeImageIndex)
		w.Header().Set("Link", `<?page=two>; rel="next"`)
		w.Write(emptyPage)
	}))

	_, err := fetcher.FetchReferrers(context.Background(), subject)
	if err == nil || !strings.Contains(err.Error(), "pagination loop") {
		t.Fatalf("FetchReferrers() error = %v, want pagination loop", err)
	}
	if requests.Load() != 2 {
		t.Fatalf("referrers requests = %d, want 2 before loop detection", requests.Load())
	}
}

func TestFetchReferrersPaginationRetriesTransientFailure(t *testing.T) {
	const name = "pagination-retry"
	firstPage := newIndex().OCIManifest()
	secondPage := newIndex(
		newContent(ocispec.MediaTypeImageManifest, []byte("referrer")),
	).OCIManifest()

	var secondPageAttempts atomic.Int32
	fetcher, subject := newReferrersFetcher(t, name, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ocispec.MediaTypeImageIndex)
		if r.URL.Query().Get("page") == "" {
			w.Header().Set("Link", `<?page=two>; rel="next"`)
			w.Write(firstPage)
			return
		}
		if secondPageAttempts.Add(1) == 1 {
			http.Error(w, "temporary failure", http.StatusServiceUnavailable)
			return
		}
		w.Write(secondPage)
	}))

	refs, err := fetcher.FetchReferrers(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 {
		t.Fatalf("paginated referrers = %d, want 1", len(refs))
	}
	if secondPageAttempts.Load() != 2 {
		t.Fatalf("second-page attempts = %d, want 2", secondPageAttempts.Load())
	}
}

func TestFetchReferrersMissingContinuationFailsClosed(t *testing.T) {
	const name = "missing-continuation"
	firstPage := newIndex().OCIManifest()
	fetcher, subject := newReferrersFetcher(t, name, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "" {
			w.Header().Set("Content-Type", ocispec.MediaTypeImageIndex)
			w.Header().Set("Link", `<?page=two>; rel="next"`)
			w.Write(firstPage)
			return
		}
		http.NotFound(w, r)
	}))

	_, err := fetcher.FetchReferrers(context.Background(), subject)
	if err == nil {
		t.Fatal("FetchReferrers() succeeded after a missing continuation page")
	}
	if errdefs.IsNotFound(err) {
		t.Fatalf("continuation error retained ErrNotFound identity: %v", err)
	}
}

func TestFetchReferrersContinuationPreservesCancellation(t *testing.T) {
	const name = "canceled-continuation"
	firstPage := newIndex().OCIManifest()
	ctx, cancel := context.WithCancel(context.Background())
	fetcher, subject := newReferrersFetcher(t, name, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "" {
			w.Header().Set("Content-Type", ocispec.MediaTypeImageIndex)
			w.Header().Set("Link", `<?page=two>; rel="next"`)
			w.Write(firstPage)
			return
		}
		cancel()
		<-r.Context().Done()
	}))

	_, err := fetcher.FetchReferrers(ctx, subject)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("FetchReferrers() error = %v, want context cancellation", err)
	}
}

func TestFetchReferrersDescriptorLimit(t *testing.T) {
	const name = "descriptor-limit"
	manifests := make([]testContent, maxReferrerDescriptors+1)
	for i := range manifests {
		manifests[i] = newContent(ocispec.MediaTypeImageManifest, []byte(fmt.Sprintf("referrer-%d", i)))
	}
	index := newIndex(manifests...).OCIManifest()
	fetcher, subject := newReferrersFetcher(t, name, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ocispec.MediaTypeImageIndex)
		w.Write(index)
	}))

	_, err := fetcher.FetchReferrers(context.Background(), subject)
	if err == nil || !strings.Contains(err.Error(), "more than 4096 descriptors") {
		t.Fatalf("FetchReferrers() error = %v, want descriptor limit", err)
	}
}

func TestFetchReferrersTotalSizeLimit(t *testing.T) {
	const name = "total-size-limit"
	firstPage := newIndex(
		newContent(ocispec.MediaTypeImageManifest, []byte(strings.Repeat("a", 64))),
	).OCIManifest()
	secondPage := newIndex(
		newContent(ocispec.MediaTypeImageManifest, []byte(strings.Repeat("b", 64))),
	).OCIManifest()

	oldMaxManifestSize := MaxManifestSize
	MaxManifestSize = int64(len(firstPage) + len(secondPage) - 1)
	t.Cleanup(func() {
		MaxManifestSize = oldMaxManifestSize
	})

	fetcher, subject := newReferrersFetcher(t, name, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ocispec.MediaTypeImageIndex)
		if r.URL.Query().Get("page") == "" {
			w.Header().Set("Link", `<?page=two>; rel="next"`)
			w.Write(firstPage)
			return
		}
		w.Write(secondPage)
	}))

	_, err := fetcher.FetchReferrers(context.Background(), subject)
	if err == nil || !strings.Contains(err.Error(), "exceeds maximum") {
		t.Fatalf("FetchReferrers() error = %v, want aggregate size limit", err)
	}
}

func TestFetchReferrersCompressedDecodedSizeLimit(t *testing.T) {
	const name = "compressed-size-limit"
	index := newIndex().OCIManifest()
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(index); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if compressed.Len() <= len(index) {
		t.Fatalf("test requires encoded size %d to exceed decoded size %d", compressed.Len(), len(index))
	}

	oldMaxManifestSize := MaxManifestSize
	MaxManifestSize = int64(len(index))
	t.Cleanup(func() {
		MaxManifestSize = oldMaxManifestSize
	})

	fetcher, subject := newReferrersFetcher(t, name, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ocispec.MediaTypeImageIndex)
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(compressed.Bytes())
	}))

	refs, err := fetcher.FetchReferrers(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 0 {
		t.Fatalf("compressed empty index returned %d referrers", len(refs))
	}
}

func TestNextLink(t *testing.T) {
	tests := []struct {
		name      string
		values    []string
		want      string
		wantError bool
	}{
		{
			name:   "next among multiple links",
			values: []string{`</previous>; rel="prev", </next?cursor=a,b>; rel="next"; title="a;b"`},
			want:   "/next?cursor=a,b",
		},
		{
			name:   "no next relation",
			values: []string{`</previous>; rel="prev"`},
		},
		{
			name:      "malformed link",
			values:    []string{`</next; rel="next"`},
			wantError: true,
		},
		{
			name:      "multiple next links",
			values:    []string{`</one>; rel="next", </two>; rel="next"`},
			wantError: true,
		},
		{
			name:   "valid extensions and repeated target",
			values: []string{`</next>; rel="next"; type=application/vnd.oci.image.index.v1+json; extension, </next>; rel=next,`},
			want:   "/next",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := nextLink(test.values)
			if got != test.want {
				t.Fatalf("nextLink() = %q, want %q", got, test.want)
			}
			if (err != nil) != test.wantError {
				t.Fatalf("nextLink() error = %v, wantError %v", err, test.wantError)
			}
		})
	}
}

func TestNextReferrersRequest(t *testing.T) {
	current := &request{
		method: http.MethodGet,
		path:   "/v2/repository/referrers/sha256:subject?artifactType=signature&ns=source.example",
		host: RegistryHost{
			Scheme: "https",
			Host:   "registry.example",
		},
	}
	fixed := url.Values{
		"artifactType": {"signature"},
		"ns":           {"source.example"},
	}

	next, canonical, err := nextReferrersRequest(current, fixed, "?last=cursor")
	if err != nil {
		t.Fatal(err)
	}
	query, err := requestQuery(next)
	if err != nil {
		t.Fatal(err)
	}
	if query.Get("last") != "cursor" ||
		query.Get("artifactType") != "signature" ||
		query.Get("ns") != "source.example" {
		t.Fatalf("next request query = %v", query)
	}
	if canonical != "https://registry.example/v2/repository/referrers/sha256:subject?artifactType=signature&last=cursor&ns=source.example" {
		t.Fatalf("canonical URL = %q", canonical)
	}

	if _, canonical, err := nextReferrersRequest(
		current,
		fixed,
		"https://registry.example:443/v2/repository/referrers/sha256:subject?last=cursor",
	); err != nil {
		t.Fatalf("explicit default port was rejected: %v", err)
	} else if canonical != "https://registry.example/v2/repository/referrers/sha256:subject?artifactType=signature&last=cursor&ns=source.example" {
		t.Fatalf("default-port canonical URL = %q", canonical)
	}

	explicitPortCurrent := current.clone()
	explicitPortCurrent.host.Host = "registry.example:443"
	if _, canonical, err := nextReferrersRequest(
		explicitPortCurrent,
		fixed,
		"https://registry.example/v2/repository/referrers/sha256:subject?last=cursor",
	); err != nil {
		t.Fatalf("implicit default port was rejected: %v", err)
	} else if canonical != "https://registry.example:443/v2/repository/referrers/sha256:subject?artifactType=signature&last=cursor&ns=source.example" {
		t.Fatalf("implicit-port canonical URL = %q", canonical)
	}

	for _, link := range []string{
		"https://other.example/v2/repository/referrers/sha256:subject?last=cursor",
		"https://registry.example:444/v2/repository/referrers/sha256:subject?last=cursor",
		"/v2/other/referrers/sha256:subject?last=cursor",
		"?last=cursor#fragment",
	} {
		if _, _, err := nextReferrersRequest(current, fixed, link); err == nil {
			t.Fatalf("nextReferrersRequest(%q) unexpectedly succeeded", link)
		}
	}

	encodedLink := "/v2%2Frepository/referrers/sha256%3Asubject?ns=source.example&token=a%2Fb&artifactType=signature"
	next, _, err = nextReferrersRequest(current, fixed, encodedLink)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(next.path, "/v2/repository/referrers/sha256:subject?") {
		t.Fatalf("request did not retain the original endpoint: %q", next.path)
	}
	if !strings.HasSuffix(next.path, "?ns=source.example&token=a%2Fb&artifactType=signature") {
		t.Fatalf("opaque query was rewritten: %q", next.path)
	}
}

func TestFetchReferrers(t *testing.T) {
	t.Run("basic", func(t *testing.T) {
		runReferrersTest(t, "testname", tlsServer)
	})
	t.Run("missing length", func(t *testing.T) {
		runReferrersTest(t, "testname", tlsServer, func(tc *testContent) {
			tc.skipLength = true
		})
	})
	t.Run("too long", func(t *testing.T) {
		runReferrersTest(t, "testname", tlsServer, func(tc *testContent) {
			tc.content = make([]byte, MaxManifestSize+1)
		})
	})
}

func runReferrersTest(t *testing.T, name string, sf func(h http.Handler) (string, ResolverOptions, func()), ropts ...contentOpt) {
	var (
		ctx = context.Background()
		r   = http.NewServeMux()
	)

	m := newManifest(
		newContent(ocispec.MediaTypeImageConfig, []byte("1")),
		newContent(ocispec.MediaTypeImageLayerGzip, []byte("2")),
	)
	mc := newContent(ocispec.MediaTypeImageManifest, m.OCIManifest())

	i := newIndex(
		newContent(ocispec.MediaTypeImageManifest, []byte("some signature manifest"), withArtifactType("application/vnd.test.sig")),
		newContent(ocispec.MediaTypeImageManifest, []byte("some sbom"), withArtifactType("application/vnd.test.sbom")),
	)
	ic := newContent(ocispec.MediaTypeImageIndex, i.OCIManifest(), ropts...)

	m.RegisterHandler(r, name)
	i.RegisterHandler(r, name)
	r.Handle(fmt.Sprintf("/v2/%s/manifests/%s", name, mc.Digest()), mc)
	r.Handle(fmt.Sprintf("/v2/%s/referrers/%s", name, mc.Digest()), ic)
	r.Handle(fmt.Sprintf("/v2/%s/manifests/%s", name, strings.Replace(mc.Digest().String(), ":", "-", 1)), ic)

	base, ro, close := sf(logHandler{t, r})
	defer close()

	resolver := NewResolver(ro)
	image := fmt.Sprintf("%s/%s@%s", base, name, mc.Digest())

	_, d, err := resolver.Resolve(ctx, image)
	if err != nil {
		t.Fatal(err)
	}
	f, err := resolver.Fetcher(ctx, image)
	if err != nil {
		t.Fatal(err)
	}

	rf := f.(remotes.ReferrersFetcher)

	refs, err := rf.FetchReferrers(ctx, d.Digest)
	if len(ic.content) > int(MaxManifestSize) {
		if err == nil {
			t.Fatal("expected error for exceeding max size")
		}
		if !strings.Contains(err.Error(), "exceeds maximum allowed") {
			t.Fatalf("unexpected error: %v", err)
		}
		if !errdefs.IsNotFound(err) {
			t.Fatalf("unexpected error type: %v", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}

	if len(refs) != 2 {
		t.Fatalf("Unexpected number of references: %d, expected 2", len(refs))
	}

	for _, ref := range refs {
		if err := testFetch(ctx, f, ref); err != nil {
			t.Fatal(err)
		}
	}

	refs, err = rf.FetchReferrers(ctx, d.Digest, remotes.WithReferrerArtifactTypes("application/vnd.test.sig"))
	if err != nil {
		t.Fatal(err)
	}

	if len(refs) != 1 {
		t.Fatalf("Unexpected number of references: %d, expected 1", len(refs))
	}

	for _, ref := range refs {
		if ref.ArtifactType != "application/vnd.test.sig" {
			t.Fatalf("Unexpected artifact type: %q", ref.ArtifactType)
		}
	}
}

func newReferrersFetcher(t *testing.T, name string, handler http.Handler) (remotes.ReferrersFetcher, digest.Digest) {
	t.Helper()

	subject := newContent(ocispec.MediaTypeImageManifest, []byte(`{"schemaVersion":2}`))
	mux := http.NewServeMux()
	mux.Handle(fmt.Sprintf("/v2/%s/manifests/%s", name, subject.Digest()), subject)
	mux.Handle(fmt.Sprintf("/v2/%s/referrers/%s", name, subject.Digest()), handler)

	base, options, closeServer := tlsServer(logHandler{t, mux})
	t.Cleanup(closeServer)

	resolver := NewResolver(options)
	image := fmt.Sprintf("%s/%s@%s", base, name, subject.Digest())
	_, descriptor, err := resolver.Resolve(context.Background(), image)
	if err != nil {
		t.Fatal(err)
	}
	fetcher, err := resolver.Fetcher(context.Background(), image)
	if err != nil {
		t.Fatal(err)
	}
	referrersFetcher, ok := fetcher.(remotes.ReferrersFetcher)
	if !ok {
		t.Fatal("docker fetcher does not implement ReferrersFetcher")
	}
	return referrersFetcher, descriptor.Digest
}

type testIndex struct {
	manifests []testContent
}

func newIndex(manifests ...testContent) testIndex {
	return testIndex{
		manifests: manifests,
	}
}

func (ti testIndex) OCIManifest() []byte {
	manifest := ocispec.Index{
		Versioned: specs.Versioned{
			SchemaVersion: 2,
		},
		Manifests: make([]ocispec.Descriptor, len(ti.manifests)),
	}
	for i, c := range ti.manifests {
		manifest.Manifests[i] = c.Descriptor()
	}
	b, _ := json.Marshal(manifest)
	return b
}

func (ti testIndex) RegisterHandler(r *http.ServeMux, name string) {
	for _, c := range ti.manifests {
		r.Handle(fmt.Sprintf("/v2/%s/blobs/%s", name, c.Digest()), c)
		r.Handle(fmt.Sprintf("/v2/%s/manifests/%s", name, c.Digest()), c)
	}
}
