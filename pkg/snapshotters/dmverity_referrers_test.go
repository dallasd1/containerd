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
	"fmt"
	"testing"

	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/errdefs"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

func TestFetchSignaturesDiscovery(t *testing.T) {
	subject := ocispec.Descriptor{Digest: digest.FromString("subject")}
	for _, tc := range []struct {
		name       string
		fetcher    remotes.Fetcher
		discovered bool
		wantErr    error
	}{
		{"unsupported", plainTestFetcher{}, false, nil},
		{"empty result", signatureTestFetcher{}, true, nil},
		{"oversized index", signatureTestFetcher{err: fmt.Errorf("referrers index exceeds maximum allowed: %w", errdefs.ErrNotFound)}, false, errdefs.ErrNotFound},
		{"unavailable", signatureTestFetcher{err: errdefs.ErrUnavailable}, false, errdefs.ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bundle, discovered, err := fetchSignatures(t.Context(), tc.fetcher, nil, subject, nil)
			require.ErrorIs(t, err, tc.wantErr)
			require.Nil(t, bundle)
			require.Equal(t, tc.discovered, discovered)
		})
	}
}

func TestSignatureDiscoveryErrorPreservesSelection(t *testing.T) {
	subject := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageManifest,
		Digest:    digest.FromString("subject"),
	}
	selections := &DmveritySelections{}
	selections.Record(subject.Digest, digest.FromString("retained referrer"))
	before := selections.ImageLabels(nil)
	handler := AppendSignatureHandlerWrapper(
		signatureTestFetcher{err: fmt.Errorf("referrers index exceeds maximum allowed: %w", errdefs.ErrNotFound)},
		nil, selections,
	)(images.HandlerFunc(func(context.Context, ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		return nil, nil
	}))

	// No store is supplied: failed discovery must not access or clear the cache.
	_, err := handler.Handle(t.Context(), subject)
	require.ErrorIs(t, err, errdefs.ErrNotFound)
	require.Equal(t, before, selections.ImageLabels(nil))
}

type signatureTestFetcher struct {
	remotes.Fetcher
	err error
}

func (f signatureTestFetcher) FetchReferrers(context.Context, digest.Digest, ...remotes.FetchReferrersOpt) ([]ocispec.Descriptor, error) {
	return nil, f.err
}

type plainTestFetcher struct{ remotes.Fetcher }
