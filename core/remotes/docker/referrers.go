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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/errdefs"
	"github.com/containerd/log"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	maxReferrerPages       = 64
	maxReferrerDescriptors = 4096
)

type referrersPage struct {
	response        *http.Response
	request         *request
	allowPagination bool
	fixedQuery      url.Values
}

func (r dockerFetcher) FetchReferrers(ctx context.Context, dgst digest.Digest, opts ...remotes.FetchReferrersOpt) ([]ocispec.Descriptor, error) {
	var config remotes.FetchReferrersConfig
	for _, opt := range opts {
		if err := opt(ctx, &config); err != nil {
			return nil, err
		}
	}

	ctx, err := ContextWithRepositoryScope(ctx, r.refspec, false)
	if err != nil {
		return nil, err
	}
	page, err := r.openReferrers(ctx, dgst, config)
	if err != nil {
		if errdefs.IsNotFound(err) {
			return []ocispec.Descriptor{}, nil
		}
		return nil, err
	}

	tFilter := map[string]struct{}{}
	for _, artifactType := range config.ArtifactTypes {
		tFilter[artifactType] = struct{}{}
	}

	var (
		referrers       []ocispec.Descriptor
		descriptorCount int
		totalBytes      int64
		seenPages       = map[string]struct{}{page.request.String(): {}}
	)
	for pageNumber := 1; ; pageNumber++ {
		remaining := MaxManifestSize - totalBytes
		manifests, readBytes, decodeErr := decodeReferrersIndex(
			page.response.Body,
			page.response.ContentLength,
			remaining,
			maxReferrerDescriptors-descriptorCount,
		)
		closeErr := page.response.Body.Close()
		if decodeErr != nil {
			if pageNumber > 1 {
				// NotFound is meaningful only for the initial endpoint. A
				// missing or rejected continuation page is incomplete data.
				if errdefs.IsNotFound(decodeErr) {
					return nil, fmt.Errorf("decode referrers page %d: %v", pageNumber, decodeErr)
				}
				return nil, fmt.Errorf("decode referrers page %d: %w", pageNumber, decodeErr)
			}
			return nil, decodeErr
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close referrers response: %w", closeErr)
		}
		totalBytes += readBytes

		descriptorCount += len(manifests)
		if len(tFilter) == 0 {
			referrers = append(referrers, manifests...)
		} else {
			for _, desc := range manifests {
				if _, ok := tFilter[desc.ArtifactType]; ok {
					referrers = append(referrers, desc)
				}
			}
		}

		if !page.allowPagination {
			break
		}
		next, err := nextLink(page.response.Header.Values("Link"))
		if err != nil {
			return nil, err
		}
		if next == "" {
			break
		}
		if pageNumber == maxReferrerPages {
			return nil, fmt.Errorf("referrers index exceeds maximum page count %d", maxReferrerPages)
		}

		nextRequest, canonicalURL, err := nextReferrersRequest(page.request, page.fixedQuery, next)
		if err != nil {
			return nil, err
		}
		if _, ok := seenPages[canonicalURL]; ok {
			return nil, fmt.Errorf("referrers pagination loop detected at %q", canonicalURL)
		}
		seenPages[canonicalURL] = struct{}{}

		// Pagination is tied to the selected host and cursor. No host fallback
		// follows this request, so enable the request helper's terminal-host
		// retry behavior for transient registry errors.
		response, err := r.openReferrersRequest(ctx, nextRequest, true)
		if err != nil {
			// Do not preserve ErrNotFound here: losing a continuation page
			// must not be interpreted as an empty referrers list.
			if errdefs.IsNotFound(err) {
				return nil, fmt.Errorf("fetch referrers page %d: %v", pageNumber+1, err)
			}
			return nil, fmt.Errorf("fetch referrers page %d: %w", pageNumber+1, err)
		}
		page.response = response
		page.request = nextRequest
		// fixedQuery and allowPagination remain tied to the selected registry
		// endpoint from the first page.
	}
	return referrers, nil
}

func decodeReferrersIndex(body io.Reader, contentLength, byteLimit int64, descriptorLimit int) ([]ocispec.Descriptor, int64, error) {
	if byteLimit <= 0 {
		return nil, 0, fmt.Errorf("referrers index exceeds maximum total size %d", MaxManifestSize)
	}
	if contentLength > byteLimit {
		return nil, 0, fmt.Errorf(
			"referrers index size %d exceeds maximum allowed %d: %w",
			contentLength,
			byteLimit,
			errdefs.ErrNotFound,
		)
	}

	counter := &countingReader{reader: io.LimitReader(body, byteLimit+1)}
	dec := json.NewDecoder(counter)
	token, err := dec.Token()
	if err != nil {
		return nil, counter.bytesRead, fmt.Errorf("failed to decode referrers index: %w", err)
	}
	if token != json.Delim('{') {
		return nil, counter.bytesRead, fmt.Errorf("referrers index is not a JSON object")
	}

	var (
		manifests        []ocispec.Descriptor
		manifestsDecoded bool
	)
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return nil, counter.bytesRead, fmt.Errorf("failed to decode referrers index field: %w", err)
		}
		field, ok := token.(string)
		if !ok {
			return nil, counter.bytesRead, fmt.Errorf("referrers index field name is not a string")
		}
		if field != "manifests" {
			var ignored json.RawMessage
			if err := dec.Decode(&ignored); err != nil {
				return nil, counter.bytesRead, fmt.Errorf("failed to decode referrers index field %q: %w", field, err)
			}
			continue
		}
		if manifestsDecoded {
			return nil, counter.bytesRead, fmt.Errorf("referrers index contains duplicate manifests fields")
		}
		manifestsDecoded = true

		token, err = dec.Token()
		if err != nil {
			return nil, counter.bytesRead, fmt.Errorf("failed to decode referrers manifests: %w", err)
		}
		if token != json.Delim('[') {
			return nil, counter.bytesRead, fmt.Errorf("referrers index manifests is not a JSON array")
		}
		for dec.More() {
			if len(manifests) >= descriptorLimit {
				return nil, counter.bytesRead, fmt.Errorf(
					"referrers index contains more than %d descriptors",
					maxReferrerDescriptors,
				)
			}
			var descriptor ocispec.Descriptor
			if err := dec.Decode(&descriptor); err != nil {
				return nil, counter.bytesRead, fmt.Errorf("failed to decode referrer descriptor: %w", err)
			}
			manifests = append(manifests, descriptor)
		}
		if _, err := dec.Token(); err != nil {
			return nil, counter.bytesRead, fmt.Errorf("failed to close referrers manifests array: %w", err)
		}
	}
	if _, err := dec.Token(); err != nil {
		return nil, counter.bytesRead, fmt.Errorf("failed to close referrers index: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, counter.bytesRead, fmt.Errorf("unexpected data after JSON object")
	}
	if counter.bytesRead > byteLimit {
		return nil, counter.bytesRead, fmt.Errorf("referrers index exceeds maximum total size %d", MaxManifestSize)
	}
	return manifests, counter.bytesRead, nil
}

func nextReferrersRequest(current *request, fixedQuery url.Values, link string) (*request, string, error) {
	baseURL, err := url.Parse(current.String())
	if err != nil {
		return nil, "", fmt.Errorf("parse current referrers URL: %w", err)
	}
	linkURL, err := url.Parse(link)
	if err != nil {
		return nil, "", fmt.Errorf("parse referrers pagination link %q: %w", link, err)
	}
	if linkURL.User != nil || linkURL.Fragment != "" {
		return nil, "", fmt.Errorf("referrers pagination link %q contains user information or a fragment", link)
	}

	nextURL := baseURL.ResolveReference(linkURL)
	if !sameOrigin(nextURL, baseURL) {
		return nil, "", fmt.Errorf("referrers pagination link %q changes registry origin", link)
	}
	if nextURL.Path != baseURL.Path {
		return nil, "", fmt.Errorf("referrers pagination link %q changes the referrers endpoint", link)
	}

	query := nextURL.Query()
	rewriteQuery := false
	for key, values := range fixedQuery {
		if slices.Equal(query[key], values) {
			continue
		}
		query[key] = append([]string(nil), values...)
		rewriteQuery = true
	}
	if rewriteQuery {
		nextURL.RawQuery = query.Encode()
	}

	nextRequest := current.clone()
	nextRequest.path = baseURL.EscapedPath()
	if nextURL.ForceQuery || nextURL.RawQuery != "" {
		nextRequest.path += "?" + nextURL.RawQuery
	}
	return nextRequest, nextRequest.String(), nil
}

func sameOrigin(first, second *url.URL) bool {
	return strings.EqualFold(first.Scheme, second.Scheme) &&
		strings.EqualFold(first.Hostname(), second.Hostname()) &&
		effectivePort(first) == effectivePort(second)
}

func effectivePort(value *url.URL) string {
	if port := value.Port(); port != "" {
		return port
	}
	switch strings.ToLower(value.Scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}

func nextLink(values []string) (string, error) {
	var next string
	for _, value := range values {
		links, err := splitLinkHeader(value)
		if err != nil {
			return "", fmt.Errorf("parse referrers Link header: %w", err)
		}
		for _, link := range links {
			link = strings.TrimSpace(link)
			if !strings.HasPrefix(link, "<") {
				return "", fmt.Errorf("parse referrers Link header: link %q does not start with '<'", link)
			}
			end := strings.IndexByte(link, '>')
			if end < 0 {
				return "", fmt.Errorf("parse referrers Link header: link %q has no closing '>'", link)
			}
			target := link[1:end]
			if target == "" {
				return "", fmt.Errorf("parse referrers Link header: link target is empty")
			}

			parameters := strings.TrimSpace(link[end+1:])
			if parameters == "" {
				continue
			}
			if !strings.HasPrefix(parameters, ";") {
				return "", fmt.Errorf("parse referrers Link header: link %q has malformed parameters", link)
			}
			parameters = strings.TrimRight(parameters, " \t;")
			if parameters == "" {
				continue
			}
			parts, err := splitLinkValue(strings.TrimPrefix(parameters, ";"), ';')
			if err != nil {
				return "", fmt.Errorf("parse referrers Link header: %w", err)
			}
			for _, part := range parts {
				key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
				if !ok || !strings.EqualFold(strings.TrimSpace(key), "rel") {
					continue
				}
				value = strings.TrimSpace(value)
				if strings.HasPrefix(value, `"`) {
					if len(value) < 2 || !strings.HasSuffix(value, `"`) {
						return "", fmt.Errorf("parse referrers Link header: malformed rel parameter %q", value)
					}
					value = value[1 : len(value)-1]
				}
				for _, relation := range strings.Fields(value) {
					if !strings.EqualFold(relation, "next") {
						continue
					}
					if next != "" && next != target {
						return "", fmt.Errorf("referrers Link header contains conflicting next links")
					}
					next = target
				}
			}
		}
	}
	return next, nil
}

func splitLinkHeader(value string) ([]string, error) {
	return splitLinkValue(value, ',')
}

func splitLinkValue(value string, separator byte) ([]string, error) {
	var (
		parts   []string
		start   int
		inAngle bool
		inQuote bool
		escaped bool
	)
	for i := range len(value) {
		char := value[i]
		switch {
		case escaped:
			escaped = false
		case inQuote && char == '\\':
			escaped = true
		case char == '"':
			inQuote = !inQuote
		case !inQuote && char == '<':
			if inAngle {
				return nil, fmt.Errorf("nested '<' in %q", value)
			}
			inAngle = true
		case !inQuote && char == '>':
			if !inAngle {
				return nil, fmt.Errorf("unexpected '>' in %q", value)
			}
			inAngle = false
		case !inQuote && !inAngle && char == separator:
			if part := strings.TrimSpace(value[start:i]); part != "" {
				parts = append(parts, part)
			}
			start = i + 1
		}
	}
	if escaped || inQuote || inAngle {
		return nil, fmt.Errorf("unterminated Link header value %q", value)
	}
	if part := strings.TrimSpace(value[start:]); part != "" {
		parts = append(parts, part)
	}
	return parts, nil
}

func requestQuery(req *request) (url.Values, error) {
	requestURL, err := url.Parse(req.String())
	if err != nil {
		return nil, err
	}
	return requestURL.Query(), nil
}

func (r dockerFetcher) openReferrersRequest(ctx context.Context, req *request, lastHost bool) (*http.Response, error) {
	req.setMediaType(ocispec.MediaTypeImageIndex)
	// Referrers indexes are small JSON responses. Let net/http negotiate and
	// transparently decode gzip so ContentLength describes decoded data (or is
	// unknown) and the aggregate byte limit remains unambiguous.
	req.header.Del("Accept-Encoding")
	if err := r.Acquire(ctx, 1); err != nil {
		return nil, err
	}
	response, err := req.doWithRetries(ctx, lastHost, withErrorCheck)
	if err != nil {
		r.Release(1)
		return nil, err
	}
	if encoding := response.Header.Get("Content-Encoding"); encoding != "" &&
		!strings.EqualFold(encoding, "identity") && !response.Uncompressed {
		response.Body.Close()
		r.Release(1)
		return nil, fmt.Errorf("unsupported referrers content encoding %q", encoding)
	}
	response.Body = &fnOnClose{
		BeforeClose: func() {
			r.Release(1)
		},
		ReadCloser: response.Body,
	}
	return response, nil
}

func (r dockerFetcher) openReferrers(ctx context.Context, dgst digest.Digest, config remotes.FetchReferrersConfig) (*referrersPage, error) {
	ctx = log.WithLogger(ctx, log.G(ctx).WithField("digest", dgst))

	hosts := r.filterHosts(HostCapabilityReferrers)
	var fallbackHosts []RegistryHost
	if len(hosts) == 0 {
		fallbackHosts = r.filterHosts(HostCapabilityResolve)
		if len(fallbackHosts) == 0 {
			return nil, fmt.Errorf("no referrers hosts: %w", errdefs.ErrNotFound)
		}
	} else {
		// If referrers are defined, use same hosts for fallback
		fallbackHosts = hosts
	}

	var firstErr error
	for i, host := range hosts {
		req := r.request(host, http.MethodGet, "referrers", dgst.String())
		for _, artifactType := range config.ArtifactTypes {
			if err := req.addQuery("artifactType", artifactType); err != nil {
				return nil, err
			}
		}
		for k, vs := range config.QueryFilters {
			for _, v := range vs {
				if err := req.addQuery(k, v); err != nil {
					return nil, err
				}
			}
		}
		if err := req.addNamespace(r.refspec.Hostname()); err != nil {
			return nil, err
		}

		fixedQuery, err := requestQuery(req)
		if err != nil {
			return nil, err
		}
		response, err := r.openReferrersRequest(ctx, req, i == len(hosts)-1)
		if err != nil {
			if !errdefs.IsNotFound(err) {
				log.G(ctx).WithError(err).WithField("host", host.Host).Debug("error fetching referrers")
				if firstErr == nil {
					firstErr = err
				}
			}
		} else {
			return &referrersPage{
				response:        response,
				request:         req,
				allowPagination: true,
				fixedQuery:      fixedQuery,
			}, nil
		}
	}

	for i, host := range fallbackHosts {
		req := r.request(host, http.MethodGet, "manifests", strings.Replace(dgst.String(), ":", "-", 1))
		if err := req.addNamespace(r.refspec.Hostname()); err != nil {
			return nil, err
		}
		response, err := r.openReferrersRequest(ctx, req, i == len(fallbackHosts)-1)
		if err != nil {
			if errdefs.IsNotFound(err) {
				// Equivalent to empty referrers list
				firstErr = err
				break
			}
			log.G(ctx).WithError(err).WithField("host", host.Host).Debug("error fetching referrers via fallback")
			if firstErr == nil {
				firstErr = err
			}
		} else {
			return &referrersPage{
				response: response,
				request:  req,
			}, nil
		}
	}
	if firstErr == nil {
		firstErr = fmt.Errorf("could not be found at any host: %w", errdefs.ErrNotFound)
	}

	return nil, firstErr
}
