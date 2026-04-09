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
	"io"
	"sync"
	"time"

	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/errdefs"
	"github.com/containerd/log"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	// TargetLayerSignatureLabel contains the base64-encoded signature for dm-verity verification
	TargetLayerSignatureLabel = "containerd.io/snapshot/dmverity.layer-signature"

	// TargetLayerRootHashLabel contains the dm-verity root hash for the layer
	TargetLayerRootHashLabel = "containerd.io/snapshot/dmverity.layer-roothash"

	// Annotation keys used in signature manifest layers
	sigLayerDigestAnnotation    = "io.cncf.notary.dmverity.layer-digest"
	sigLayerRootHashAnnotation  = "io.cncf.notary.dmverity.layer-roothash"
	sigLayerSignatureAnnotation = "io.cncf.notary.dmverity.layer-signature"

	// SignatureArtifactType is the artifact type for OCI referrers containing dm-verity signatures
	SignatureArtifactType = "application/vnd.cncf.notary.dmverity.v1"

	// ociAnnotationCreated is the OCI annotation for creation timestamp
	ociAnnotationCreated = "org.opencontainers.image.created"
)

// LayerSignatureInfo contains signature information for a layer
type LayerSignatureInfo struct {
	RootHash  string
	Signature string
}

// fetchSignatures fetches dm-verity signatures from the registry using OCI referrers API.
// Returns a map of layerDigest -> LayerSignatureInfo.
func fetchSignatures(ctx context.Context, fetcher remotes.Fetcher, manifestDigest digest.Digest) map[string]*LayerSignatureInfo {
	signatures := make(map[string]*LayerSignatureInfo)

	refFetcher, ok := fetcher.(remotes.ReferrersFetcher)
	if !ok {
		log.G(ctx).Debug("Fetcher does not support referrers API, skipping signature fetch")
		return signatures
	}

	// Fetch signature referrers for this manifest
	referrers, err := refFetcher.FetchReferrers(ctx, manifestDigest,
		remotes.WithReferrerArtifactTypes(SignatureArtifactType))
	if err != nil {
		if errdefs.IsNotFound(err) {
			log.G(ctx).Debug("No signature referrers found")
			return signatures
		}
		log.G(ctx).WithError(err).Debug("Failed to fetch referrers")
		return signatures
	}

	if len(referrers) == 0 {
		log.G(ctx).Debug("No signature artifacts found for manifest")
		return signatures
	}

	log.G(ctx).WithField("count", len(referrers)).WithField("manifest", manifestDigest).Info("Fetching dm-verity signature artifacts")

	// Fetch all referrer manifests and find the newest one by timestamp
	type referrerWithManifest struct {
		desc      ocispec.Descriptor
		manifest  ocispec.Manifest
		createdAt time.Time
	}

	var parsedReferrers []referrerWithManifest
	for _, refDesc := range referrers {
		rc, err := fetcher.Fetch(ctx, refDesc)
		if err != nil {
			log.G(ctx).WithError(err).WithField("digest", refDesc.Digest).Warn("Failed to fetch signature manifest")
			continue
		}

		manifestData, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			log.G(ctx).WithError(err).Warn("Failed to read signature manifest")
			continue
		}

		var sigManifest ocispec.Manifest
		if err := json.Unmarshal(manifestData, &sigManifest); err != nil {
			log.G(ctx).WithError(err).Warn("Failed to unmarshal signature manifest")
			continue
		}

		// Parse the creation timestamp from annotations
		var createdAt time.Time
		if sigManifest.Annotations != nil {
			if createdStr, ok := sigManifest.Annotations[ociAnnotationCreated]; ok {
				if t, err := time.Parse(time.RFC3339, createdStr); err == nil {
					createdAt = t
					log.G(ctx).WithFields(log.Fields{
						"digest":  refDesc.Digest,
						"created": createdStr,
					}).Debug("Parsed referrer creation timestamp")
				}
			}
		}

		parsedReferrers = append(parsedReferrers, referrerWithManifest{
			desc:      refDesc,
			manifest:  sigManifest,
			createdAt: createdAt,
		})
	}

	if len(parsedReferrers) == 0 {
		log.G(ctx).Debug("No valid signature manifests found")
		return signatures
	}

	// Find the newest referrer by timestamp
	newestIdx := 0
	for i := 1; i < len(parsedReferrers); i++ {
		if parsedReferrers[i].createdAt.After(parsedReferrers[newestIdx].createdAt) {
			newestIdx = i
		}
	}

	newestReferrer := parsedReferrers[newestIdx]
	log.G(ctx).WithFields(log.Fields{
		"digest":  newestReferrer.desc.Digest,
		"created": newestReferrer.createdAt,
		"total":   len(parsedReferrers),
	}).Info("Using newest signature referrer")

	// Extract signature data from the newest referrer's layer annotations
	for _, layer := range newestReferrer.manifest.Layers {
		if layer.Annotations == nil {
			continue
		}

		layerDigest := layer.Annotations[sigLayerDigestAnnotation]
		rootHash := layer.Annotations[sigLayerRootHashAnnotation]
		signature := layer.Annotations[sigLayerSignatureAnnotation]

		if layerDigest != "" && rootHash != "" && signature != "" {
			signatures[layerDigest] = &LayerSignatureInfo{
				RootHash:  rootHash,
				Signature: signature,
			}
			log.G(ctx).WithFields(log.Fields{
				"layer":     layerDigest,
				"roothash":  rootHash,
				"signature": signature[:min(len(signature), 32)] + "...",
			}).Info("Found dm-verity signature for layer")
		}
	}

	log.G(ctx).WithField("manifest", manifestDigest).Info("Signatures fetched successfully")
	return signatures
}

// AppendSignatureHandlerWrapper creates a handler that fetches signatures when processing
// a manifest and adds signature annotations to layer descriptors.
// This should wrap the handler AFTER AppendInfoHandlerWrapper.
func AppendSignatureHandlerWrapper(fetcher remotes.Fetcher) func(f images.Handler) images.Handler {
	return func(f images.Handler) images.Handler {
		return signatureHandler(f, fetcher)
	}
}

// AppendSignatureHandlerWrapperFromResolver creates a signature handler wrapper using a resolver.
// The fetcher is lazily created from the resolver when the handler is first invoked.
// This is useful for the CRI path where the resolver is available at option setup time,
// but the fetcher needs to be created later.
func AppendSignatureHandlerWrapperFromResolver(resolver remotes.Resolver, ref string) func(f images.Handler) images.Handler {
	var (
		fetcher     remotes.Fetcher
		fetcherOnce sync.Once
		fetcherErr  error
	)

	return func(f images.Handler) images.Handler {
		return images.HandlerFunc(func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
			// Lazily initialize the fetcher
			fetcherOnce.Do(func() {
				fetcher, fetcherErr = resolver.Fetcher(ctx, ref)
				if fetcherErr != nil {
					log.G(ctx).WithError(fetcherErr).Warn("Failed to create fetcher for signature lookup")
				} else {
					log.G(ctx).Debug("Created fetcher for signature lookup")
				}
			})

			// If we couldn't create a fetcher, just pass through
			if fetcherErr != nil || fetcher == nil {
				return f.Handle(ctx, desc)
			}

			return signatureHandler(f, fetcher).Handle(ctx, desc)
		})
	}
}

// signatureHandler is the core handler logic for fetching and attaching signatures
func signatureHandler(f images.Handler, fetcher remotes.Fetcher) images.Handler {
	return images.HandlerFunc(func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		children, err := f.Handle(ctx, desc)
		if err != nil {
			return nil, err
		}

		// When we encounter a manifest, fetch signatures for it
		if images.IsManifestType(desc.MediaType) {
			// Fetch signatures directly - no global cache needed
			signatures := fetchSignatures(ctx, fetcher, desc.Digest)

			// Add signature annotations to layer descriptors
			for i := range children {
				c := &children[i]
				if images.IsLayerType(c.MediaType) {
					if sig, ok := signatures[c.Digest.String()]; ok {
						if c.Annotations == nil {
							c.Annotations = make(map[string]string)
						}
						c.Annotations[TargetLayerSignatureLabel] = sig.Signature
						c.Annotations[TargetLayerRootHashLabel] = sig.RootHash
						log.G(ctx).WithField("layer", c.Digest).Debug("Added signature annotations to layer")
					}
				}
			}
		}

		return children, nil
	})
}
