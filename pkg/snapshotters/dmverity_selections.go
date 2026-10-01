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
	"maps"
	"slices"
	"strings"
	"sync"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/platforms"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	imageDmverityReferrerLabel   = "containerd.io/gc.ref.content.dmverity-referrer/"
	imageDmverityNoReferrerLabel = "containerd.io/snapshot/erofs.dmverity.no-referrer/"
)

// DmveritySelections records each platform manifest's referrer during a pull, so
// aliases and concurrent re-signing cannot change what the image resolves to.
type DmveritySelections struct {
	mu     sync.Mutex
	labels map[string]string
}

// Record pins a manifest's selection. An empty referrer records known absence.
func (s *DmveritySelections) Record(subject, referrer digest.Digest) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.labels == nil {
		s.labels = make(map[string]string)
	}
	if referrer == "" {
		delete(s.labels, imageDmverityReferrerLabel+subject.Encoded())
		s.labels[imageDmverityNoReferrerLabel+subject.Encoded()] = "true"
		return
	}
	delete(s.labels, imageDmverityNoReferrerLabel+subject.Encoded())
	s.labels[imageDmverityReferrerLabel+subject.Encoded()] = referrer.String()
}

// ImageLabels adds the selected manifests to an image record.
func (s *DmveritySelections) ImageLabels(labels map[string]string) map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return WithDmverityImageSelectionLabels(labels, s.labels)
}

// WithDmverityImageSelectionLabels returns labels updated with the given selections.
func WithDmverityImageSelectionLabels(labels, selections map[string]string) map[string]string {
	merged := maps.Clone(labels)
	if merged == nil {
		merged = make(map[string]string, len(selections))
	}
	// Replace the opposite observation without disturbing unrelated image labels.
	for key, value := range selections {
		if suffix, ok := strings.CutPrefix(key, imageDmverityReferrerLabel); ok {
			delete(merged, imageDmverityNoReferrerLabel+suffix)
		} else if suffix, ok := strings.CutPrefix(key, imageDmverityNoReferrerLabel); ok {
			delete(merged, imageDmverityReferrerLabel+suffix)
		}
		merged[key] = value
	}
	return merged
}

func isDmverityImageSelectionLabel(key string) bool {
	return strings.HasPrefix(key, imageDmverityReferrerLabel) ||
		strings.HasPrefix(key, imageDmverityNoReferrerLabel)
}

// DmverityImageSelectionLabels returns only an image's selection labels.
func DmverityImageSelectionLabels(labels map[string]string) map[string]string {
	var selected map[string]string
	for key, value := range labels {
		if isDmverityImageSelectionLabel(key) {
			if selected == nil {
				selected = make(map[string]string)
			}
			selected[key] = value
		}
	}
	return selected
}

// DmveritySelectionFieldpaths returns image update fieldpaths for selection
// labels that differ between current and desired.
func DmveritySelectionFieldpaths(current, desired map[string]string) []string {
	var fieldpaths []string
	for _, labels := range []map[string]string{current, desired} {
		for key := range labels {
			if isDmverityImageSelectionLabel(key) && current[key] != desired[key] &&
				!slices.Contains(fieldpaths, "labels."+key) {
				fieldpaths = append(fieldpaths, "labels."+key)
			}
		}
	}
	return fieldpaths
}

func imageDmveritySelection(labels map[string]string, subject digest.Digest) (digest.Digest, bool, error) {
	referrerLabel := imageDmverityReferrerLabel + subject.Encoded()
	noneLabel := imageDmverityNoReferrerLabel + subject.Encoded()
	value, signed := labels[referrerLabel]
	none, observedNone := labels[noneLabel]
	if signed {
		if observedNone {
			return "", false, fmt.Errorf("conflicting image dm-verity selections for %s", subject)
		}
		referrer, err := digest.Parse(value)
		if err != nil {
			return "", false, fmt.Errorf("invalid image dm-verity referrer for %s: %w", subject, err)
		}
		return referrer, true, nil
	}
	if observedNone && none != "true" {
		return "", false, fmt.Errorf("invalid image dm-verity no-referrer observation for %s", subject)
	}
	return "", observedNone, nil
}

// DmveritySnapshotKey resolves the same materializations as deferred unpack.
func DmveritySnapshotKey(ctx context.Context, store content.Store, target ocispec.Descriptor, platform platforms.MatchComparer, diffIDs []digest.Digest, imageLabels map[string]string) (string, error) {
	if platform == nil {
		platform = platforms.All
	}
	// Follow the selected platform's manifests without walking layer payloads.
	childrenHandler := images.LimitManifests(
		images.FilterPlatforms(images.ChildrenHandler(store), platform), platform, 1,
	)
	handler := AppendCachedSignatureHandlerWrapper(store, imageLabels)(childrenHandler)
	var layers []ocispec.Descriptor
	if err := images.Walk(ctx, images.HandlerFunc(func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		children, err := handler.Handle(ctx, desc)
		if err != nil {
			return nil, err
		}
		if images.IsManifestType(desc.MediaType) {
			for _, child := range children {
				if images.IsLayerType(child.MediaType) {
					layers = append(layers, child)
				}
			}
			return nil, nil
		}
		return children, nil
	}), target); err != nil {
		return "", err
	}
	chainIDs, err := DmverityChainIDs(diffIDs, layers)
	if err != nil {
		return "", err
	}
	if len(chainIDs) == 0 {
		return "", nil
	}
	return chainIDs[len(chainIDs)-1].String(), nil
}

func loadRetainedDmverityBundle(
	ctx context.Context,
	store content.Store,
	subject ocispec.Descriptor,
	imageLayers map[string]struct{},
	imageLabels map[string]string,
) (map[string]*DmverityTarget, digest.Digest, bool, error) {
	referrerDigest, selected, err := imageDmveritySelection(imageLabels, subject.Digest)
	if err != nil {
		return nil, "", false, err
	}
	if !selected {
		return nil, "", false, nil
	}
	if referrerDigest == "" {
		return nil, "", true, nil
	}
	// Resolve the retained bundle and recheck its binding to the requested image layers.
	infos, err := readDmverityBundle(ctx, store, ocispec.Descriptor{Digest: referrerDigest}, subject, imageLayers)
	return infos, referrerDigest, true, err
}
