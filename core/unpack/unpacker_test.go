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

package unpack

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/diff"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/images/imagetest"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/core/snapshots"
	snpkg "github.com/containerd/containerd/v2/pkg/snapshotters"
	"github.com/containerd/containerd/v2/plugins"
	"github.com/containerd/errdefs"
	"github.com/containerd/platforms"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/semaphore"
)

func TestLayerPolicyCallbacks(t *testing.T) {
	for _, mode := range []string{"new snapshot", "prepare error", "cache hit", "concurrent commit"} {
		t.Run(mode, func(t *testing.T) {
			ctx := t.Context()
			store := imagetest.NewContentStore(ctx, t)
			layer := store.Blob(ocispec.MediaTypeImageLayerGzip, []byte("layer"))
			diffID := digest.FromString("uncompressed layer")
			config := store.JSONObject(ocispec.MediaTypeImageConfig, ocispec.Image{
				RootFS: ocispec.RootFS{Type: "layers", DiffIDs: []digest.Digest{diffID}},
			})
			manifest := store.Manifest(config, layer)
			sn := &recordingSnapshotter{committed: map[string]snapshots.Info{}}
			up := Platform{SnapshotterKey: "test", Snapshotter: sn, Applier: diffIDApplier{layer.Descriptor.Digest: diffID}}
			sentinel := errors.New("policy rejected layer")
			locker := &policyTestLocker{held: make(map[string]bool)}
			selectedKey := "policy-" + diffID.String()
			lockKey := "sn://test/" + selectedKey
			preparations := 0
			validations := 0
			up.PrepareLayer = func(_ context.Context, _ ocispec.Descriptor, chainID string) (snapshots.LayerPreparation, error) {
				preparations++
				require.Equal(t, diffID.String(), chainID)
				require.False(t, locker.isHeld(lockKey), "policy must be derived before locking")
				if mode == "prepare error" {
					return snapshots.LayerPreparation{}, sentinel
				}
				return snapshots.LayerPreparation{
					Key:         selectedKey,
					GCQualifier: "policy",
					Labels:      map[string]string{"test.policy": "selected"},
					ValidateExisting: func(info snapshots.Info) error {
						validations++
						require.True(t, locker.isHeld(lockKey), "validation must hold the selected key's lock")
						require.Equal(t, "old", info.Labels["test.policy"])
						return sentinel
					},
				}, nil
			}
			if mode == "cache hit" || mode == "concurrent commit" {
				sn.committed[selectedKey] = snapshots.Info{Labels: map[string]string{"test.policy": "old"}}
			}
			sn.alreadyExistsOnCommit = mode == "concurrent commit"
			u, err := NewUnpacker(ctx, store.Store, WithUnpackPlatform(up), WithDuplicationSuppressor(locker))
			require.NoError(t, err)
			require.NoError(t, images.Dispatch(ctx, u.Unpack(images.ChildrenHandler(store.Store)), nil, manifest.Descriptor))
			_, err = u.Wait()
			if mode == "new snapshot" {
				require.NoError(t, err)
				require.Equal(t, "selected", sn.committed[selectedKey].Labels["test.policy"])
				require.Equal(t, selectedKey, sn.committed[selectedKey].Labels[labelSnapshotRef])
				require.Equal(t, diffID.String(), sn.committed[selectedKey].Labels[labelSnapshotDiffID])
				configInfo, err := store.Info(ctx, config.Descriptor.Digest)
				require.NoError(t, err)
				require.Equal(t, selectedKey, configInfo.Labels["containerd.io/gc.ref.snapshot.test/policy"])
			} else {
				require.ErrorIs(t, err, sentinel)
			}
			require.Equal(t, 1, preparations)
			require.False(t, locker.isHeld(lockKey))
			if mode == "cache hit" || mode == "concurrent commit" {
				require.Equal(t, 1, validations)
				require.Equal(t, "old", sn.committed[selectedKey].Labels["test.policy"])
			} else {
				require.Zero(t, validations)
			}
		})
	}
}

func TestLayerPreparationRejectsInvalidSnapshotIdentity(t *testing.T) {
	for _, tc := range []struct {
		name     string
		prepared snapshots.LayerPreparation
		wantErr  string
	}{
		{name: "empty key", wantErr: "empty snapshot key"},
		{name: "missing qualifier", prepared: snapshots.LayerPreparation{Key: "alternate"}, wantErr: "requires a GC label qualifier"},
		{name: "slash", prepared: snapshots.LayerPreparation{Key: "alternate", GCQualifier: "a/b"}, wantErr: "invalid GC label qualifier"},
		{name: "backslash", prepared: snapshots.LayerPreparation{Key: "alternate", GCQualifier: `a\b`}, wantErr: "invalid GC label qualifier"},
		{name: "dot", prepared: snapshots.LayerPreparation{Key: "alternate", GCQualifier: "."}, wantErr: "invalid GC label qualifier"},
		{name: "dotdot", prepared: snapshots.LayerPreparation{Key: "alternate", GCQualifier: ".."}, wantErr: "invalid GC label qualifier"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			store := imagetest.NewContentStore(ctx, t)
			layer := store.Blob(ocispec.MediaTypeImageLayerGzip, []byte("layer"))
			diffID := digest.FromString("uncompressed layer")
			config := store.JSONObject(ocispec.MediaTypeImageConfig, ocispec.Image{
				RootFS: ocispec.RootFS{Type: "layers", DiffIDs: []digest.Digest{diffID}},
			})
			manifest := store.Manifest(config, layer)
			sn := &recordingSnapshotter{committed: make(map[string]snapshots.Info)}
			u, err := NewUnpacker(ctx, store.Store, WithUnpackPlatform(Platform{
				Snapshotter: sn,
				Applier:     diffIDApplier{layer.Descriptor.Digest: diffID},
				PrepareLayer: func(context.Context, ocispec.Descriptor, string) (snapshots.LayerPreparation, error) {
					return tc.prepared, nil
				},
			}))
			require.NoError(t, err)
			require.NoError(t, images.Dispatch(ctx, u.Unpack(images.ChildrenHandler(store.Store)), nil, manifest.Descriptor))
			_, err = u.Wait()
			require.ErrorContains(t, err, tc.wantErr)
			require.Empty(t, sn.preparedParents, "invalid preparation must not create snapshots")
		})
	}
}

func TestLayerPolicyIsPlatformScoped(t *testing.T) {
	ctx := t.Context()
	store := imagetest.NewContentStore(ctx, t)
	layer := store.Blob(ocispec.MediaTypeImageLayerGzip, []byte("layer"))
	diffID := digest.FromString("uncompressed layer")
	spec := platforms.DefaultSpec()
	config := store.JSONObject(ocispec.MediaTypeImageConfig, ocispec.Image{
		Platform: spec,
		RootFS:   ocispec.RootFS{Type: "layers", DiffIDs: []digest.Digest{diffID}},
	})
	manifest := store.Manifest(config, layer)
	sn := &recordingSnapshotter{committed: map[string]snapshots.Info{}}
	other := spec
	other.OS = "unsupported"
	u, err := NewUnpacker(ctx, store.Store,
		WithUnpackPlatform(Platform{
			Platform: platforms.Only(other), Snapshotter: sn,
			Applier: diffIDApplier{layer.Descriptor.Digest: diffID},
			PrepareLayer: func(context.Context, ocispec.Descriptor, string) (snapshots.LayerPreparation, error) {
				t.Error("unmatched platform policy invoked")
				return snapshots.LayerPreparation{}, errors.New("wrong platform")
			},
		}),
		WithUnpackPlatform(Platform{
			Platform: platforms.Only(spec), Snapshotter: sn,
			Applier: diffIDApplier{layer.Descriptor.Digest: diffID},
		}))
	require.NoError(t, err)
	require.NoError(t, images.Dispatch(ctx, u.Unpack(images.ChildrenHandler(store.Store)), nil, manifest.Descriptor))
	_, err = u.Wait()
	require.NoError(t, err)
	require.Contains(t, sn.committed, diffID.String())
}

func TestStableSnapshotLanesCoexistInEitherOrder(t *testing.T) {
	diffIDs := []digest.Digest{digest.FromString("shared base"), digest.FromString("image tail")}
	chainIDs := identity.ChainIDs(append([]digest.Digest(nil), diffIDs...))
	for _, parallel := range []bool{false, true} {
		for _, signedFirst := range []bool{true, false} {
			name := "unsigned then signed"
			if signedFirst {
				name = "signed then unsigned"
			}
			if parallel {
				name += " parallel"
			}
			t.Run(name, func(t *testing.T) {
				ctx := t.Context()
				store := imagetest.NewContentStore(ctx, t)
				config := store.JSONObject(ocispec.MediaTypeImageConfig, ocispec.Image{
					RootFS: ocispec.RootFS{Type: "layers", DiffIDs: diffIDs},
				})
				layers := []imagetest.Content{
					store.Blob(ocispec.MediaTypeImageLayerGzip, []byte("shared base")),
					store.Blob(ocispec.MediaTypeImageLayerGzip, []byte("image tail")),
				}
				manifest := store.Manifest(config, layers...)
				sn := &recordingSnapshotter{committed: make(map[string]snapshots.Info)}
				platform := Platform{
					SnapshotterKey:          "erofs",
					Snapshotter:             sn,
					SnapshotterCapabilities: []string{"dmverity-referrers"},
					Applier: diffIDApplier{
						layers[0].Descriptor.Digest: diffIDs[0],
						layers[1].Descriptor.Digest: diffIDs[1],
					},
					PrepareLayer: func(_ context.Context, desc ocispec.Descriptor, chainID string) (snapshots.LayerPreparation, error) {
						if _, signed := desc.Annotations["test.signed"]; signed {
							return snapshots.LayerPreparation{Key: "signed-" + chainID, GCQualifier: "dmverity"}, nil
						}
						return snapshots.LayerPreparation{Key: chainID}, nil
					},
				}
				if parallel {
					platform.SnapshotterCapabilities = append(platform.SnapshotterCapabilities, "rebase")
				}
				run := func(signed bool) {
					opts := []UnpackerOpt{WithUnpackPlatform(platform)}
					if parallel {
						opts = append(opts, WithUnpackLimiter(semaphore.NewWeighted(3)))
					}
					u, err := NewUnpacker(ctx, store.Store, opts...)
					require.NoError(t, err)
					base := images.ChildrenHandler(store.Store)
					handler := images.HandlerFunc(func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
						children, err := base.Handle(ctx, desc)
						if err != nil {
							return nil, err
						}
						if signed && images.IsManifestType(desc.MediaType) {
							for i := range children {
								if images.IsLayerType(children[i].MediaType) {
									children[i].Annotations = map[string]string{"test.signed": "true"}
								}
							}
						}
						return children, nil
					})
					require.NoError(t, images.Dispatch(ctx, u.Unpack(handler), nil, manifest.Descriptor))
					_, err = u.Wait()
					require.NoError(t, err)
				}

				run(signedFirst)
				run(!signedFirst)

				for _, chainID := range chainIDs {
					plainKey := chainID.String()
					signedKey := "signed-" + plainKey
					require.Contains(t, sn.committed, plainKey)
					require.Contains(t, sn.committed, signedKey)
				}
				require.Empty(t, sn.parents[chainIDs[0].String()])
				require.Empty(t, sn.parents["signed-"+chainIDs[0].String()])
				require.Equal(t, chainIDs[0].String(), sn.parents[chainIDs[1].String()])
				require.Equal(t, "signed-"+chainIDs[0].String(), sn.parents["signed-"+chainIDs[1].String()])

				configInfo, err := store.Store.Info(ctx, config.Descriptor.Digest)
				require.NoError(t, err)
				require.Equal(t, chainIDs[1].String(), configInfo.Labels["containerd.io/gc.ref.snapshot.erofs"])
				require.Equal(t, "signed-"+chainIDs[1].String(), configInfo.Labels["containerd.io/gc.ref.snapshot.erofs/dmverity"])
			})
		}
	}
}

func generateRandomDiffIDs(t testing.TB, num int) []digest.Digest {
	const size = 10
	diffIDs := make([]digest.Digest, 0, num)
	for range num {
		b := make([]byte, size)
		_, err := rand.Read(b)
		if err != nil {
			t.Fatalf("failed to generate random bytes: %v", err)
		}
		diffIDs = append(diffIDs, digest.FromBytes(b))
	}
	return diffIDs
}

func BenchmarkUnpackWithChainID(b *testing.B) {
	// This simulates the old way of repeatedly calculating per-layer chainID
	// as we unpack every layers, by calling `identity.ChainID`.
	unpackWithChainID := func(diffIDs []digest.Digest) {
		var chain []digest.Digest
		for i := range diffIDs {
			_ = identity.ChainID(chain) // parent layer chainID
			chain = append(chain, diffIDs[i])
			_ = identity.ChainID(chain).String() // current layer chainID
		}
		_ = identity.ChainID(chain).String()
	}

	numLayers := []int{5, 10, 25, 50}
	for _, sz := range numLayers {
		b.Run(fmt.Sprintf("num of layers: %d", sz), func(b *testing.B) {
			diffIDs := generateRandomDiffIDs(b, sz)
			for i := 0; i < b.N; i++ {
				unpackWithChainID(diffIDs)
			}
		})
	}
}

func BenchmarkUnpackWithChainIDs(b *testing.B) {
	// This simulates the new way of pre-calculating all chainIDs for every layer
	// by calling `identity.ChainIDs` once.
	unpackWithChainIDs := func(diffIDs []digest.Digest) {
		chainIDs := make([]digest.Digest, len(diffIDs))
		copy(chainIDs, diffIDs)
		chainIDs = identity.ChainIDs(chainIDs)
		for i := range diffIDs {
			if i > 0 {
				_ = chainIDs[i-1].String() // parent layer chainID
			}
			_ = chainIDs[i].String() // current layer chainID
		}
		if len(chainIDs) > 0 {
			_ = chainIDs[len(chainIDs)-1].String()
		}
	}

	numLayers := []int{5, 10, 25, 50}
	for _, sz := range numLayers {
		b.Run(fmt.Sprintf("num of layers: %d", sz), func(b *testing.B) {
			diffIDs := generateRandomDiffIDs(b, sz)
			for i := 0; i < b.N; i++ {
				unpackWithChainIDs(diffIDs)
			}
		})
	}
}

func TestBindToOverlay(t *testing.T) {
	testCases := []struct {
		name   string
		mounts []mount.Mount
		expect []mount.Mount
	}{
		{
			name: "single bind mount",
			mounts: []mount.Mount{
				{
					Type:    "bind",
					Source:  "/path/to/source",
					Options: []string{"ro", "rbind"},
				},
			},
			expect: []mount.Mount{
				{
					Type:   "overlay",
					Source: "overlay",
					Options: []string{
						"ro",
						"upperdir=/path/to/source",
					},
				},
			},
		},
		{
			name: "overlay mount",
			mounts: []mount.Mount{
				{
					Type:   "overlay",
					Source: "overlay",
					Options: []string{
						"lowerdir=/path/to/lower",
						"upperdir=/path/to/upper",
					},
				},
			},
			expect: []mount.Mount{
				{
					Type:   "overlay",
					Source: "overlay",
					Options: []string{
						"lowerdir=/path/to/lower",
						"upperdir=/path/to/upper",
					},
				},
			},
		},
		{
			name: "multiple mounts",
			mounts: []mount.Mount{
				{
					Type:   "bind",
					Source: "/path/to/source1",
				},
				{
					Type:   "bind",
					Source: "/path/to/source2",
				},
			},
			expect: []mount.Mount{
				{
					Type:   "bind",
					Source: "/path/to/source1",
				},
				{
					Type:   "bind",
					Source: "/path/to/source2",
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := bindToOverlay(tc.mounts)
			if !reflect.DeepEqual(result, tc.expect) {
				t.Errorf("unexpected result: got %v, want %v", result, tc.expect)
			}
		})
	}
}

type policyTestLocker struct {
	mu   sync.Mutex
	held map[string]bool
}

func (l *policyTestLocker) Lock(_ context.Context, key string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.held[key] {
		return fmt.Errorf("key %q already locked", key)
	}
	l.held[key] = true
	return nil
}

func (l *policyTestLocker) Unlock(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.held, key)
}

func (l *policyTestLocker) isHeld(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.held[key]
}

type recordingSnapshotter struct {
	snapshots.Snapshotter
	mu                    sync.Mutex
	committed             map[string]snapshots.Info
	preparedParents       map[string]string
	parents               map[string]string
	alreadyExistsOnCommit bool
}

func (s *recordingSnapshotter) Prepare(_ context.Context, key string, parent string, opts ...snapshots.Opt) ([]mount.Mount, error) {
	var info snapshots.Info
	for _, opt := range opts {
		if err := opt(&info); err != nil {
			return nil, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.preparedParents == nil {
		s.preparedParents = make(map[string]string)
	}
	s.preparedParents[key] = parent
	if _, ok := s.committed[info.Labels[labelSnapshotRef]]; ok && !s.alreadyExistsOnCommit {
		return nil, errdefs.ErrAlreadyExists
	}
	return nil, nil
}

func (s *recordingSnapshotter) Stat(_ context.Context, key string) (snapshots.Info, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	info, ok := s.committed[key]
	if !ok {
		return snapshots.Info{}, errdefs.ErrNotFound
	}
	return info, nil
}

func (s *recordingSnapshotter) Commit(_ context.Context, name, key string, opts ...snapshots.Opt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.alreadyExistsOnCommit {
		return errdefs.ErrAlreadyExists
	}
	var info snapshots.Info
	for _, opt := range opts {
		if err := opt(&info); err != nil {
			return err
		}
	}
	if info.Parent == "" {
		info.Parent = s.preparedParents[key]
	}
	info.Name = name
	if s.parents == nil {
		s.parents = make(map[string]string)
	}
	s.parents[name] = info.Parent
	s.committed[name] = info
	return nil
}

func (s *recordingSnapshotter) Remove(context.Context, string) error {
	return nil
}

type diffIDApplier map[digest.Digest]digest.Digest

func (a diffIDApplier) Apply(_ context.Context, desc ocispec.Descriptor, _ []mount.Mount, _ ...diff.ApplyOpt) (ocispec.Descriptor, error) {
	return ocispec.Descriptor{MediaType: ocispec.MediaTypeImageLayer, Digest: a[desc.Digest]}, nil
}

// signedImageFixture stores an image whose layer has a retained signed bundle.
func signedImageFixture(t *testing.T, store imagetest.ContentStore, rootHash string, signatureContent ...string) (
	manifest imagetest.Content, layer ocispec.Descriptor, diffID, signatureDigest digest.Digest,
) {
	t.Helper()
	const (
		erofsAnnotationPrefix = "io.containerd.erofs.v1/"
		sourceLayerAnnotation = erofsAnnotationPrefix + "dmverity.source-layer-digest"
		rootHashAnnotation    = erofsAnnotationPrefix + "dmverity.root-hash"
		artifactType          = "application/vnd.containerd.erofs.dmverity.v1"
		metadataMediaType     = "application/vnd.containerd.erofs.metadata.v1"
		treeMediaType         = "application/vnd.containerd.erofs.dmverity.merkle-tree.v1"
		signatureMediaType    = "application/vnd.containerd.erofs.dmverity.layer-signature.v1+pkcs7"
	)

	layerBlob := store.Blob(ocispec.MediaTypeImageLayerGzip, []byte("layer"))
	layer = layerBlob.Descriptor
	diffID = digest.FromString("uncompressed layer")
	config := store.JSONObject(ocispec.MediaTypeImageConfig, ocispec.Image{
		RootFS: ocispec.RootFS{Type: "layers", DiffIDs: []digest.Digest{diffID}},
	})
	manifest = store.Manifest(config, layerBlob)

	payload := func(mediaType string, extra map[string]string) ocispec.Descriptor {
		data := []byte(mediaType + " for " + layer.Digest.String())
		if mediaType == signatureMediaType && len(signatureContent) > 0 {
			data = []byte(signatureContent[0])
		}
		blob := store.Blob(mediaType, data)
		desc := blob.Descriptor
		desc.Annotations = map[string]string{sourceLayerAnnotation: layer.Digest.String()}
		for k, v := range extra {
			desc.Annotations[k] = v
		}
		return desc
	}
	subject := manifest.Descriptor
	signature := payload(signatureMediaType, map[string]string{rootHashAnnotation: rootHash})
	referrer := store.JSONObject(ocispec.MediaTypeImageManifest, ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: artifactType,
		Config:       ocispec.DescriptorEmptyJSON,
		Subject:      &subject,
		Layers: []ocispec.Descriptor{
			payload(metadataMediaType, nil),
			payload(treeMediaType, nil),
			signature,
		},
	})

	_, err := store.Store.Update(t.Context(), content.Info{
		Digest: subject.Digest,
		Labels: map[string]string{
			"containerd.io/gc.ref.content.dmverity": referrer.Descriptor.Digest.String(),
		},
	}, "labels.containerd.io/gc.ref.content.dmverity")
	require.NoError(t, err)
	return manifest, layer, diffID, signature.Digest
}

func TestUnpackRequiresValidatedReferrersForSignedIdentity(t *testing.T) {
	const rootHash = "b4e1c9f30a5d7e2186c4fb0937ad5e2c81f6b3a4d9c0e7182b5a6f3c4d9e0a71"

	for _, tc := range []struct {
		name       string
		validated  bool
		wantSigned bool
	}{
		{name: "discovery did not validate targets"},
		{name: "discovery validated targets", validated: true, wantSigned: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := imagetest.NewContentStore(ctx, t)
			manifest, layer, diffID, _ := signedImageFixture(t, store, rootHash)

			sn := &recordingSnapshotter{committed: map[string]snapshots.Info{}}
			up := Platform{
				SnapshotterKey:          "erofs",
				Snapshotter:             sn,
				SnapshotterCapabilities: []string{plugins.CapabilityDmverityReferrers},
				Applier:                 diffIDApplier{layer.Digest: diffID},
			}
			if tc.validated {
				up.PrepareLayer = snpkg.PrepareDmverityLayer
			}
			uopts := []UnpackerOpt{WithUnpackPlatform(up)}
			u, err := NewUnpacker(ctx, store.Store, uopts...)
			require.NoError(t, err)

			handler := snpkg.AppendCachedSignatureHandlerWrapper(store.Store)(
				images.ChildrenHandler(store.Store))
			require.NoError(t, images.Dispatch(ctx, u.Unpack(handler), nil, manifest.Descriptor))
			_, err = u.Wait()
			require.NoError(t, err)

			if tc.wantSigned {
				key, err := snpkg.DmveritySnapshotKey(identity.ChainID([]digest.Digest{diffID}).String())
				require.NoError(t, err)
				require.Contains(t, sn.committed, key, "signed layer must use the stable signed lane")
				require.NotContains(t, sn.committed, diffID.String())
				require.Len(t, sn.committed, 1)
				for _, info := range sn.committed {
					require.Equal(t, rootHash, info.Labels["containerd.io/snapshot/erofs.dmverity.root-hash"])
				}
				return
			}
			// Without a capable applier the signed sidecars are never written,
			// so the layer must not claim a signed snapshot identity.
			require.Contains(t, sn.committed, diffID.String())
			require.NotContains(t, sn.committed[diffID.String()].Labels,
				"containerd.io/snapshot/erofs.dmverity.root-hash")
		})
	}
}

func TestUnpackSignedSnapshotCachePolicy(t *testing.T) {
	const originalRoot = "b4e1c9f30a5d7e2186c4fb0937ad5e2c81f6b3a4d9c0e7182b5a6f3c4d9e0a71"
	for _, tc := range []struct {
		name     string
		rootHash string
		wantErr  bool
	}{
		{name: "different root rejected", rootHash: "c5f2dae41b6e8f3297d50ac1a48be6f3d20a7c4b5eadf8293c6b7a4d5eaf1b82", wantErr: true},
		{name: "same root keeps original signature", rootHash: originalRoot},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			store := imagetest.NewContentStore(ctx, t)
			sn := &recordingSnapshotter{committed: map[string]snapshots.Info{}}
			for i, signatureText := range []string{"old signature", "new signature"} {
				rootHash := originalRoot
				if i > 0 {
					rootHash = tc.rootHash
				}
				manifest, layer, diffID, _ := signedImageFixture(t, store, rootHash, signatureText)
				u, err := NewUnpacker(ctx, store.Store, WithUnpackPlatform(Platform{
					SnapshotterKey:          "erofs",
					Snapshotter:             sn,
					SnapshotterCapabilities: []string{plugins.CapabilityDmverityReferrers},
					Applier:                 diffIDApplier{layer.Digest: diffID},
					PrepareLayer:            snpkg.PrepareDmverityLayer,
				}))
				require.NoError(t, err)
				handler := snpkg.AppendCachedSignatureHandlerWrapper(store.Store)(images.ChildrenHandler(store.Store))
				require.NoError(t, images.Dispatch(ctx, u.Unpack(handler), nil, manifest.Descriptor))
				_, err = u.Wait()
				if i > 0 && tc.wantErr {
					require.ErrorContains(t, err, "violates layer policy")
				} else {
					require.NoError(t, err)
				}
				key, err := snpkg.DmveritySnapshotKey(identity.ChainID([]digest.Digest{diffID}).String())
				require.NoError(t, err)
				require.Contains(t, sn.committed, key)
				require.Len(t, sn.committed, 1)
				require.Equal(t, originalRoot, sn.committed[key].Labels["containerd.io/snapshot/erofs.dmverity.root-hash"])
				require.Equal(t, digest.FromString("old signature").String(), sn.committed[key].Labels["containerd.io/snapshot/erofs.dmverity.signature-digest"])
			}
		})
	}
}

func TestUnpackValidatesConcurrentChainIDCommit(t *testing.T) {
	rootHash := "b4e1c9f30a5d7e2186c4fb0937ad5e2c81f6b3a4d9c0e7182b5a6f3c4d9e0a71"
	for _, mismatch := range []bool{false, true} {
		t.Run(fmt.Sprintf("root hash mismatch=%t", mismatch), func(t *testing.T) {
			ctx := context.Background()
			store := imagetest.NewContentStore(ctx, t)
			manifest, layer, diffID, signatureDigest := signedImageFixture(t, store, rootHash)
			existingRoot := rootHash
			if mismatch {
				existingRoot = "c5f2dae41b6e8f3297d50ac1a48be6f3d20a7c4b5eadf8293c6b7a4d5eaf1b82"
			}
			key, err := snpkg.DmveritySnapshotKey(identity.ChainID([]digest.Digest{diffID}).String())
			require.NoError(t, err)
			sn := &recordingSnapshotter{
				committed: map[string]snapshots.Info{
					key: {Labels: map[string]string{
						"containerd.io/snapshot/erofs.dmverity.root-hash":        existingRoot,
						"containerd.io/snapshot/erofs.dmverity.signature-digest": signatureDigest.String(),
					}},
				},
				alreadyExistsOnCommit: true,
			}
			u, err := NewUnpacker(ctx, store.Store, WithUnpackPlatform(Platform{
				SnapshotterKey:          "erofs",
				Snapshotter:             sn,
				SnapshotterCapabilities: []string{plugins.CapabilityDmverityReferrers},
				Applier:                 diffIDApplier{layer.Digest: diffID},
				PrepareLayer:            snpkg.PrepareDmverityLayer,
			}))
			require.NoError(t, err)
			handler := snpkg.AppendCachedSignatureHandlerWrapper(store.Store)(images.ChildrenHandler(store.Store))
			require.NoError(t, images.Dispatch(ctx, u.Unpack(handler), nil, manifest.Descriptor))
			_, err = u.Wait()
			if mismatch {
				require.ErrorContains(t, err, "concurrently committed snapshot")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestOrdinaryUnpackDoesNotInspectSeparateSignedLane(t *testing.T) {
	ctx := context.Background()
	store := imagetest.NewContentStore(ctx, t)
	diffID := digest.FromString("uncompressed layer")
	config := store.JSONObject(ocispec.MediaTypeImageConfig, ocispec.Image{
		RootFS: ocispec.RootFS{Type: "layers", DiffIDs: []digest.Digest{diffID}},
	})
	layer := store.Blob(ocispec.MediaTypeImageLayerGzip, []byte("layer"))
	manifest := store.Manifest(config, layer)
	signedKey, err := snpkg.DmveritySnapshotKey(diffID.String())
	require.NoError(t, err)
	sn := &recordingSnapshotter{
		committed: map[string]snapshots.Info{
			signedKey: {Labels: map[string]string{"test.preserved": "true"}},
		},
	}
	u, err := NewUnpacker(ctx, store.Store, WithUnpackPlatform(Platform{
		SnapshotterKey:          "erofs",
		Snapshotter:             sn,
		SnapshotterCapabilities: []string{plugins.CapabilityDmverityReferrers},
		Applier:                 diffIDApplier{layer.Descriptor.Digest: diffID},
		PrepareLayer:            snpkg.PrepareDmverityLayer,
	}))
	require.NoError(t, err)
	require.NoError(t, images.Dispatch(ctx, u.Unpack(images.ChildrenHandler(store.Store)), nil, manifest.Descriptor))
	_, err = u.Wait()
	require.NoError(t, err)
	require.Len(t, sn.committed, 2)
	require.Contains(t, sn.committed, diffID.String())
	require.Equal(t, "true", sn.committed[signedKey].Labels["test.preserved"])
}
