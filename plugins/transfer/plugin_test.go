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

package transfer

import (
	"errors"
	"path/filepath"
	"slices"
	"testing"

	"github.com/containerd/containerd/v2/core/diff"
	"github.com/containerd/containerd/v2/core/metadata"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/core/transfer/local"
	"github.com/containerd/containerd/v2/core/unpack"
	"github.com/containerd/containerd/v2/plugins"
	contentlocal "github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/containerd/platforms"
	"github.com/containerd/plugin"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	bolt "go.etcd.io/bbolt"
)

func TestPullHandlerWrapperRequestIntent(t *testing.T) {
	for _, tc := range []struct {
		name                              string
		enabled, requested, capable, want bool
	}{
		{name: "fetch off"},
		{name: "fetch enabled", enabled: true, want: true},
		{name: "explicit overlayfs", enabled: true, requested: true},
		{name: "unsupported explicit request", enabled: true, requested: true},
		{name: "signed matched platform", requested: true, capable: true, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var capabilities []string
			if tc.enabled {
				capabilities = []string{plugins.CapabilityDmverityReferrers}
			}
			ms, ic := newTestInitContext(t,
				map[string]snapshots.Snapshotter{"erofs": &testSnapshotter{}}, nil,
				map[string][]string{"erofs": capabilities},
			)
			lc := &local.TransferConfig{}
			configureDmverityFetchRetention(ic, ms, lc)
			var matched []unpack.Platform
			if tc.capable {
				matched = []unpack.Platform{{SnapshotterCapabilities: []string{plugins.CapabilityDmverityReferrers}}}
			} else if tc.name == "explicit overlayfs" {
				matched = []unpack.Platform{{SnapshotterKey: "overlayfs"}}
			}
			wrapper, err := lc.PullHandlerWrapper(t.Context(), nil, nil, tc.requested, matched)
			if err != nil || (wrapper != nil) != tc.want {
				t.Fatalf("wrapper present=%v want=%v error=%v", wrapper != nil, tc.want, err)
			}
		})
	}
}

func TestConfigureUnpackPlatforms(t *testing.T) {
	tests := []struct {
		name                  string
		candidates            []*plugin.Registration
		config                transferConfig
		expectedErr           error
		expectedUnpackConfigs int
		expectedApplier       bool
	}{
		{
			name: "optional explicit differ skip",
			candidates: []*plugin.Registration{
				newTestDiffPlugin("erofs", nil, plugin.ErrSkipPlugin, platforms.DefaultSpec()),
			},
			config: transferConfig{
				UnpackConfiguration: []unpackConfiguration{
					{
						Platform:    platforms.Format(platforms.DefaultSpec()),
						Snapshotter: "native",
						Differ:      "erofs",
						Optional:    true,
					},
				},
			},
		},
		{
			name: "required explicit differ skip",
			candidates: []*plugin.Registration{
				newTestDiffPlugin("erofs", nil, plugin.ErrSkipPlugin, platforms.DefaultSpec()),
			},
			config: transferConfig{
				UnpackConfiguration: []unpackConfiguration{
					{
						Platform:    platforms.Format(platforms.DefaultSpec()),
						Snapshotter: "native",
						Differ:      "erofs",
					},
				},
			},
			expectedErr: plugin.ErrSkipPlugin,
		},
		{
			name: "optional explicit differ missing",
			config: transferConfig{
				UnpackConfiguration: []unpackConfiguration{
					{
						Platform:    platforms.Format(platforms.DefaultSpec()),
						Snapshotter: "native",
						Differ:      "missing",
						Optional:    true,
					},
				},
			},
		},
		{
			name: "auto differ skips unavailable candidate",
			candidates: []*plugin.Registration{
				newTestDiffPlugin("skipped", nil, plugin.ErrSkipPlugin, platforms.DefaultSpec()),
				newTestDiffPlugin("usable", testApplier{}, nil, platforms.DefaultSpec()),
			},
			config: transferConfig{
				UnpackConfiguration: []unpackConfiguration{
					{
						Platform:    platforms.Format(platforms.DefaultSpec()),
						Snapshotter: "native",
					},
				},
			},
			expectedUnpackConfigs: 1,
			expectedApplier:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ms, ic := newTestInitContext(t, map[string]snapshots.Snapshotter{"native": &testSnapshotter{}}, tt.candidates,
				map[string][]string{"native": {plugins.CapabilityDmverityReferrers}},
			)
			lc := &local.TransferConfig{}

			err := configureUnpackPlatforms(ic, ms, &tt.config, lc)
			if !errors.Is(err, tt.expectedErr) {
				t.Fatalf("expected error %v, got %v", tt.expectedErr, err)
			}
			if len(lc.UnpackPlatforms) != tt.expectedUnpackConfigs {
				t.Fatalf("expected %d unpack platforms, got %d", tt.expectedUnpackConfigs, len(lc.UnpackPlatforms))
			}
			if tt.expectedApplier {
				if _, ok := lc.UnpackPlatforms[0].Applier.(testApplier); !ok {
					t.Fatalf("expected test applier, got %T", lc.UnpackPlatforms[0].Applier)
				}
			}
			if err == nil {
				configureDmverityFetchRetention(ic, ms, lc)
				wrapper, err := lc.PullHandlerWrapper(t.Context(), nil, nil, false, nil)
				if err != nil || wrapper == nil {
					t.Fatalf("available snapshotter must enable fetch retention even without an applier: %v", err)
				}
			}
		})
	}
}

func TestConfigureUnpackPlatformsSelectsSignedLaneForCapableSnapshotter(t *testing.T) {
	ms, ic := newTestInitContext(t,
		map[string]snapshots.Snapshotter{"erofs": &testSnapshotter{}},
		[]*plugin.Registration{newTestDiffPlugin("erofs", testApplier{}, nil, platforms.DefaultSpec())},
		map[string][]string{"erofs": {plugins.CapabilityDmverityReferrers}},
	)
	config := transferConfig{UnpackConfiguration: []unpackConfiguration{{
		Platform:    platforms.Format(platforms.DefaultSpec()),
		Snapshotter: "erofs",
		Differ:      "erofs",
	}}}
	lc := &local.TransferConfig{}
	if err := configureUnpackPlatforms(ic, ms, &config, lc); err != nil {
		t.Fatal(err)
	}
	if len(lc.UnpackPlatforms) != 1 {
		t.Fatalf("expected one unpack platform, got %d", len(lc.UnpackPlatforms))
	}
	up := lc.UnpackPlatforms[0]
	if up.PrepareLayer == nil {
		t.Fatal("capable snapshotter is missing dm-verity layer policy")
	}
}

func TestConfigureDmverityFetchRetentionCapability(t *testing.T) {
	for _, tc := range []struct {
		name                                    string
		available, capable, failed, missingMeta bool
		want                                    bool
	}{
		{name: "disabled", available: true},
		{name: "enabled without unpack platforms", available: true, capable: true, want: true},
		{name: "registered but unavailable", capable: true},
		{name: "failed snapshotter", capable: true, failed: true},
		{name: "missing plugin metadata", available: true, capable: true, missingMeta: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshotters := map[string]snapshots.Snapshotter{}
			if tc.available {
				snapshotters["erofs"] = &testSnapshotter{}
			}
			var capabilities []string
			if tc.capable {
				capabilities = []string{plugins.CapabilityDmverityReferrers}
			}
			ms, ic := newTestInitContext(t, snapshotters, nil, map[string][]string{"erofs": capabilities})
			if tc.missingMeta {
				ic = plugin.NewContext(t.Context(), plugin.NewPluginSet(), nil)
			}
			if !tc.available {
				p := (&plugin.Registration{
					Type: plugins.SnapshotPlugin,
					ID:   "erofs",
					InitFn: func(ic *plugin.InitContext) (any, error) {
						ic.Meta.Capabilities = append(ic.Meta.Capabilities, capabilities...)
						if tc.failed {
							return nil, errors.New("snapshotter unavailable")
						}
						return &testSnapshotter{}, nil
					},
				}).Init(plugin.NewContext(t.Context(), ic.Plugins(), nil))
				if err := ic.Plugins().Add(p); err != nil {
					t.Fatal(err)
				}
			}
			lc := &local.TransferConfig{}
			config := transferConfig{UnpackConfiguration: []unpackConfiguration{}}
			if err := configureUnpackPlatforms(ic, ms, &config, lc); err != nil {
				t.Fatal(err)
			}
			configureDmverityFetchRetention(ic, ms, lc)
			wrapper, err := lc.PullHandlerWrapper(t.Context(), nil, nil, false, nil)
			if err != nil || (wrapper != nil) != tc.want {
				t.Fatalf("expected fetch retention %v, got wrapper %v, error %v", tc.want, wrapper != nil, err)
			}
			hasCapability := slices.Contains(ic.Meta.Capabilities, plugins.CapabilityDmverityReferrers)
			if hasCapability != tc.want {
				t.Fatalf("expected capability %v, got %v", tc.want, hasCapability)
			}
		})
	}
}

func newTestInitContext(t *testing.T, snapshotters map[string]snapshots.Snapshotter, candidates []*plugin.Registration, capabilityMaps ...map[string][]string) (*metadata.DB, *plugin.InitContext) {
	t.Helper()
	var capabilities map[string][]string
	if len(capabilityMaps) > 0 {
		capabilities = capabilityMaps[0]
	}

	cs, err := contentlocal.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	bdb, err := bolt.Open(filepath.Join(t.TempDir(), "metadata.db"), 0o644, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := bdb.Close(); err != nil {
			t.Fatal(err)
		}
	})

	db := metadata.NewDB(bdb, cs, snapshotters)
	ps := plugin.NewPluginSet()
	for name, sn := range snapshotters {
		ic := plugin.NewContext(t.Context(), ps, nil)
		p := (&plugin.Registration{
			Type: plugins.SnapshotPlugin,
			ID:   name,
			InitFn: func(ic *plugin.InitContext) (any, error) {
				ic.Meta.Capabilities = append(ic.Meta.Capabilities, capabilities[name]...)
				return sn, nil
			},
		}).Init(ic)
		if err := ps.Add(p); err != nil {
			t.Fatal(err)
		}
	}
	for _, candidate := range candidates {
		ic := plugin.NewContext(t.Context(), ps, nil)
		if err := ps.Add(candidate.Init(ic)); err != nil {
			t.Fatal(err)
		}
	}

	return db, plugin.NewContext(t.Context(), ps, nil)
}

func newTestDiffPlugin(id string, applier diff.Applier, err error, supported ...ocispec.Platform) *plugin.Registration {
	return &plugin.Registration{
		Type: plugins.DiffPlugin,
		ID:   id,
		InitFn: func(ic *plugin.InitContext) (any, error) {
			ic.Meta.Platforms = append(ic.Meta.Platforms, supported...)
			return applier, err
		},
	}
}

type testApplier struct {
	diff.Applier
}

type testSnapshotter struct {
	snapshots.Snapshotter
}
