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

package diff

import (
	"context"
	"fmt"
	"slices"
	"strings"

	diffapi "github.com/containerd/containerd/api/services/diff/v1"
	"github.com/containerd/errdefs"
	"github.com/containerd/errdefs/pkg/errgrpc"
	"github.com/containerd/plugin"
	"github.com/containerd/plugin/registry"
	"github.com/containerd/typeurl/v2"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"google.golang.org/grpc"

	"github.com/containerd/containerd/v2/core/diff"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/internal/erofsutils"
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/containerd/containerd/v2/pkg/snapshotters"
	"github.com/containerd/containerd/v2/plugins"
	"github.com/containerd/containerd/v2/plugins/services"
)

type config struct {
	// Order is the order of preference in which to try diff algorithms, the
	// first differ which is supported is used.
	// Note when multiple differs may be supported, this order will be
	// respected for which is chosen. Each differ should return the same
	// correct output, allowing any ordering to be used to prefer
	// more optimimal implementations.
	Order []string `toml:"default"`
	// sync_fs is an experimental setting. It's to force sync
	// filesystem during unpacking to ensure that data integrity.
	// It is effective for all containerd client.
	SyncFs bool `toml:"sync_fs"`
}

type differ interface {
	diff.Comparer
	diff.Applier
}

func init() {
	registry.Register(&plugin.Registration{
		Type: plugins.ServicePlugin,
		ID:   services.DiffService,
		Requires: []plugin.Type{
			plugins.DiffPlugin,
		},
		Config: defaultDifferConfig,
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
			differs, err := ic.GetByType(plugins.DiffPlugin)
			if err != nil {
				return nil, err
			}
			syncFs := ic.Config.(*config).SyncFs
			orderedNames := ic.Config.(*config).Order
			ordered := make([]differ, len(orderedNames))
			var dmverityCapable []string
			var dmverityConfigured, dmverityRequired bool
			for i, n := range orderedNames {
				d, ok := differs[n]
				if !ok {
					return nil, fmt.Errorf("needed differ not loaded: %s", n)
				}

				ordered[i], ok = d.(differ)
				if !ok {
					return nil, fmt.Errorf("differ does not implement Comparer and Applier interface: %s", n)
				}

				if p := ic.Plugins().Get(plugins.DiffPlugin, n); p != nil &&
					slices.Contains(p.Meta.Capabilities, plugins.CapabilityDmverityReferrers) {
					dmverityCapable = append(dmverityCapable, n)
					dmverityConfigured = true
					if i == 0 && slices.Contains(p.Meta.Capabilities, plugins.CapabilityDmveritySignaturesRequired) {
						dmverityRequired = true
					}
				}
			}
			if len(orderedNames) > 0 && len(dmverityCapable) > 0 && orderedNames[0] == dmverityCapable[0] {
				ic.Meta.Capabilities = append(ic.Meta.Capabilities, plugins.CapabilityDmverityReferrers)
				if dmverityRequired {
					ic.Meta.Capabilities = append(ic.Meta.Capabilities, plugins.CapabilityDmveritySignaturesRequired)
				}
			}

			return &local{
				differs:            ordered,
				orderedNames:       orderedNames,
				dmverityCapable:    dmverityCapable,
				dmverityConfigured: dmverityConfigured,
				dmverityRequired:   dmverityRequired,
				syncfs:             syncFs,
			}, nil
		},
	})
}

type local struct {
	differs []differ
	// orderedNames mirrors differs and is retained so callers can report
	// which appliers this service will actually select.
	orderedNames []string
	// dmverityCapable lists the ordered differs that advertise
	// plugins.CapabilityDmverityReferrers.
	dmverityCapable []string
	// dmverityConfigured distinguishes an opted-out service from an invalid
	// ordered differ chain. Runtime-only annotations are ignored when the
	// feature is not configured.
	dmverityConfigured bool
	dmverityRequired   bool
	syncfs             bool
}

var _ diffapi.DiffClient = &local{}

// DmverityAppliers reports the ordered applier chain this service will select
// from, and the subset of it able to consume dm-verity referrer artifacts.
//
// Discovery of dm-verity artifacts is derived from loaded diff plugins, but
// layers are applied by the differ this service selects. When the two disagree,
// artifacts are fetched and then dropped, producing layers with no dm-verity
// device while configuration still reads as though verification is enabled.
// Callers use this to bind enforcement to the selected applier instead.
func (l *local) DmverityAppliers() (ordered []string, capable []string) {
	return l.orderedNames, l.dmverityCapable
}

func (l *local) DmveritySignaturesRequired() bool {
	return l.dmverityRequired
}

func (l *local) Apply(ctx context.Context, er *diffapi.ApplyRequest, _ ...grpc.CallOption) (*diffapi.ApplyResponse, error) {
	var (
		ocidesc ocispec.Descriptor
		err     error
		desc    = oci.DescriptorFromProto(er.Diff)
		mounts  = mount.FromProto(er.Mounts)
	)

	var opts []diff.ApplyOpt
	if er.Payloads != nil {
		payloads := make(map[string]typeurl.Any)
		for k, v := range er.Payloads {
			payloads[k] = v
		}
		opts = append(opts, diff.WithPayloads(payloads))
	}
	if l.syncfs {
		er.SyncFs = true
	}
	opts = append(opts, diff.WithSyncFs(er.SyncFs))

	if err := l.validateDmverityApply(desc, mounts); err != nil {
		return nil, errgrpc.ToGRPC(err)
	}
	for _, differ := range l.differs {
		ocidesc, err = differ.Apply(ctx, desc, mounts, opts...)
		if !errdefs.IsNotImplemented(err) {
			break
		}
	}

	if err != nil {
		return nil, errgrpc.ToGRPC(err)
	}

	return &diffapi.ApplyResponse{
		Applied: oci.DescriptorToProto(ocidesc),
	}, nil

}

func (l *local) validateDmverityApply(desc ocispec.Descriptor, mounts []mount.Mount) error {
	if desc.Annotations[snapshotters.TargetLayerSignatureLabel] == "" &&
		desc.Annotations[snapshotters.TargetLayerRootHashLabel] == "" &&
		desc.Annotations[snapshotters.TargetLayerEROFSMetadataDescriptorLabel] == "" &&
		desc.Annotations[snapshotters.TargetLayerMerkleTreeDescriptorLabel] == "" {
		return nil
	}
	if !l.dmverityConfigured {
		return nil
	}
	if len(mounts) == 0 {
		return nil
	}
	if _, err := erofsutils.MountsToLayer(mounts); err != nil {
		if errdefs.IsNotImplemented(err) {
			return nil
		}
		return err
	}
	if len(l.orderedNames) == 0 || len(l.dmverityCapable) == 0 ||
		l.orderedNames[0] != l.dmverityCapable[0] {
		return fmt.Errorf(
			"dm-verity layer annotations require a capable first differ; ordered [%s], capable [%s]",
			strings.Join(l.orderedNames, ", "),
			strings.Join(l.dmverityCapable, ", "),
		)
	}
	return nil
}

func (l *local) Diff(ctx context.Context, dr *diffapi.DiffRequest, _ ...grpc.CallOption) (*diffapi.DiffResponse, error) {
	var (
		ocidesc ocispec.Descriptor
		err     error
		aMounts = mount.FromProto(dr.Left)
		bMounts = mount.FromProto(dr.Right)
	)

	var opts []diff.Opt
	if dr.MediaType != "" {
		opts = append(opts, diff.WithMediaType(dr.MediaType))
	}
	if dr.Ref != "" {
		opts = append(opts, diff.WithReference(dr.Ref))
	}
	if dr.Labels != nil {
		opts = append(opts, diff.WithLabels(dr.Labels))
	}
	if dr.SourceDateEpoch != nil {
		tm := dr.SourceDateEpoch.AsTime()
		opts = append(opts, diff.WithSourceDateEpoch(&tm))
	}

	for _, d := range l.differs {
		ocidesc, err = d.Compare(ctx, aMounts, bMounts, opts...)
		if !errdefs.IsNotImplemented(err) {
			break
		}
	}
	if err != nil {
		return nil, errgrpc.ToGRPC(err)
	}

	return &diffapi.DiffResponse{
		Diff: oci.DescriptorToProto(ocidesc),
	}, nil
}
