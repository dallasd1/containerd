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

package plugin

import (
	"fmt"

	"github.com/containerd/log"
	"github.com/containerd/platforms"
	"github.com/containerd/plugin"
	"github.com/containerd/plugin/registry"

	"github.com/containerd/containerd/v2/core/metadata"
	"github.com/containerd/containerd/v2/internal/dmverity"
	"github.com/containerd/containerd/v2/internal/erofsutils"
	"github.com/containerd/containerd/v2/plugins"
	"github.com/containerd/containerd/v2/plugins/diff/erofs"
)

// Config represents configuration for the erofs plugin.
type Config struct {
	// MkfsOptions are extra options used for the applier
	MkfsOptions []string `toml:"mkfs_options"`

	// EnableTarIndex enables the tar index mode where the index is generated
	// for tar content without extracting the tar
	EnableTarIndex bool `toml:"enable_tar_index"`

	// EnableDmverity enables discovery and enforcement of signed dm-verity
	// metadata for EROFS layers. Unsigned layers remain ordinary EROFS unless
	// RequireSignatures rejects them.
	EnableDmverity bool `toml:"enable_dmverity"`

	// RequireSignatures requires dm-verity signatures to be present on all layers.
	// When enabled, layer application will fail if a signature is not present.
	// EnableDmverity must be true and the EROFS snapshotter must use
	// dmverity_mode = "on", so pre-existing plain snapshots cannot be mounted.
	RequireSignatures bool `toml:"require_signatures"`
}

func init() {
	registry.Register(&plugin.Registration{
		Type: plugins.DiffPlugin,
		ID:   "erofs",
		Requires: []plugin.Type{
			plugins.MetadataPlugin,
		},
		Config: &Config{},
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
			tarModeSupported, err := erofsutils.SupportGenerateFromTar()
			if err != nil {
				return nil, fmt.Errorf("failed to check mkfs.erofs availability: %v: %w", err, plugin.ErrSkipPlugin)
			}
			if !tarModeSupported {
				return nil, fmt.Errorf("mkfs.erofs does not support tar mode (--tar option), disabling erofs differ: %w", plugin.ErrSkipPlugin)
			}

			md, err := ic.GetSingle(plugins.MetadataPlugin)
			if err != nil {
				return nil, err
			}

			p := platforms.DefaultSpec()
			p.OS = "linux"
			ic.Meta.Platforms = append(ic.Meta.Platforms, p)
			cs := md.(*metadata.DB).ContentStore()
			config := ic.Config.(*Config)

			var opts []erofs.DifferOpt

			// require_signatures is only honoured inside the dm-verity block
			// below, so accepting this combination would silently give an
			// operator who asked for mandatory signatures no enforcement at all.
			if config.RequireSignatures && !config.EnableDmverity {
				return nil, fmt.Errorf("erofs differ: require_signatures requires enable_dmverity to be true")
			}

			if len(config.MkfsOptions) > 0 {
				opts = append(opts, erofs.WithMkfsOptions(config.MkfsOptions))
			}

			if config.EnableTarIndex {
				opts = append(opts, erofs.WithTarIndexMode())
			}

			if config.EnableDmverity {
				supportErr := dmverity.CheckSignatureSupport()
				enableDmverity, err := dmverityEnabled(config.RequireSignatures, supportErr)
				if err != nil {
					return nil, err
				}
				if supportErr != nil {
					log.G(ic.Context).WithError(supportErr).Warn("signed dm-verity support is unavailable; applying layers as plain EROFS")
				}
				if enableDmverity {
					opts = append(opts, erofs.WithDmverity())

					if config.RequireSignatures {
						opts = append(opts, erofs.WithRequireSignatures())
						ic.Meta.Capabilities = append(ic.Meta.Capabilities, plugins.CapabilityDmveritySignaturesRequired)
					}

					// Advertise that this differ consumes dm-verity referrer
					// artifacts so pull implementations enable referrer discovery
					// without requiring separate configuration.
					ic.Meta.Capabilities = append(ic.Meta.Capabilities, plugins.CapabilityDmverityReferrers)
				}
			}

			return erofs.NewErofsDiffer(cs, opts...), nil
		},
	})
}

func dmverityEnabled(required bool, supportErr error) (bool, error) {
	if required && supportErr != nil {
		return false, fmt.Errorf("erofs differ: require_signatures is true but signed dm-verity mappings are unavailable: %w", supportErr)
	}
	return supportErr == nil, nil
}
