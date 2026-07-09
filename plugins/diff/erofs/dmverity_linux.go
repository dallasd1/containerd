//go:build linux

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

package erofs

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/containerd/containerd/v2/internal/dmverity"
	"github.com/containerd/log"
)

// formatDmverityLayer delegates to the shared internal/dmverity.FormatLayerBlob
// helper. Block size is determined by differ mode:
//   - Tar index mode requires 512-byte blocks because mkfs.erofs --tar=i uses
//     512-byte metadata blocks and dm-verity logical_block_size must match.
//   - Regular tar conversion mode uses the standard 4096-byte page size.
func (s *erofsDiff) formatDmverityLayer(ctx context.Context, layerBlobPath string) (string, error) {
	blockSize := uint32(4096)
	if s.enableTarIndex {
		blockSize = 512
	}
	log.G(ctx).WithFields(log.Fields{
		"tag":            "dmverity_format",
		"event":          "differ_invoke",
		"path":           layerBlobPath,
		"blockSize":      blockSize,
		"enableTarIndex": s.enableTarIndex,
	}).Info("dmverity_format: differ.Apply invoking FormatLayerBlob (tar-stream path)")
	return dmverity.FormatLayerBlob(ctx, layerBlobPath, blockSize)
}

var (
	// ipeSecurityFSPath is the securityfs directory exposed by the IPE LSM.
	ipeSecurityFSPath    = "/sys/kernel/security/ipe"
	ipeCheckOnce         sync.Once
	ipeRequiresSignature bool
)

// ipeRequiresDmveritySignatures reports whether an active IPE policy consumes
// the dm-verity signature property. The boot policy is active before containerd
// starts, so the result is cached once per process.
func ipeRequiresDmveritySignatures(ctx context.Context) bool {
	ipeCheckOnce.Do(func() {
		ipeRequiresSignature = ipePolicyRequiresDmveritySignatures(ctx)
		log.G(ctx).WithField("ipe_requires_dmverity_signatures", ipeRequiresSignature).
			Info("Evaluated IPE dm-verity signature requirement")
	})
	return ipeRequiresSignature
}

func ipePolicyRequiresDmveritySignatures(ctx context.Context) bool {
	policiesDir := filepath.Join(ipeSecurityFSPath, "policies")
	entries, err := os.ReadDir(policiesDir)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		active, err := os.ReadFile(filepath.Join(policiesDir, entry.Name(), "active"))
		if err != nil || strings.TrimSpace(string(active)) != "1" {
			continue
		}
		policy, err := os.ReadFile(filepath.Join(policiesDir, entry.Name(), "policy"))
		if err != nil {
			continue
		}
		if bytes.Contains(policy, []byte("dmverity_signature")) {
			log.G(ctx).WithField("ipe_policy", entry.Name()).
				Info("Active IPE policy requires dm-verity signatures")
			return true
		}
	}
	return false
}
