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
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/core/snapshots/storage"
	"github.com/containerd/errdefs"
	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/require"
)

func TestFailedSignedParentViewCanBeRetried(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(root, "snapshots"), 0700))
	ms, err := storage.NewMetaStore(filepath.Join(root, "metadata.db"))
	require.NoError(t, err)
	s := &snapshotter{root: root, ms: ms, dmverityMode: "auto"}
	t.Cleanup(func() { require.NoError(t, s.Close()) })

	_, err = s.Prepare(ctx, "parent-active", "")
	require.NoError(t, err)
	var parentID string
	require.NoError(t, ms.WithTransaction(ctx, false, func(ctx context.Context) error {
		var err error
		parentID, _, _, err = storage.GetInfo(ctx, "parent-active")
		return err
	}))
	require.NoError(t, os.WriteFile(s.layerBlobPath(parentID), []byte("layer"), 0600))

	rootHash := strings.Repeat("a", 64)
	signatureDigest := digest.FromString("signature").String()
	require.NoError(t, s.Commit(ctx, "parent", "parent-active", snapshots.WithLabels(map[string]string{
		"containerd.io/snapshot/erofs.dmverity.root-hash":        rootHash,
		"containerd.io/snapshot/erofs.dmverity.signature-digest": signatureDigest,
	})))

	_, err = s.View(ctx, "retry-view", "parent")
	require.ErrorContains(t, err, "requires signed dm-verity referrers")
	_, err = s.Stat(ctx, "retry-view")
	require.True(t, errdefs.IsNotFound(err), "failed view left a snapshot: %v", err)

	s.enableDmverityReferrers = true
	mounts, err := s.View(ctx, "retry-view", "parent")
	require.NoError(t, err)
	require.Len(t, mounts, 1)
	require.Contains(t, mounts[0].Options, "X-containerd.dmverity.root-hash="+rootHash)
}

func TestSignedReferrersRejectDmverityOff(t *testing.T) {
	_, err := NewSnapshotter(t.TempDir(), WithDmverityReferrers(), WithDmverityMode("off"))
	require.ErrorContains(t, err, "enable_dmverity_referrers requires dmverity_mode")
}
