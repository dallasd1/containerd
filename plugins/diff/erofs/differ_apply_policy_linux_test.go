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
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/internal/dmverity"
	"github.com/containerd/containerd/v2/internal/erofsutils"
	snpkg "github.com/containerd/containerd/v2/pkg/snapshotters"
	"github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/google/uuid"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplyNativeDmverityPolicy(t *testing.T) {
	ctx := context.Background()
	cs, err := local.NewStore(t.TempDir())
	require.NoError(t, err)
	data := bytes.Repeat([]byte("native erofs test data"), 512)
	desc := writeTestBlob(t, ctx, cs, data, "application/vnd.containerd.test.layer.erofs")

	probe := filepath.Join(t.TempDir(), "probe.erofs")
	require.NoError(t, os.WriteFile(probe, data, 0600))
	layerUUID := uuid.NewSHA1(uuid.NameSpaceURL, []byte("erofs:blobs/"+desc.Digest))
	rootHash, err := dmverity.FormatLayerBlob(ctx, probe, 4096, layerUUID.String())
	require.NoError(t, err)
	signed := desc
	signed.Annotations = map[string]string{
		snpkg.TargetLayerSignatureLabel: base64.StdEncoding.EncodeToString([]byte("signature")),
		snpkg.TargetLayerRootHashLabel:  rootHash,
	}

	t.Run("disabled ignores complete annotations", func(t *testing.T) {
		layer, mounts := newPolicyLayer(t)
		_, err := NewErofsDiffer(cs).Apply(ctx, signed, mounts)
		require.NoError(t, err)
		assertNoDmveritySidecars(t, layer)
	})

	t.Run("disabled ignores partial annotations", func(t *testing.T) {
		layer, mounts := newPolicyLayer(t)
		partial := desc
		partial.Annotations = map[string]string{
			snpkg.TargetLayerRootHashLabel: rootHash,
		}
		_, err := NewErofsDiffer(cs).Apply(ctx, partial, mounts)
		require.NoError(t, err)
		assertNoDmveritySidecars(t, layer)
	})

	t.Run("optional unsigned remains plain", func(t *testing.T) {
		layer, mounts := newPolicyLayer(t)
		_, err := NewErofsDiffer(cs, WithDmverity()).Apply(ctx, desc, mounts)
		require.NoError(t, err)
		assertNoDmveritySidecars(t, layer)
	})

	t.Run("required unsigned fails", func(t *testing.T) {
		layer, mounts := newPolicyLayer(t)
		_, err := NewErofsDiffer(cs, WithDmverity(), WithRequireSignatures()).Apply(ctx, desc, mounts)
		require.ErrorContains(t, err, "signature required")
		assertNoDmveritySidecars(t, layer)
	})

	t.Run("signed creates protected sidecars", func(t *testing.T) {
		layer, mounts := newPolicyLayer(t)
		_, err := NewErofsDiffer(cs, WithDmverity()).Apply(ctx, signed, mounts)
		require.NoError(t, err)
		assertDmveritySidecars(t, layer)
	})
}

func TestApplyTarDmverityPolicy(t *testing.T) {
	supported, err := erofsutils.SupportGenerateFromTar()
	if err != nil || !supported {
		t.Skip("mkfs.erofs tar mode is unavailable")
	}

	ctx := context.Background()
	cs, err := local.NewStore(t.TempDir())
	require.NoError(t, err)
	tarData := policyTar(t)
	desc := writeTestBlob(t, ctx, cs, tarData, ocispec.MediaTypeImageLayer)
	differ := NewErofsDiffer(
		cs,
		WithDmverity(),
		WithMkfsOptions([]string{"-T0"}),
	)

	plainLayer, plainMounts := newPolicyLayer(t)
	_, err = differ.Apply(ctx, desc, plainMounts)
	require.NoError(t, err)
	assertNoDmveritySidecars(t, plainLayer)

	probe := filepath.Join(t.TempDir(), "probe.erofs")
	require.NoError(t, copyFile(filepath.Join(plainLayer, "layer.erofs"), probe))
	layerUUID := uuid.NewSHA1(uuid.NameSpaceURL, []byte("erofs:blobs/"+desc.Digest))
	rootHash, err := dmverity.FormatLayerBlob(ctx, probe, 4096, layerUUID.String())
	require.NoError(t, err)

	signed := desc
	signed.Annotations = map[string]string{
		snpkg.TargetLayerSignatureLabel: base64.StdEncoding.EncodeToString([]byte("signature")),
		snpkg.TargetLayerRootHashLabel:  rootHash,
	}
	signedLayer, signedMounts := newPolicyLayer(t)
	_, err = differ.Apply(ctx, signed, signedMounts)
	require.NoError(t, err)
	assertDmveritySidecars(t, signedLayer)
}

func newPolicyLayer(t *testing.T) (string, []mount.Mount) {
	t.Helper()
	layer := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(layer, ".erofslayer"), nil, 0600))
	return layer, []mount.Mount{{
		Type:   "bind",
		Source: filepath.Join(layer, "layer.erofs"),
	}}
}

func assertNoDmveritySidecars(t *testing.T, layer string) {
	t.Helper()
	for _, path := range []string{
		dmverity.MetadataPath(filepath.Join(layer, "layer.erofs")),
		dmverity.SignaturePath(filepath.Join(layer, "layer.erofs")),
		dmverity.SignatureRequiredPath(filepath.Join(layer, "layer.erofs")),
		dmverity.HashDevicePath(filepath.Join(layer, "layer.erofs")),
	} {
		_, err := os.Stat(path)
		assert.ErrorIs(t, err, os.ErrNotExist, path)
	}
}

func assertDmveritySidecars(t *testing.T, layer string) {
	t.Helper()
	for _, path := range []string{
		dmverity.MetadataPath(filepath.Join(layer, "layer.erofs")),
		dmverity.SignaturePath(filepath.Join(layer, "layer.erofs")),
		dmverity.SignatureRequiredPath(filepath.Join(layer, "layer.erofs")),
	} {
		info, err := os.Stat(path)
		require.NoError(t, err, path)
		assert.Positive(t, info.Size(), path)
	}
}

func policyTar(t *testing.T) []byte {
	t.Helper()
	var data bytes.Buffer
	writer := tar.NewWriter(&data)
	content := []byte("hello dm-verity\n")
	require.NoError(t, writer.WriteHeader(&tar.Header{
		Name:     "hello.txt",
		Mode:     0644,
		Size:     int64(len(content)),
		ModTime:  time.Unix(0, 0),
		Typeflag: tar.TypeReg,
	}))
	_, err := writer.Write(content)
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	return data.Bytes()
}

func copyFile(source, target string) error {
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	return os.WriteFile(target, data, 0600)
}
