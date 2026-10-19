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

package server

import (
	"context"
	"testing"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/images/imagetest"
	imagestore "github.com/containerd/containerd/v2/internal/cri/store/image"
	"github.com/containerd/errdefs"
	"github.com/containerd/platforms"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"
)

type aliasImageStore struct {
	images.Store
	records map[string]images.Image
}

func (s aliasImageStore) Get(_ context.Context, name string) (images.Image, error) {
	if image, ok := s.records[name]; ok {
		return image, nil
	}
	return images.Image{}, errdefs.ErrNotFound
}

func TestDmverityContainerImage(t *testing.T) {
	ctx := t.Context()
	store := imagetest.NewContentStore(ctx, t)
	config := store.JSONObject(ocispec.MediaTypeImageConfig, ocispec.Image{
		Platform: platforms.DefaultSpec(),
		RootFS: ocispec.RootFS{
			Type: "layers", DiffIDs: []digest.Digest{digest.FromString("diff")},
		},
	})
	layer := store.Blob(ocispec.MediaTypeImageLayer, []byte("layer"))
	const observationLabel = "containerd.io/gc.ref.content.dmverity"
	manifest := func(name string) ocispec.Descriptor {
		t.Helper()
		return store.JSONObject(ocispec.MediaTypeImageManifest, ocispec.Manifest{
			Config: config.Descriptor, Layers: []ocispec.Descriptor{layer.Descriptor},
			Annotations: map[string]string{"test.variant": name},
		}).Descriptor
	}
	plain := manifest("plain")
	signed := manifest("selected")
	invalid := manifest("invalid-observation")
	_, err := store.Update(ctx, content.Info{
		Digest: invalid.Digest, Labels: map[string]string{observationLabel: "not-a-digest"},
	}, "labels")
	require.NoError(t, err)
	otherConfig := store.JSONObject(ocispec.MediaTypeImageConfig, ocispec.Image{
		Platform: platforms.DefaultSpec(), Author: "different-config",
	})
	repointed := store.Manifest(otherConfig, layer).Descriptor
	otherPlatform := platforms.DefaultSpec()
	otherPlatform.Architecture = "unsupported"
	index := store.Index(
		imagetest.AddPlatform(imagetest.Content{Descriptor: repointed}, otherPlatform),
		imagetest.AddPlatform(imagetest.Content{Descriptor: signed}, platforms.DefaultSpec()),
	).Descriptor
	const (
		plainRef  = "docker.io/library/test:plain"
		signedRef = "docker.io/library/test:signed"
	)
	digestRef := "docker.io/library/test@" + signed.Digest.String()
	shortID := config.Descriptor.Digest.Encoded()[:12]
	hexNameRef := "docker.io/library/" + shortID + ":latest"
	records := map[string]images.Image{}
	for ref, target := range map[string]ocispec.Descriptor{
		plainRef: plain, signedRef: signed, digestRef: signed, hexNameRef: signed,
		"docker.io/library/test:invalid":   invalid,
		"docker.io/library/test:repointed": repointed, "docker.io/library/test:index": index,
	} {
		records[ref] = images.Image{Name: ref, Target: target}
	}
	client, err := containerd.New("", containerd.WithServices(
		containerd.WithContentStore(store.Store),
		containerd.WithImageStore(aliasImageStore{records: records}),
	))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	id := config.Descriptor.Digest.String()

	cases := []struct {
		name    string
		spec    runtime.ImageSpec
		aliases []string
		stock   bool
		want    string
		wantErr string
	}{
		{name: "requested signed tag", spec: runtime.ImageSpec{Image: "test:signed"}, want: signedRef},
		{name: "requested signed digest", spec: runtime.ImageSpec{Image: digestRef}, want: digestRef},
		{name: "named alias matching ID prefix", spec: runtime.ImageSpec{Image: shortID}, aliases: []string{plainRef, hexNameRef}, want: hexNameRef},
		{name: "requested selected platform", spec: runtime.ImageSpec{Image: "test:index"}, want: "docker.io/library/test:index"},
		{name: "kubelet ID and signed tag", spec: runtime.ImageSpec{Image: id, UserSpecifiedImage: "test:signed"}, want: signedRef},
		{name: "kubelet ID and signed digest", spec: runtime.ImageSpec{Image: id, UserSpecifiedImage: digestRef}, want: digestRef},
		{name: "kubelet short ID and tag", spec: runtime.ImageSpec{Image: config.Descriptor.Digest.Encoded()[:12], UserSpecifiedImage: "test:signed"}, want: signedRef},
		{name: "explicit image takes priority", spec: runtime.ImageSpec{Image: "test:signed", UserSpecifiedImage: "test:plain"}, want: signedRef},
		{name: "repointed explicit tag", spec: runtime.ImageSpec{Image: "test:repointed"}, wantErr: "expected " + id},
		{name: "repointed kubelet tag", spec: runtime.ImageSpec{Image: id, UserSpecifiedImage: "test:repointed"}, wantErr: "expected " + id},
		{name: "missing kubelet tag", spec: runtime.ImageSpec{Image: id, UserSpecifiedImage: "test:absent"}, wantErr: "not found"},
		{name: "bare ID requires binding", spec: runtime.ImageSpec{Image: id}, wantErr: "requires an explicit image reference"},
		{name: "bare short ID requires binding", spec: runtime.ImageSpec{Image: config.Descriptor.Digest.Encoded()[:12]}, wantErr: "requires an explicit image reference"},
		{name: "user image is also an ID", spec: runtime.ImageSpec{Image: id, UserSpecifiedImage: id}, wantErr: "requires an explicit image reference"},
		{name: "stock ignores requested signed tag", spec: runtime.ImageSpec{Image: "test:signed"}, stock: true, want: plainRef},
		{name: "stock ignores unbound user image", spec: runtime.ImageSpec{Image: id, UserSpecifiedImage: "test:repointed"}, stock: true, want: plainRef},
		{name: "stock does not inspect invalid metadata", spec: runtime.ImageSpec{Image: id}, aliases: []string{"docker.io/library/test:invalid", signedRef}, stock: true, want: "docker.io/library/test:invalid"},
	}
	for i := range cases {
		tc := &cases[i]
		t.Run(tc.name, func(t *testing.T) {
			aliases := tc.aliases
			if aliases == nil {
				aliases = []string{plainRef, signedRef}
			}
			service := &criService{
				client: client, dmverityCapabilities: map[string]bool{"selected": !tc.stock},
			}
			image := imagestore.Image{ID: id, References: aliases}
			var actual containerd.Image
			if tc.stock {
				actual, err = service.toContainerdImage(ctx, image)
			} else {
				actual, err = service.dmverityContainerImage(ctx, image, &tc.spec)
			}
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				require.Nil(t, actual)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, actual.Name())
			// Checkpoint and image-volume callers retain the original conversion.
			original, err := service.toContainerdImage(ctx, image)
			require.NoError(t, err)
			require.Equal(t, aliases[0], original.Name())
		})
	}
}
