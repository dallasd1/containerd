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
	compressedLayer := store.Blob(ocispec.MediaTypeImageLayerZstd, []byte("compressed layer"))
	compressed := store.Manifest(config, compressedLayer).Descriptor
	equivalentSigned := manifest("equivalent-signed")
	differentSigned := manifest("different-signed")
	retainSigned := func(subject ocispec.Descriptor, root string) {
		t.Helper()
		payload := func(mediaType string) ocispec.Descriptor {
			desc := store.Blob(mediaType, []byte(mediaType)).Descriptor
			desc.Annotations = map[string]string{
				"io.containerd.erofs.v1/dmverity.source-layer-digest": layer.Descriptor.Digest.String(),
			}
			if mediaType == "application/vnd.containerd.erofs.dmverity.layer-signature.v1+pkcs7" {
				desc.Annotations["io.containerd.erofs.v1/dmverity.root-hash"] = root
			}
			return desc
		}
		referrer := store.JSONObject(ocispec.MediaTypeImageManifest, ocispec.Manifest{
			MediaType:    ocispec.MediaTypeImageManifest,
			ArtifactType: "application/vnd.containerd.erofs.dmverity.v1",
			Config:       ocispec.DescriptorEmptyJSON,
			Subject:      &subject,
			Layers: []ocispec.Descriptor{
				payload("application/vnd.containerd.erofs.metadata.v1"),
				payload("application/vnd.containerd.erofs.dmverity.merkle-tree.v1"),
				payload("application/vnd.containerd.erofs.dmverity.layer-signature.v1+pkcs7"),
			},
		})
		_, err := store.Update(ctx, content.Info{
			Digest: subject.Digest,
			Labels: map[string]string{observationLabel: referrer.Descriptor.Digest.String()},
		}, "labels")
		require.NoError(t, err)
	}
	root := digest.FromString("root").Encoded()
	retainSigned(signed, root)
	retainSigned(equivalentSigned, root)
	retainSigned(differentSigned, digest.FromString("different-root").Encoded())
	invalid := manifest("invalid-observation")
	_, err := store.Update(ctx, content.Info{
		Digest: invalid.Digest, Labels: map[string]string{observationLabel: "not-a-digest"},
	}, "labels")
	require.NoError(t, err)
	missing := manifest("missing-bundle")
	_, err = store.Update(ctx, content.Info{
		Digest: missing.Digest, Labels: map[string]string{observationLabel: digest.FromString("missing-bundle").String()},
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
		"docker.io/library/test:compressed": compressed,
		"docker.io/library/test:equivalent": equivalentSigned,
		"docker.io/library/test:different":  differentSigned,
		"docker.io/library/test:invalid":    invalid,
		"docker.io/library/test:missing":    missing,
		"docker.io/library/test:repointed":  repointed, "docker.io/library/test:index": index,
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
		{name: "requested unsigned tag", spec: runtime.ImageSpec{Image: id, UserSpecifiedImage: "test:plain"}, want: plainRef},
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
		{name: "unambiguous ID", spec: runtime.ImageSpec{Image: id}, aliases: []string{plainRef}, want: plainRef},
		{name: "unambiguous short ID", spec: runtime.ImageSpec{Image: shortID}, aliases: []string{plainRef}, want: plainRef},
		{name: "unambiguous signed ID", spec: runtime.ImageSpec{Image: id}, aliases: []string{signedRef}, want: signedRef},
		{name: "no cached aliases", spec: runtime.ImageSpec{Image: id}, aliases: []string{}, wantErr: "has no cached image references"},
		{name: "aliases of same manifest", spec: runtime.ImageSpec{Image: id}, aliases: []string{signedRef, digestRef}, want: signedRef},
		{name: "unsigned compression aliases", spec: runtime.ImageSpec{Image: id}, aliases: []string{plainRef, "docker.io/library/test:compressed"}, want: plainRef},
		{name: "unsigned compression aliases reversed", spec: runtime.ImageSpec{Image: id}, aliases: []string{"docker.io/library/test:compressed", plainRef}, want: "docker.io/library/test:compressed"},
		{name: "equivalent signed identities", spec: runtime.ImageSpec{Image: id}, aliases: []string{signedRef, "docker.io/library/test:equivalent"}, want: signedRef},
		{name: "different signed identities", spec: runtime.ImageSpec{Image: id}, aliases: []string{signedRef, "docker.io/library/test:different"}, wantErr: "requires an explicit image reference"},
		{name: "mixed identities signed first", spec: runtime.ImageSpec{Image: id}, aliases: []string{signedRef, plainRef}, wantErr: "requires an explicit image reference"},
		{name: "invalid observation is not unsigned", spec: runtime.ImageSpec{Image: id}, aliases: []string{plainRef, "docker.io/library/test:invalid"}, wantErr: "invalid retained dm-verity referrer"},
		{name: "missing signed bundle is not unsigned", spec: runtime.ImageSpec{Image: id}, aliases: []string{plainRef, "docker.io/library/test:missing"}, wantErr: "read retained signed dm-verity bundle"},
		{name: "index and manifest aliases", spec: runtime.ImageSpec{Image: id}, aliases: []string{signedRef, "docker.io/library/test:index"}, want: signedRef},
		{name: "repointed cached alias", spec: runtime.ImageSpec{Image: id}, aliases: []string{"docker.io/library/test:repointed"}, wantErr: "expected " + id},
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
				actual, err = service.dmverityContainerImage(ctx, image, &tc.spec, nil)
			}
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				require.Nil(t, actual)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, actual.Name())
			// Checkpoint callers retain the original conversion.
			original, err := service.toContainerdImage(ctx, image)
			require.NoError(t, err)
			require.Equal(t, aliases[0], original.Name())
		})
	}
}
