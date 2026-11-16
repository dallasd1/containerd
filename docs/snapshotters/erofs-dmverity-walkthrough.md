# Signed EROFS/dm-verity: a walkthrough

This worktree's v3 signature identities and referrer-owned GC; [general EROFS options](erofs.md).

## The short answer

The snapshotter manages snapshots, parents, and mounts. The **referrer handler** parses
registry metadata; the **EROFS differ**, not the snapshotter, assembles signed layer data.

Signed assembly needs actual layer bytes, binary EROFS metadata, a hash tree, and a
signature. It creates one `layer.erofs` **per image layer**, not an all-layers image.
Read-only EROFS mounts become OverlayFS lower layers beneath a container's writable layer.

The snapshot **key** is a local cache/database name, not a cryptographic key.
Including the selected signature prevents an old signature's snapshot from
satisfying a replacement request. Selection does not rewrite or delete the old one.

## Vocabulary: which object are we talking about?

### Registry objects and image configuration

- **Descriptor:** a reference containing a blob's digest, size, media type, and
  optional annotations. It describes bytes; it is not those bytes.
- **OCI image index:** a list of image manifests, commonly one per platform.
  The signed chain here is resolved from the selected platform's manifest.
- **OCI image manifest / subject manifest:** JSON naming an image config and
  ordered layer descriptors. A dm-verity referrer's `subject` names this manifest,
  not the config or a snapshot.
- **Image config / CONFIG blob:** [JSON][oci-config] named by the manifest's `config`:
  `rootfs.diff_ids`, platform, and runtime defaults (environment, entrypoint,
  command, user). Multiple manifests can share it despite different compression.
  This is **not** `/etc/containerd/config.toml`, the daemon's plugin settings.
- **Content store:** digest-addressed blobs plus local information/labels about
  them. Manifests, config JSON, layer archives, and referrer payloads live here.
  A content blob is **not** a snapshot or a mounted filesystem.

### Layer identity, ChainID, and parents

- **Layer digest:** hashes the distributed layer blob, often a compressed tar.
  Recompressing a tar can change this digest without changing its DiffID.
- **DiffID:** hashes the uncompressed layer tar stream for this tar-layer path,
  not the resulting EROFS file. Apply calculates it; unpack checks the config's
  expected value before committing.
- **Ordinary OCI ChainID:** identifies an ordered sequence of DiffIDs. It does
  not identify a dm-verity signature, certificate, or referrer.

Using symbolic digest strings `D1`, `D2`, `D3` and `H(x)` for the SHA-256 digest
string of the exact bytes of `x`, the [OCI identity implementation][chainid] gives:

```text
C1 = D1
C2 = H(C1 + " " + D2)
C3 = H(C2 + " " + D3)
```

The separators are single spaces; the input digest strings include `sha256:`.
For ordinary snapshots, `C2`'s parent is `C1`. For the signed lane, the actual
snapshot parent is the **previous selected signed snapshot key**, not `C1`.

### Snapshots and the overloaded word "key"

- **Active snapshot:** a writable transaction created with `Prepare`, used for
  applying a layer or as a container's writable rootfs.
- **Committed snapshot:** a reusable read-only changeset with a parent.
  `Commit` consumes the active transaction and names the committed snapshot.
  A committed image top can parent a container's active snapshot.
- **Snapshot key:** the local lookup name used by unpack, snapshot metadata,
  parent selection, and GC. "Cache identity" is a useful mental model.
- **Root hash:** the Merkle-tree root digest committing to the protected layer
  data. Here it is 64 hexadecimal characters, not a `sha256:`-prefixed ChainID.
- **Signature digest:** the content digest of the selected PKCS#7 signature
  bytes, including its algorithm prefix. It is not the referrer-manifest digest.
- **Signing key / certificate:** the cryptographic identity used to sign the
  root hash; kernel trust configuration determines whether it is accepted.
  The private signing key is not a snapshot key or an input needed on the node.
- **`root_hash_sig_key_desc`:** a device-mapper option naming a kernel keyring
  object holding signature bytes. The [library][verity-library] temporarily loads it;
  this lookup description is neither the snapshot key nor the trusted signing
  certificate itself.

### Referrers, bundles, and payloads

- **Selected referrer manifest:** an OCI artifact manifest with artifact type
  `application/vnd.containerd.erofs.dmverity.v1`, bound to the subject image
  manifest. Discovery selects one candidate, not all historical signatures.
- **Retained dm-verity bundle / signature bundle:** **synonyms in this patch** for
  the selected referrer and its per-layer artifacts; not just the PKCS#7 file.
- For each image layer, the bundle names three content payloads: **EROFS
  metadata** (the binary tar-index/filesystem prefix), **tree** (the published
  dm-verity superblock/hash-tree bytes), and **signature** (PKCS#7 bytes).
  Annotations bind them to a source layer digest and give its root hash.
- A referrer manifest also has a `config` descriptor, but this path selects
  materialization payloads from its `layers` and annotations. That artifact
  config is not the application image config supplying `rootfs.diff_ids`.
- **Content GC labels/edges:** local references telling containerd what else a
  reachable blob retains; separate from immutable registry JSON.
- **Lease:** a containerd retention mechanism for resources, including work in
  progress. A lease is not a signature approval or a snapshot identity.
- **Plain and signed lanes:** separate snapshot chains for ordinary OCI unpack
  and selected signed materializations. Both can coexist for the same DiffIDs.

## From a registry pull to a container filesystem

This is the capability-enabled transfer/CRI path, not every generic local unpack.

```text
registry image/index + config + layer blobs + selected referrer payloads
  -> content store: bytes, retained selection, GC content edges
  -> unpacker: DiffIDs -> ordinary ChainIDs -> signed keys and parents
  -> EROFS differ: index + uncompressed tar + padding + published tree
                  plus signature and local dm-verity metadata sidecars
  -> EROFS snapshotter: commit records, validate identity, mount recipes
  -> mount handler -> signed dm-verity device -> read-only EROFS mounts
  -> OverlayFS lower layers + writable upper -> container rootfs
```

1. **Fetch and observe.** Transfer fetches image objects into the content store.
   `configureDmverityFetchRetention` installs the referrer handler when the
   relevant capability applies; `configureUnpackPlatforms` wires preparation and
   signed apply options. Cached CRI unpack restores retained targets locally.
   Merely finding some layer bytes in the store does not select a signature.

2. **Select and retain a bundle.** `fetchSignatures` chooses the matching
   artifact with the latest parsed creation timestamp; ties choose the
   lexicographically smaller digest. Missing/invalid times count as zero.
   `readDmverityBundleManifest` checks subject/type and all three descriptors per
   rootfs layer, not cryptographic trust.
   `persistSignatureReferrer` fetches payloads and installs bundle-to-payload
   content edges before exposing targets to unpack.
   `recordDmverityObservation` records the selected bundle on the subject.
   Replacing a retained selection must preserve every layer's root hash.
   Registry-supplied target annotations are stripped, not accepted as authority.

3. **Choose snapshots before applying.** The unpacker reads the image config,
   computes ordinary ChainIDs, then calls `PrepareDmverityLayer` with each
   ChainID and selected parent key. Signed layers get v3 keys and identity
   labels; plain layers keep ordinary keys. Cache hits must match the selected
   parent, root hash, and signature digest; mismatches are errors. On a miss,
   unpack prepares an active snapshot and applies the layer, never relabeling
   an old variant as the new one.

4. **Assemble actual data in the differ.** `erofsDiff.Apply` decompresses the
   source layer stream and calls `applySignedTarIndexArtifacts`. For signed
   targets it uses the published index/tree, rather than regenerating their
   bytes with a fresh local `mkfs` or generating a replacement signature:

   ```text
   layer.erofs = [published binary EROFS metadata][uncompressed source tar]
                 [zero padding to 4096-byte alignment][published superblock/tree]
   layer.erofs.sig       = selected PKCS#7 signature bytes
   layer.erofs.dmverity  = local JSON: roothash and hashoffset
   ```

   The offset is the end of the padded data, where the tree payload begins.
   Downloaded binary EROFS "metadata" is not this generated JSON "metadata".
   An index alone cannot supply file data. The differ returns the tar's DiffID,
   which unpack checks against the config.

5. **Commit without silently downgrading.** The snapshotter's `Commit` verifies
   the prepared/committed signed identity, the presence of `layer.erofs`, and
   matching local root-hash metadata and signature bytes. It records the
   committed snapshot and parent. A walking differ's ordinary extracted
   directory cannot substitute for signed assembly. Commit is neither the kernel
   trust check nor a full read-through of the hash tree.

6. **Mount and verify.** `createErofsMount` passes expected root/signature
   identity to the EROFS mount handler. `setupSignedDmVerityDevice` creates, or
   checks for reuse of, a signed mapper; its name includes the snapshot directory
   identity and a hash of the expected root/signature digest. `OpenSigned`
   passes the signature to the kernel using `root_hash_sig_key_desc`.
   The kernel checks the root-hash signature against its configured trust and
   dm-verity verifies protected blocks as they are read. The EROFS mounts then
   supply OverlayFS lowerdirs; the writable upper is separate, not signed by
   this image-layer mechanism. CRI uses `DmverityImageSnapshotKey` to resolve
   the same selected top for container creation and unpack readiness.

## Why the v3 snapshot key matters

[`DmveritySnapshotKey`][dmverity-identity] computes exactly:

```text
H(x) = "sha256:" + lowercase_hex(SHA256(bytes(x)))
K = H("erofs-dmverity-v3\n" + parent + "\n" + ordinaryChainID + "\n" +
      lowercaseRootHash + "\n" + signatureDigest) + "-dmverity-v3"
```

There is no trailing newline. `parent` is empty at the bottom, otherwise the full
previous selected key. ChainID/signature digests include their algorithm prefixes.

The root hash identifies protected data, **not the selected signature**.
Different signatures can cover identical data; reusing a matching-root snapshot
would keep its old signature. The signature digest separates materializations.
The parent propagates rotation through descendants even when their individual
roots and signatures have not changed.

Same chain, roots, signatures, and parents can reuse existing snapshots.
Different bundles with identical selected layer identities can share physical
snapshots: the bundle digest is **not** part of `K`. `layerPreparationIdentity`
includes the top GC owner and qualifier so another bundle still installs its
retention edge. Owner-aware dedup is not an extra snapshot-key component.
Alternate layer blobs are still fetched when manifests share configs/cache.

## A concrete signature rotation

All names below are symbolic, not usable digests. Let `F(C, P, R, S)` denote the
v3 formula; image manifest `M` keeps the same config, DiffIDs, and layer roots.

```text
bundle A selected:                         bundle B selected later:
  signature digests S1a, S2                  signature digests S1b, S2
  K1a = F(C1, "",  R1, S1a)                  K1b = F(C1, "",  R1, S1b)
  K2a = F(C2, K1a, R2, S2)                   K2b = F(C2, K1b, R2, S2)
```

`K1b != K1a` because its signature changed; `K2b != K2a` because its parent
changed. Unpack materializes the B chain if absent. Existing content blobs can
be reused by digest, without promising block deduplication across snapshot files.

A running container parented by `K2a` stays there, with the old materialized
signature. Future CRI creation resolves the selected B chain. No signature
file is overwritten in place. Cached same-root data is not evidence that the
new signature was selected, nor does selection itself delete the A chain.

## Who keeps each chain alive? The GC ownership fix

```text
image record -> optional index -> subject image manifest M
                                 |-- normal edges -> config -> plain top -> parents
                                 |-- normal edges -> source layer blobs
                                 `-- gc.ref.content.dmverity -> selected bundle B
                                                                |-- metadata/tree/signature blobs
                                                                `-- qualified snapshot edge
                                                                    -> signed top -> parents
```

The subject's full label is `containerd.io/gc.ref.content.dmverity`.
The bundle's signed-top label is:

```text
containerd.io/gc.ref.snapshot.<snapshotter>/dmverity-<hex(SHA256(bytes(topKey)))>
```

Its **value** is `topKey`. The qualifier hashes the entire top-key string and
uses only the 64 hex digits, without another `sha256:` prefix.
Ordinary plain references stay on the image config as
`containerd.io/gc.ref.snapshot.<snapshotter> = ordinaryTopChainID`.
Parent links retain lower layers. Multiple reachable bundle owners can retain one top.

Previously, keeping qualified historical signed-top edges on the shared image
config meant a still-live config pinned every old signature variant. Changing
the subject's selected bundle did not remove those unrelated config edges.
Now `PrepareDmverityLayer` sets `GCContent` to the selected referrer, and unpack
writes the qualified edge **on that bundle**, not on the shared config.
Changing M's selection to B can make A and its snapshots GC-eligible once no
other image/owner, container snapshot, lease, or other GC root retains them.
It is normal reachability GC, not immediate deletion during referrer selection.

**No migration:** earlier experimental keys/config-owned edges are not adopted or cleaned up.
Legacy config edges can retain old chains until their owning config itself becomes unreachable.

## Boundaries and evidence

- Plain OCI/overlayfs behavior remains ordinary; the preparation hook is optional.
  Plain and signed EROFS lanes coexist without replacing one another.
- Discovery is optional, not "reject every unsigned image": unsupported referrer
  discovery or an unsigned/unobserved image can use the plain path. A malformed
  latest candidate is ignored in favor of a usable retained selection, if any;
  without one it does not by itself force signing. Fetch/transport failures
  propagate. A signed observation is not cleared when discovery returns no bundle.
- Retained-bundle/payload checks, apply/commit validation, and signed mounts fail
  on errors instead of falling back to plain. Signed native-EROFS input is
  unsupported: the assembler requires a tar layer. `dmverity_mode` controls the
  separate non-referrer policy; signed mounts require `enable_dmverity_referrers`,
  and `NewSnapshotter` rejects enabling referrers with `dmverity_mode = "off"`.
- `TestUnpackSignedSnapshotGC` is a real metadata-GC regression using a **native
  backend registered as `erofs`**, plus a synthetic applier. It exercises owners,
  containers, leases, and retired variants, not kernel EROFS/dm-verity mounts.
  This walkthrough does not claim new live-node retired-variant GC validation.

## Source map: read these instead of the whole patch

- **Existing fetch/selection and wiring:** [referrer helpers][referrers],
  `dmverityHandler.Handle`/`fetchSignatures`; [transfer plugin][transfer],
  `configureDmverityFetchRetention`/`configureUnpackPlatforms`;
  [CRI opts][cri-opts], `unpackImage`/`WithNewSnapshot`.
- **Rotation identity:** [dm-verity helpers][dmverity-identity],
  `DmveritySnapshotKey`/`ValidateDmveritySnapshot`; [referrer helpers][referrers],
  `PrepareDmverityLayer`/`DmverityImageSnapshotKey`.
- **Unpack and latest owner-aware GC/dedup follow-up:** [unpacker][unpacker],
  `prepareLayers`/`layerPreparationIdentity`/`unpack`;
  [snapshot interface/policy][snapshot-api], `LayerPreparation.GCContent`.
- **Existing assembly and mount mechanics:** [differ][differ], `erofsDiff.Apply`;
  [signed assembler][assembler], `applySignedTarIndexArtifacts`;
  [snapshotter][snapshotter], `Commit`/`mounts`; [mount handler][mount-handler],
  `setupSignedDmVerityDevice`;
  [dm-verity bridge][dmverity-bridge], `OpenSigned`/`VerifySignedDevice`.
- **Reachability/readers:** [metadata GC][gc], `gcContext.references`;
  [image usage][usage], `CalculateImageUsage`;
  [CRI image store][cri-store], `Store.getImage`.
- **Regression scope:** [unpacker tests][unpack-tests], `TestUnpackSignedSnapshotGC`.

[oci-config]: ../../vendor/github.com/opencontainers/image-spec/specs-go/v1/config.go
[chainid]: ../../vendor/github.com/opencontainers/image-spec/identity/chainid.go
[snapshot-api]: ../../core/snapshots/snapshotter.go
[dmverity-identity]: ../../pkg/snapshotters/dmverity.go
[verity-library]: ../../vendor/github.com/containerd/go-dmverity/pkg/verity/verity.go
[referrers]: ../../pkg/snapshotters/dmverity_referrers.go
[transfer]: ../../plugins/transfer/plugin.go
[cri-opts]: ../../internal/cri/opts/container.go
[unpacker]: ../../core/unpack/unpacker.go
[differ]: ../../plugins/diff/erofs/differ.go
[assembler]: ../../plugins/diff/erofs/signed_tar_index.go
[snapshotter]: ../../plugins/snapshots/erofs/erofs.go
[mount-handler]: ../../plugins/mount/erofs/plugin_linux.go
[dmverity-bridge]: ../../internal/dmverity/dmverity_linux.go
[gc]: ../../core/metadata/gc.go
[usage]: ../../core/images/usage/calculator.go
[cri-store]: ../../internal/cri/store/image/image.go
[unpack-tests]: ../../core/unpack/unpacker_test.go
