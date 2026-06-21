# mkuki — kernel + container → stage0-bootable UKI

`mkuki` turns **a kernel image + a container root filesystem** into a signed
[Unified Kernel Image](https://uapi-group.org/specifications/specs/unified_kernel_image/)
(UKI) that [`stage0`](../stage0/README.md) can download, measure, and chain-load.

## Why this exists

`stage0` is a measured UEFI netboot anchor: it admits a payload (by pinned
sha256 **or** an ed25519 signature against a pinned release key), measures it
into **PCR 14**, and `StartImage`s it.

## Usage

```sh
mkuki \
  --kernel   vmlinuz \
  --stub     stub.efi \                 # systemd-boot stub (see below)
  --from-docker my-registry/app:1.2.3 \ # or: --rootfs ./rootfs (dir or tar)
  --cmdline  "console=ttyS0,115200n8 ro lockdown=confidentiality" \
  --arch     x86_64 \
  --sign-key release.pem \              # PKCS#8 ed25519; writes linux.efi.sig
  --url      https://cdn.example.com/releases/app-1.2.3.efi \
  --out      linux.efi
```

This writes `linux.efi`, `linux.efi.sig` (64-byte detached ed25519), prints the
UKI's sha256, and prints the ready-to-paste `_stage1` metadata snippet.

Rootfs input, pick one:
- `--from-docker IMAGE` — runs `docker create` + `docker export` for you
  (use `--docker podman` for another engine).
- `--rootfs <dir|tar>` — a directory tree, or a (optionally gzipped) tar such as
  `docker export`/`docker save`-layer output. Engine-agnostic: works with
  buildah, kaniko, etc.

The **systemd-boot stub** (`--stub`) is the only external artifact you need; grab
`stub.efi` from a `systemd-boot-unsigned` package (the repo's
`tools/build-uki/Makefile` already extracts one per arch). systemd v256+ is
recommended (see the project notes on stub VMA handling).

## Admission modes

| Mode | Flag | `_stage1` field | Rollover |
|---|---|---|---|
| **signed** | `--sign-key release.pem` | `ed25519: <pubkey b64>` | re-sign new builds under the same pinned key; **no metadata edit** |
| **sha256** | (omit `--sign-key`) | `sha256: <hex>` | re-pin the hash on every build |

The signature is a raw detached ed25519 over the entire UKI, and the printed
pubkey is the base64 of the 32-byte public key — exactly what
[`stage0`'s admission check](../stage0/src/sig.rs) verifies.

## The stage0 payload contract (what DIY owes)

A payload booted via `stage0` must:

1. **Be a UEFI PE.** A `mkuki` UKI satisfies this. (You could ship any EFI app.)
2. **Be admitted** — pinned sha256, or an ed25519 `.sig` at `<url>.sig` against
   the pinned release key.
3. **Carry its own init.** The UKI's initramfs provides PID 1; `mkuki` packs your
   container rootfs verbatim — your `init`/entrypoint must set up `/proc`, `/sys`,
   networking, etc. (`stage1` is what normally does this for you.)
4. **Bake its own cmdline.** `--cmdline` is embedded and immutable at boot — put
   your hardening flags here.

What you get for free from `stage0` regardless: a `db`-signed, Secure-Boot-locked
anchor, and **PCR 14 = sha256(your UKI)**, so the boot stays attestable to your
image hash. What you give up vs `stage1`: auto metadata-config pull, the
pre-execution attestation document, and the PCR 15 config measurement — build
those into your image if you need them.

## Reproducibility

Output is byte-deterministic for identical inputs: cpio entries are sorted
bytewise, stamped `uid=gid=0`, `mtime=0`, sequential inodes; gzip headers carry
no mtime/filename; PE section VMAs are derived from the stub. The generated
`.osrel` records a `BUILD_ID` over the component hashes. Same inputs → same UKI →
same PCR 14.

## Caveats

- **Everything is loaded into RAM.** `stage0` pulls the whole payload over TCP4
  into memory, and an initramfs unpacks into tmpfs (~2× the rootfs in RAM). Fine
  for a slim container; for large images, ship a tiny initramfs that mounts an
  erofs/squashfs rootfs instead of packing the whole tree into `.initrd`.
- `mkuki` does **not** `db`/Authenticode-sign the UKI (the optional-header
  checksum is zeroed). That path is only needed for firmware-direct boot, not for
  `stage0` admission; `sbsign` it separately if you also boot it off an ESP.
