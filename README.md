# 🔒 stage1 — the Lock.Boot netboot UKI

Part of [Lock.Boot](https://github.com/lockboot) — see the org page for the whole boot chain. **stage1** is the netboot **UKI**: a Unified Kernel Image (Linux kernel + minimal initramfs + the `stage1` bootloader as PID 1) that [stage0](https://github.com/lockboot/stage0) fetches over the network, verifies, measures into PCR 14, and chain-loads.

Once running, `stage1` reads a `_stage2` manifest from cloud metadata (IMDSv2), downloads the stage2 payload, verifies it by `sha256`, extends a TPM PCR, generates an attestation document, and `exec`s it as PID 1.

## Build

```bash
make x86_64            # -> tools/build-uki/x86_64/linux.efi   (the UKI)
make aarch64
make stage2-x86_64     # -> build/x86_64/stage2                (the example leaf)
```

Everything compiles inside the shared `lockboot:build` image (built from [stage0](https://github.com/lockboot/stage0)'s canonical `Dockerfile.build`); no host toolchain is needed. `vaportpm` is pulled from git, so the repo builds standalone — no sibling checkout required.

## Test the whole chain

`stage0 → UKI → stage1 → example-stage2`, under QEMU + KVM. stage0 is the harness: build its boot disk in the sibling repo, then run the chain test — it borrows `../stage0/build/<arch>/boot.disk` and the shared `lockboot:harness` image, serves the UKI + leaf + a signed/pinned manifest, and boots it:

```bash
(cd ../stage0 && make build-x86_64)
make test-chain-x86_64            # sha256 admission (default)
make test-chain-x86_64 SIGN=1     # ed25519 signed-manifest admission
```

## stage2 manifest (`_stage2`)

stage1 admits its payload from a `_stage2` block in the instance's user-data:

```json
{
  "_stage2": {
    "x86_64":  { "url": "https://example.com/stage2-amd64", "sha256": "abc123..." },
    "aarch64": { "url": "https://example.com/stage2-arm64", "sha256": "def456..." },
    "args": ["--flag", "value"]
  }
}
```

Any statically-linked Linux ELF works; the minimal rootfs provides `/bin/{busybox,stage1}` (plus `udhcpc.script`) and `/tmp`.

## Publish the UKI

The UKI is served over HTTP(S) for stage0 to fetch. Upload it and print the matching `_stage1` block (the doc stage0 uses to admit the UKI):

```bash
tools/publish.sh s3://bucket/prefix x86_64 local   # or gs://bucket/prefix
```

The bootable cloud image — the stage0 Secure Boot root — is published from the [stage0 repo](https://github.com/lockboot/stage0), not here.

## Crates

- **`stage1`** — the PID-1 bootloader baked into the UKI.
- **`mkuki`** — reproducible UKI assembler (kernel + gzip'd cpio layers → PE, optional `ed25519` signature); a build-host tool.
- **`example-stage2`** — a minimal example leaf payload; copy it as a template for your own stage2.

## License

Apache-2.0 OR MIT, at your option.
