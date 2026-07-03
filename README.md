# 🔒 stage1 — the Lock.Boot netboot UKI

Part of [Lock.Boot](https://github.com/lockboot) — see the org page for the whole boot chain. **stage1** is the netboot **UKI**: a Unified Kernel Image (Linux kernel + minimal initramfs + the `stage1` bootloader as PID 1) that [stage0](https://github.com/lockboot/stage0) fetches over the network, verifies, measures into PCR 14, and chain-loads.

Once running, `stage1` reads a `_stage2` manifest from cloud metadata (IMDSv2), downloads the stage2 payload, **admits it by a pinned `sha256` or an `ed25519` signature**, extends **PCR 14 with the payload hash** (loaded code only — never config), generates an attestation, and `exec`s it as PID 1.

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

stage1 admits its stage2 payload from a `_stage2` block in the instance's user-data, per architecture. Choose **one** admission mode per entry.

**sha256** — pin an exact payload:

```json
{
  "_stage2": {
    "x86_64":  { "url": "https://host/stage2-amd64", "sha256": "abc123..." },
    "aarch64": { "url": "https://host/stage2-arm64", "sha256": "def456..." },
    "args": ["--flag", "value"]
  }
}
```

**ed25519** — pin a long-term release **public key** (base64 of 32 bytes). The payload can then roll forward with **no reconfiguration**: re-sign it, push it, reboot. stage1 fetches a detached signature at `<url>.sig` (override with `sig_url`; `{sha256}` is substituted) and verifies it against the pinned key:

```json
{
  "_stage2": {
    "x86_64": {
      "url": "https://host/stage2-amd64",
      "ed25519": "BASE64_32BYTE_PUBKEY",
      "args_url": "https://host/args.json"
    }
  }
}
```

`args_url` (ed25519 mode only) fetches a **signed** JSON array of strings — verified against the same key via `<args_url>.sig` (or an explicit `args_sig_url`) — that **overrides** inline `args`. Generate configs with `stage1 --make-config <ARCH> <URL>` (sha256) or `stage1 --make-config-ed25519 <ARCH> <URL> <PUBKEY_B64>`; sign payloads with `openssl pkeyutl -sign -rawin` (the same key format `mkuki` uses, wire-compatible with stage0).

**Fallback URLs.** Every URL field (`url`, `sig_url`, `args_url`, `args_sig_url`) accepts either a single string **or a list of strings** tried in order — for mirror resiliency. Because the payload is cryptographically pinned, any mirror that yields verifying bytes is accepted; a dead or wrong mirror is simply skipped. URLs may be `http://` or `https://`, and `sig_url`/`args_url`/`args_sig_url` may contain a `{sha256}` placeholder (replaced with the payload's hex digest, for content-addressed signatures):

```json
{
  "_stage2": {
    "x86_64": {
      "url": ["https://cdn1/stage2", "https://cdn2/stage2"],
      "ed25519": "BASE64_32BYTE_PUBKEY",
      "sig_url": ["https://cdn1/sigs/{sha256}.sig", "https://cdn2/sigs/{sha256}.sig"]
    }
  }
}
```

**Measurement is code-only.** stage1 extends **PCR 14** with the SHA-256 of the stage2 binary and nothing else — the admission pin / key / signature and the config JSON are *not* measured. This keeps the platform quote reproducible from the boot artifacts alone (stage0 → UKI → app), and leaves a stage2 app free to measure whatever config *it* deems trust-relevant (PCR 15 is left untouched for it).

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
