# 🔒 stage1 — the Lock.Boot netboot UKI

Part of [Lock.Boot](https://github.com/lockboot) — see the org page for the whole boot chain. **stage1** is the netboot **UKI**: a Unified Kernel Image (Linux kernel + minimal initramfs + the `stage1` bootloader as PID 1) that [stage0](https://github.com/lockboot/stage0) fetches over the network, verifies, measures into PCR 14, and chain-loads.

Once running, `stage1` reads a `_stage2` manifest from cloud metadata (IMDSv2), downloads the stage2 payload, **admits it by a pinned `sha256` or an `ed25519` signature**, extends **PCR 14 with the payload hash** (loaded code only — never config), generates an attestation, and `exec`s it as PID 1 from a sealed in-memory image (never a file on disk).

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

## stage2 admission (`_stage2`)

stage1 admits its stage2 payload from a `_stage2` block in the instance's user-data, per architecture. Each arch entry is a **discriminated union** — exactly one of a `payload` (admit a binary now) or a `manifest` (resolve a signed manifest first):

**payload / sha256** — pin an exact binary:

```json
{
  "_stage2": {
    "x86_64":  { "payload": { "url": "https://host/stage2-amd64", "sha256": "abc123...", "args": ["--flag", "value"] } },
    "aarch64": { "payload": { "url": "https://host/stage2-arm64", "sha256": "def456..." } }
  }
}
```

**payload / ed25519** — pin a long-term release **public key** (base64 of 32 bytes). The binary rolls forward with **no reconfiguration**: re-sign it, push it, reboot. stage1 fetches a detached signature at `<url>.sig` (override with `sig_url`; `{sha256}` is substituted) and verifies it against the pinned key:

```json
{
  "_stage2": {
    "x86_64": { "payload": {
      "url": "https://host/stage2-amd64",
      "ed25519": "BASE64_32BYTE_PUBKEY",
      "args_url": "https://host/args.json"
    } }
  }
}
```

`args_url` (ed25519 mode only) fetches a **signed** JSON array of strings — verified against the same key via `<args_url>.sig` (or an explicit `args_sig_url`) — that **overrides** inline `args`.

**manifest** — pin a release key **and** a manifest URL. stage1 fetches the signed manifest (itself a `_stage2` user-data fragment), verifies its detached signature (`<url>.sig`, override with `sig_url`) against the pinned `ed25519` key, **deep-merges the whole document into the received user-data at the top level** (manifest wins on conflict), and re-evaluates the entry. It loops — a manifest may resolve to a `payload` (done) or delegate to a *fresh* `manifest` (per-hop key delegation) — until a payload is reached; a repeated `(url, sha256)` is a cycle and fails closed. Binding the binary + args under one manifest signature stops a hostile mirror from mixing-and-matching independently-signed pieces:

```json
{
  "_stage2": {
    "x86_64": { "manifest": { "url": "https://host/stage2.manifest.json", "ed25519": "BASE64_32BYTE_PUBKEY" } }
  }
}
```

The optional `manifest.sha256` also pins the manifest's own bytes. Every hop is recorded in the merged entry's `resolved_manifests` array (each with the resolved hash + verifying key) — verifier-authoritative provenance the payload sees on stdin. You don't hand-write these docs: the [`deploy` tool](#deploy) below signs the payloads/manifests and generates the `user-data.json`.

**Fallback URLs.** Every URL field (`url`, `sig_url`, `args_url`, `args_sig_url`, `manifest.url`) accepts either a single string **or a list of strings** tried in order — for mirror resiliency. Because the payload is cryptographically pinned, any mirror that yields verifying bytes is accepted; a dead or wrong mirror is simply skipped. URLs may be `http://` or `https://`, and the `*_url` fields may contain a `{sha256}` placeholder (replaced with the payload's — or manifest's — hex digest, for content-addressed signatures):

```json
{
  "_stage2": {
    "x86_64": { "payload": {
      "url": ["https://cdn1/stage2", "https://cdn2/stage2"],
      "ed25519": "BASE64_32BYTE_PUBKEY",
      "sig_url": ["https://cdn1/sigs/{sha256}.sig", "https://cdn2/sigs/{sha256}.sig"]
    } }
  }
}
```

**Measurement is code-only.** stage1 extends **PCR 14** with the SHA-256 of the stage2 binary and nothing else — the admission pin / key / signature and the config JSON are *not* measured. This keeps the platform quote reproducible from the boot artifacts alone (stage0 → UKI → app), and leaves a stage2 app free to measure whatever config *it* deems trust-relevant (PCR 15 is left untouched for it).

**Execution is pathless.** stage1 loads the payload into a sealed `memfd` (`F_SEAL_WRITE`) and `execveat`s it directly, so the bytes measured into PCR 14 are immutable and are exactly what runs — nothing is written to a named path where it could be swapped between measurement and exec. The payload receives the raw user-data JSON on **stdin** (a second in-memory file, so any runtime that reads stdin works — no extra-fd convention that would trip up Bun/Node single-file executables), and the pre-exec attestation at `/tmp/stage1.attest`.

Any statically-linked Linux ELF works, as long as it reads its config from stdin; the minimal rootfs provides `/bin/{busybox,stage1}` (plus `udhcpc.script`) and `/tmp`.

## Arguments and config model

Two distinct hops, don't conflate them:

- **stage1's own config** comes from the cloud **metadata** service (the PID-1 boot path) or, when stage1 is run as a normal process, from a user-data doc **piped on stdin** (`stage1 < user-data.json`). There are no `--url`/`--file` flags — pipe it in. `--attest` remains for diagnostics.
- **The stage2 app's argv** comes from the payload's inline **`args`** or its signed `args_url` (which overrides inline); in manifest mode these ride inside the signed manifest. They are handed to the payload as `argv[1..]` (with `argv[0] = "stage2"`).

Note on `_stage1.args`: that field belongs to **stage0**, which sets the booted EFI program's UEFI *LoadOptions* from it — the generic contract for any EFI stage1. For **this Linux UKI**, the kernel command line is baked into the signed, measured `.cmdline` and is authoritative: under Secure Boot the stub **ignores** LoadOptions, so `_stage1.args` cannot (and must not) alter the UKI cmdline. Configure a UKI-based stage1 through **`_stage2`**, not the kernel cmdline. See the [stage0 repo](https://github.com/lockboot/stage0) for the LoadOptions contract.

## Deploy

The **`deploy`** tool (binary `lockboot-deploy`) turns local build artifacts into an upload-ready deployment: it signs (or hashes) the UKI + stage2 as `payload` entries — or, with `--manifest`, wraps each in a **signed manifest** and pins a `manifest` entry — composes **mirror URL lists** from repeated `--base-url`, and emits a directory plus a merged `user-data.json` carrying both `_stage1` (the UKI hop) and `_stage2` (the payload hop).

```bash
lockboot-deploy create --arch x86_64 \
  --uki tools/build-uki/x86_64/linux.efi --stage2 build/x86_64/stage2 \
  --key release.pem \                          # ed25519 signed mode (omit for sha256 pins)
  --base-url http://cdn1 --base-url http://cdn2 \
  --out ./deploy
lockboot-deploy validate ./deploy              # check against the admission rules
lockboot-deploy modify ./deploy --add-base-url http://cdn3   # add / --remove-base-url a mirror
```

`create` writes `deploy/<arch>/{linux.efi,stage2}` (+ `.sig` in signed mode) and merges `deploy/user-data.json`; sync the directory to each mirror and pass `user-data.json` as the instance's user-data. It shares the `metadata` types with the stage1 verifier, so what it emits is exactly what stage0/stage1 accept. (`tools/publish.sh` remains as a simpler UKI-only uploader; the bootable cloud image — the stage0 Secure Boot root — is published from the [stage0 repo](https://github.com/lockboot/stage0).)

## Crates

- **`stage1`** — the on-instance PID-1 bootloader baked into the UKI (verify-only: admit → measure → exec).
- **`metadata`** — the `_stage1`/`_stage2` wire types + `validate()`, shared by the stage1 verifier and the deploy emitter (one source of truth, no drift).
- **`ed25519-sign`** — the ed25519 sign/verify + sha256 primitive (the cross-repo wire contract), used by `mkuki`, `deploy`, and `stage1`.
- **`mkuki`** — reproducible UKI assembler (kernel + gzip'd cpio layers → PE, optional `ed25519` signature); a build-host tool.
- **`deploy`** — the deployment tool above (`lockboot-deploy`); a build-host tool.
- **`example-stage2`** — a minimal example leaf payload; copy it as a template for your own stage2.

## License

Apache-2.0 OR MIT, at your option.
