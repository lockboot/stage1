# stage0 — measured UEFI network bootloader

`stage0` is a pure-UEFI application (no Linux kernel) that the firmware boots
directly. It downloads and chain-loads another **UEFI** binary over the network,
measuring it into the TPM first. It is the kernel-less sibling of `stage1`:
same metadata-driven, measure-then-execute model, but living entirely in UEFI
boot services.

## Flow

1. Bring up the NIC via `EFI_IP4_CONFIG2` (DHCP).
2. Fetch a `_stage0` user-data document from the cloud metadata service over
   `EFI_HTTP_PROTOCOL` (EC2 IMDSv2 → GCP → Azure → Aliyun, mirroring `stage1`).
3. Download the per-arch UEFI payload from the pinned URL over raw `EFI_TCP4`
   (`src/tcp4.rs`); a hostname URL is resolved via `EFI_DNS4` (`src/dns4.rs`).
   Metadata uses `EFI_HTTP` at fixed link-local IPs; the payload uses TCP4.
4. **Admit** the payload by one of two policies (see "Admission & trust"):
   - **sha256 mode** — the payload's SHA-256 must equal the value pinned in the
     metadata (immutable payload).
   - **signed mode** — a detached ed25519 signature fetched from `<url>.sig` must
     verify against a long-term release **public key** pinned in the metadata
     (the payload can roll forward without editing metadata).
5. Measure into the TPM via `EFI_TCG2_PROTOCOL`: **PCR 14** ← SHA-256(payload).
   Nothing else is measured — see "Admission & trust".
6. `LoadImage` (from the memory buffer, via a temporary `FileAuthentication`
   override) + `StartImage` to chain-load.

Integrity/authenticity comes from the pinned hash or signature, so plain HTTP is
used (no reliance on the inconsistently-available `EFI_TLS_PROTOCOL`).

## Admission & trust

The attestation surface is deliberately minimal: **the only thing measured is
PCR 14** — "stage0 ran, and it loaded a binary with this hash." The config, the
pinned hash, the release key and the signature are *not* measured. A verifier
just checks PCR 14 against the set of approved release hashes; it does not have
to model the metadata document or key material. (This is why PCR 15 — the config
measurement `stage1` does — is intentionally dropped here.)

The signature/hash is **admission control only**: it decides whether stage0 is
*willing* to load a payload, not what gets attested. Signed mode exists so a
deployment can pin a long-term release key once and let new builds roll forward
under that key without touching VM metadata; the private key stays offline with
the publisher and never reaches a deployed machine.

Because the payload is admitted by stage0's own policy rather than the firmware
`db`, stage0 chain-loads it through a temporary **security-arch override**
(`secauth.rs`): it swaps `EFI_SECURITY2_ARCH_PROTOCOL.FileAuthentication` for an
allow-all across a single `LoadImage`, then restores it — exactly shim's
`security_policy_install()`. The firmware still does all real PE loading and
relocation; only the *verdict* is replaced. This is what lets the deployment
keep its lockdown model (a per-release, ephemeral `db` key that signs `stage0`
itself and is then destroyed, with the variable store locked) **and** still
chain-load late-bound payloads — the two are otherwise mutually exclusive, since
an ephemeral, destroyed key cannot sign a payload fetched at boot.

Note this makes `stage0` a trust anchor *with policy*, not merely a measurer:
it is itself `db`-signed and measured, and everything it loads is measured into
PCR 14, so the chain stays attestable end to end.

## `_stage0` metadata schema

Each arch entry carries a `url` plus **exactly one** of `sha256` (pin an exact
hash) or `ed25519` (pin a base64 release public key; the detached signature is
fetched from `<url>.sig`):

```json
{
  "_stage0": {
    "args": ["optional", "load-options"],
    "x86_64":  { "url": "http://…/payload.efi", "sha256":  "<64 hex>" },
    "aarch64": { "url": "http://…/payload.efi", "ed25519": "<base64 32-byte pubkey>" }
  }
}
```

## TPM access

`stage0` reuses `vaportpm-attest` unchanged — that crate funnels all TPM I/O
through its `TpmTransport` trait, so `stage0` supplies a `Tcg2Transport` backed
by `EFI_TCG2_PROTOCOL.SubmitCommand` (`src/tcg2.rs`) and calls the same
`pcr_extend` used on Linux. `stage0` only *measures*; the chained payload (or a
later Linux stage) produces the actual TPM2_Quote. Build the crate with
`--no-default-features` (no_std) for UEFI targets.

## Build & test

```sh
# Build the stage0 .efi (in the build container; vaportpm pulled from git)
make tools/build-stage0/x86_64/stage0.efi          # or aarch64

# Assemble + sign the bootable ESP disk (privileged: losetup/mount)
make tools/build-stage0/x86_64/boot.disk

# End-to-end under QEMU: builds + ed25519-signs the test payload, pins the
# release pubkey into user-data.stage0.json (signed mode), serves the payload
# and its .sig locally (via a DNS name, exercising EFI_DNS4), and boots stage0.
make test-stage0-x86_64

# Or boot an already-built disk, choosing what to boot:
./tools/qemu-test/boot.sh --kind stage0 --arch x86_64 \
    --payload tools/build-stage0/x86_64/payload.efi
./tools/qemu-test/boot.sh --help
```

Always include the arch suffix: `make boot-stage0` (no arch) is **not** a target
— it would be misread as a UKI build for an architecture literally named
"stage0".

The test payload (`crates/stage0-test-payload`) is a trivial chain-loaded UEFI
app that prints a banner and reads back PCR 14/15, confirming the
measure-then-execute path end to end.
