# 🔒🌩️ LockBoot

A secure two-stage boot system using the TPM (and AWS Nitro, if available) for verifiable system initialization. It provides a minimal UEFI linux image which downloads and performs a TPM-based verified execution:

- **Multi-Cloud**: Automatic configuration from AWS/GCP/Azure metadata (IMDSv2)
- **Verified Boot**: SHA256 validation with TPM PCR measurements (PCR 14: binary, PCR 15: config)
- **Attestation**: Pre-execution TPM attestation documents for remote verification
- **Multi-Architecture**: Native support for x86_64 and aarch64
- **Secure Boot**: UEFI Secure Boot signed and locked (DeployedMode=1)

## Quick Start

This repo builds the netboot **UKI** (`linux.efi`) that [stage0](https://github.com/lockboot/stage0) fetches, verifies, measures into PCR 14, and chain-loads. Build it with:

```bash
make x86_64            # -> tools/build-uki/x86_64/linux.efi
```

To exercise the whole chain under QEMU (stage0 → UKI → stage1 → example-stage2), stage0 is the harness — build its boot disk in the sibling repo, then run the chain test (borrows `../stage0/build/<arch>/boot.disk` and the shared `lockboot:harness` image):

```bash
(cd ../stage0 && make build-x86_64)   # the external stage0 boot apparatus
make test-chain-x86_64                # sha256 admission (default)
make test-chain-x86_64 SIGN=1         # ed25519 signed-manifest admission
```

## Configuration Format

```json
{
  "_stage2": {
    "x86_64": {
      "url": "https://example.com/stage2-amd64",
      "sha256": "abc123..."
    },
    "aarch64": {
      "url": "https://example.com/stage2-arm64",
      "sha256": "def456..."
    },
    "args": ["--flag", "value"]
  }
}
```

You can run any statically linked Linux ELF, but the minimal filesystem only has `/bin/{busybox,bwrap,stage1}` and `/tmp`

## Components

- **[stage0](https://github.com/lockboot/stage0)**: Kernel-less UEFI netboot loader (downloads + measures + chain-loads a UEFI payload) — its own repo; this repo's UKI is the payload it netboots
- **[stage1](crates/stage1/README.md)**: Secure bootloader (fetches config, verifies binaries, extends PCRs)
- **[example-stage2](crates/example-stage2/README.md)**: Example user application
- **[vaportpm](https://github.com/lockboot/vaportpm)**: TPM 2.0 attestation library (external dependency)

## Cloud Deployment

Two independent artifacts are published on two tracks:

- **The bootable cloud image (the stage0 Secure Boot root)** is built and published from the [stage0 repo](https://github.com/lockboot/stage0) (its `tools/publish/` bakes the AMI/GCP image from the `stage0-v*` release). That is the firmware-admitted root of trust and is not this repo's concern.
- **The netboot UKI (this repo)** is just a file served over HTTP(S): stage0 downloads it, verifies the pinned `sha256` (or `ed25519` signature), measures it into PCR 14, and chain-loads it. Publish it and print the matching `_stage1` block with:

```bash
tools/publish.sh s3://bucket/prefix x86_64 local   # or gs://bucket/prefix
```

The instance's user-data carries the `_stage1` doc pointing at wherever you uploaded `linux.efi` (see [Configuration Format](#configuration-format)).

## License

Licensed under Apache 2.0 or MIT at your option.
