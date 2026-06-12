# 🔒🌩️ LockBoot

A secure two-stage boot system using the TPM (and AWS Nitro, if available) for verifiable system initialization. It provides a minimal UEFI linux image which downloads and performs a TPM-based verified execution:

- **Multi-Cloud**: Automatic configuration from AWS/GCP/Azure metadata (IMDSv2)
- **Verified Boot**: SHA256 validation with TPM PCR measurements (PCR 14: binary, PCR 15: config)
- **Attestation**: Pre-execution TPM attestation documents for remote verification
- **Multi-Architecture**: Native support for x86_64 and aarch64
- **Secure Boot**: UEFI Secure Boot signed and locked (DeployedMode=1)

## Quick Start

The `make` based build system will create a bootable disk image to be run by Qemu (with a vTPM) to simulate a generic 'secure cloud' environment:

```bash
make boot-x86_64 boot-aarch64
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

- **[stage0](crates/stage0/README.md)**: Kernel-less UEFI netboot loader (downloads + measures + chain-loads a UEFI payload)
- **[stage1](crates/stage1/README.md)**: Secure bootloader (fetches config, verifies binaries, extends PCRs)
- **[example-stage2](crates/example-stage2/README.md)**: Example user application
- **[vaportpm](https://github.com/lockboot/vaportpm)**: TPM 2.0 attestation library (external dependency)

## Cloud Deployment

Deploy the same config across AWS, GCP, or Azure. Publish scripts are provided in `tools/publish/`.

### AWS EC2

Requires Nitro v4+ instances with TPM 2.0 and UEFI boot support:

| Architecture | Tested Instance | Notes |
|---|---|---|
| x86_64 | `c6i.large` | Intel Xeon Gen 3, Nitro v4 |
| aarch64 | `c7g.medium` | Graviton 3, Nitro v4 |

```bash
tools/publish/ec2/create-ami.sh us-east-1 x86_64 local
```

### GCP Confidential VMs

Requires Confidential VM instances with Shielded VM and custom Secure Boot keys. Uses GVE network driver (virtio-net not available on Confidential VMs).

| Architecture | Tested Instance | Notes |
|---|---|---|
| x86_64 | `n2d-standard-2` | AMD SEV-SNP |

```bash
tools/publish/gcp/create-image.sh my-project x86_64 local
```

### Azure

```bash
az vm create --user-data "$(cat user-data.json | base64 -w0)" ...
```

## License

Licensed under Apache 2.0 or MIT at your option.
