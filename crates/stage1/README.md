# stage1

A secure loader designed be exec'd after-setup by by `init` as **PID 1** as part of a Unified Kernel Image (UKI) initrd boot environment. The `stage1` executable fetches JSON config data from the cloud metadata service, then it downloads and verifies a stage2 binary, generates TPM attestations, then passed control to stage2. It establishes a chain of trust by:

1. **Fetching configuration** from cloud metadata services (AWS EC2, GCP, Azure)
2. **Downloading stage2 binary** from a specified URL
3. **Verifying SHA256 checksum** to ensure binary integrity
4. **Generating TPM attestation** before execution (captures PCR state)
5. **Extending TPM PCRs** 14 and 15 with measurements of the stage2 binary and configuration file
6. **Executing stage2** via `exec()`, replacing the PID 1 process

## Configuration Format

Stage1 expects a JSON configuration with a `_stage2` object containing architecture-specific configurations:

```json
{
  "_stage2": {
    "aarch64": {
      "url": "https://example.com/stage2-binary-arm64",
      "sha256": "abc123def456..."
    },
    "x86_64": {
      "url": "https://example.com/stage2-binary-amd64",
      "sha256": "def456abc123..."
    },
    "args": ["--flag", "value"]
  },
  "custom_field": "your-data-here"
}
```

### Architecture-Specific Fields

At least one architecture must be specified (`aarch64` or `x86_64`). Stage1 will automatically select the configuration matching its build architecture.

Each architecture configuration requires:
- **`url`** (string): HTTPS/HTTP URL to download the stage2 binary from
- **`sha256`** (string): Expected hex encoded SHA256 of the binary

### Optional Fields

- **`args`** (array of strings): Command-line arguments to pass to stage2 (applies to both architectures)

### Custom Fields

Any additional fields in the JSON are preserved, the raw file is written to `/tmp/stage2-config.json` for the stage2 binary to access.

## Usage Modes

### 1. Production (PID 1 / no arguments)

As PID 1 (or with no arguments), stage1 fetches its user-data JSON from the cloud metadata service, admits and measures the stage2 payload, attests the virgin state, then execs it. This is the normal boot path.

### 2. Config on stdin

A user-data document piped on stdin takes precedence over the metadata service - the Unix way, for local testing or bespoke delivery:

```bash
stage1 < user-data.json
cat user-data.json | stage1
```

stage1 only reads stdin when it is a pipe or a regular file, never the console, so PID 1 never blocks waiting for input. Deployment documents are produced by the separate `deploy` tool (`lockboot-deploy`), not by this binary.

### 3. Generate TPM Attestation

```bash
sudo stage1 --attest [challenge]
```

Requires root and access to `/dev/tpm0` to generate an attestation document containing:

- EK certificates and public key
- AK public key bound to all PCR values
- Signed quote with challenge
- Additional NitroTPM information

**Example:**
```bash
# Generate attestation with nonce
sudo stage1 --attest "challenge-from-verifier" > attestation.json

# Generate attestation without nonce
sudo stage1 --attest > attestation.json
```

The optional `challenge` can be used as a signing mechanism or as proof-of-liveness, by default it will use the current UTC UNIX integer timestamp.

## TPM Measurements

Before executing stage2, stage1 extends exactly one PCR:

| PCR | Purpose | Value Extended |
|-----|---------|----------------|
| **PCR 14** | Stage2 binary | SHA-256 of the stage2 code, and nothing else |

Measurement is **code-only**: the config, the admission pin/key, and the argv are *not* measured, so the platform quote is reproducible from the boot artifacts alone. PCR 15 is deliberately left untouched for a stage2 app to measure whatever config *it* deems trust-relevant. The stage2 payload runs from a sealed in-memory image (never a file on disk); it receives the raw user-data JSON on **stdin**, and the pre-execution attestation is written to `/tmp/stage1.attest`.

## Attestation Trust Model

The attestation is generated in the **virgin state** - before any user-provided code runs and before PCRs are extended. This ordering is critical, but it only provides security guarantees because the AK is a **restricted signing key**.

A restricted signing key can only sign digests that the TPM itself produces. When the AK signs a `TPM2_Quote`, the quote contains the actual PCR values at signing time - generated internally by the TPM, not by software. This means even if stage2 has access to the AK handle, it can only produce quotes reflecting the *current* PCR state (with stage2 already measured into PCR14). It cannot forge a quote showing virgin-state PCRs.

Without the restricted key constraint, the trust model collapses into tautology: stage2 could simply sign "I'm in virgin state" and the attestation would prove nothing.

The attestation uses `H(binary)` as the nonce - the SHA-256 of the stage2 code - binding the attestation to the specific intended workload. Config is deliberately not bound, matching the code-only PCR 14 measurement. Once this virgin-state attestation exists, any future use of the same AK inherits this trust anchor. A verifier can reason: "this AK was attested in a clean PCR state before this exact binary ran, therefore subsequent quotes from this AK come from a system that started from that trusted state."

The restricted signing constraint is imposed by cloud vTPMs (notably GCP), which limits the AK to operations like `TPM2_Quote`, `TPM2_Certify`, and `TPM2_CertifyCreation`. While this can feel limiting, it's precisely what makes the trust model sound.

## Building

From the repository root:

```bash
cargo build --release -p stage1
```

The binary will be output to `target/x86_64-unknown-linux-musl/release/stage1`.

## Cloud Setup Examples

Stage1 automatically detects and retrieves configuration from:

| Cloud Provider | Metadata Service | Encoding | Header Required |
|----------------|------------------|----------|-----------------|
| **AWS EC2** | IMDSv2 (token-based) | Plain text | Token auth |
| **GCP** | metadata.google.internal | Plain text | `Metadata-Flavor: Google` |
| **Azure** | IMDS | Base64 | `Metadata: true` |

The boot loader tries each provider in sequence and uses the first successful response.


### AWS EC2

Set user-data when launching an instance:

```bash
aws ec2 run-instances \
  --image-id ami-xxxxx \
  --instance-type c6i.xlarge \
  --user-data file://config.json
```

Stage1 will automatically fetch from IMDSv2.

### GCP

Set custom metadata with the `user-data` key:

```bash
gcloud compute instances create INSTANCE_NAME \
  --metadata user-data="$(cat config.json)"
```

**Or via Terraform:**
```hcl
resource "google_compute_instance" "vm" {
  metadata = {
    user-data = file("config.json")
  }
}
```

### Azure

Set user-data on the VM:

```bash
az vm create \
  --name INSTANCE_NAME \
  --resource-group RESOURCE_GROUP \
  --user-data "$(cat config.json | base64 -w0)"
```

Note: Azure requires base64-encoding when setting, but stage1 automatically decodes it.

## Example Workflow

### 1. Build stage2 binaries for both architectures
```bash
# Build for x86_64
cargo build --release --target x86_64-unknown-linux-musl -p example-stage2

# Build for aarch64
cargo build --release --target aarch64-unknown-linux-musl -p example-stage2
```

### 2. Upload to S3 (or any hosting)
```bash
aws s3 cp target/x86_64-unknown-linux-musl/release/example-stage2 \
  s3://mybucket/stage2-amd64

aws s3 cp target/aarch64-unknown-linux-musl/release/example-stage2 \
  s3://mybucket/stage2-arm64
```

### 3. Generate the deployment document
Use the `deploy` tool (`lockboot-deploy`) to hash (or sign) the payloads and emit a `user-data.json` carrying `_stage1` and `_stage2`; see the [repo README](../../README.md#deploy). stage1 does not generate config itself.

### 4. Test locally
```bash
stage1 < user-data.json
```

### 5. Deploy to cloud
```bash
# AWS: Set as user-data (works for both x86_64 and aarch64 instances)
aws ec2 run-instances --user-data file://config.json ...

# GCP: Set as metadata
gcloud compute instances create --metadata user-data="$(cat config.json)" ...

# Azure: Set as user-data (base64 encoded)
az vm create --user-data "$(cat config.json | base64 -w0)" ...
```

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
