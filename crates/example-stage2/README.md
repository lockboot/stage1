# example-stage2

A simple demonstration binary for use as a stage2 payload in the LockBoot secure boot chain.

## Overview

This binary is designed to run as **PID 1** (the init process) after being downloaded, verified, and executed by `stage1`. It demonstrates how a stage2 payload can access configuration data and attestation information provided by the boot loader.

## What It Does

1. **Prints command-line arguments** - Shows any arguments passed from the stage1 configuration
2. **Displays stage2 configuration** - Reads and prints `/tmp/stage2-config.json` (the full user-data JSON provided to stage1)
3. **Shows attestation data** - Reads and prints `/tmp/stage1.attest` (the TPM attestation generated before execution)
4. **Waits for log capture** - Sleeps for 60 seconds to allow console logs to be captured
5. **Powers off the system** - Cleanly shuts down using `libc::reboot()`

## Why It Must Power Off

Since this binary runs as PID 1 (the init process), it **cannot simply exit**. If PID 1 exits, the Linux kernel will panic. Therefore, the binary must explicitly call `poweroff()` to shut down the system gracefully.

The `poweroff()` function checks if it's running as PID 1 before actually powering off, making it safe for testing:

```rust
fn poweroff() {
    let pid = std::process::id();
    if pid == 1 {
        unsafe {
            libc::sync();
            libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF);
        }
    } else {
        std::process::exit(1);
    }
}
```

## Building

From the repository root:

```bash
cargo build --release -p example-stage2
```

The binary will be output to `target/x86_64-unknown-linux-musl/release/example-stage2`.

## Example Deployment

A pre-built version of this binary is hosted at:
```
https://lockboot.s3.us-east-1.amazonaws.com/examples/stage2/example-stage2
```

### Configuration File

The corresponding stage1 metadata file is available at:
```
https://lockboot.s3.us-east-1.amazonaws.com/examples/stage2/user-data.example.json
```

This configuration was generated using:
```bash
stage1 --make-config https://lockboot.s3.us-east-1.amazonaws.com/examples/stage2/example-stage2
```

### Example Configuration Structure

```json
{
  "_stage2": {
    "url": "https://lockboot.s3.us-east-1.amazonaws.com/examples/stage2/example-stage2",
    "sha256": "abc123...",
    "args": ["--debug", "test"]
  }
}
```

## Usage with stage1

### Option 1: EC2 Metadata Service

Launch an EC2 instance with the configuration in the user-data field. The `stage1` binary (running as PID 1 in a UKI boot) will automatically:

1. Fetch the configuration from the EC2 metadata service
2. Download the stage2 binary from the specified URL
3. Verify the SHA256 checksum
4. Extend TPM PCRs 14 and 15 with measurements
5. Generate a TPM attestation document
6. Execute the stage2 binary (this example)

### Option 2: Manual Testing (config on stdin)

```bash
# Generate user-data.json with the `deploy` tool (lockboot-deploy), then pipe it in:
sudo stage1 < user-data.json
# or
curl -s https://lockboot.s3.us-east-1.amazonaws.com/examples/stage2/user-data.example.json | sudo stage1
```

## Expected Output

When executed, the binary will produce output similar to:

```
=== Arguments ===
arg[0]: /tmp/stage2.exe
arg[1]: --debug
arg[2]: test

=== /tmp/stage2-config.json ===
{
  "_stage2": {
    "url": "https://lockboot.s3.us-east-1.amazonaws.com/examples/stage2/example-stage2",
    "sha256": "...",
    "args": ["--debug", "test"]
  }
}

=== /tmp/stage1.attest ===
{
  "ek_cert": "...",
  "ak_pub": "...",
  "pcrs": {...},
  "quote": "...",
  "signature": "...",
  "nonce": "..."
}

=== Task complete, waiting 60 seconds for console log capture ===
=== Powering off ===
```

## Creating Your Own Stage2 Binary

This example serves as a template for creating custom stage2 payloads. Your binary should:

1. **Not exit** - Always power off or reboot instead of returning from main
2. **Read configuration** from `/tmp/stage2-config.json` if needed
3. **Access attestation** from `/tmp/stage1.attest` if verification is required
4. **Handle errors gracefully** - Log errors and power off on failure
5. **Flush output** - Ensure all stdout/stderr is flushed before powering off

### Minimal Stage2 Template

```rust
use std::io::{self, Write};

fn main() {
    // Your application logic here
    println!("Hello from stage2!");

    // Flush output
    let _ = io::stdout().flush();
    let _ = io::stderr().flush();

    // Must power off (we're PID 1)
    poweroff();
}

fn poweroff() {
    let pid = std::process::id();
    if pid == 1 {
        unsafe {
            libc::sync();
            libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF);
        }
    } else {
        std::process::exit(1);
    }
}
```

## Dependencies

- `libc` - For system calls (`sync`, `reboot`)

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.

## See Also

- [stage1](../stage1/) - The secure boot loader that executes this binary
- [vaportpm](https://github.com/lockboot/vaportpm) - TPM 2.0 library used for attestation
- [Root README](../../README.md) - Full project documentation
