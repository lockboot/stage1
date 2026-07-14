// SPDX-License-Identifier: MIT OR Apache-2.0

//! `mkuki` — turn a kernel + container rootfs into a stage0-bootable Unified
//! Kernel Image, with no binutils/objcopy/ukify or systemd on the build host.
//!
//! This is the command-line front end: it parses arguments, installs the tracing
//! subscriber, and drives the [`mkuki`] library, which holds all the assembly
//! logic so it can also be reused directly. It assembles a systemd-boot-stub UKI
//! in-process, optionally signs it with the ed25519 release key stage0 admits
//! with, and prints the UKI/layer hashes. The resulting `.efi` is a plain UEFI
//! payload — nothing in it depends on stage1.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::Parser;
use tracing::info;
use tracing_subscriber::{filter::LevelFilter, EnvFilter};

use mkuki::{
    assemble, build_initramfs, docker_export, generate_os_release, sign, Layer, LayerSource,
    UkiSpec,
};

/// Build a stage0-bootable UKI from a kernel + container rootfs.
#[derive(Parser, Debug)]
#[command(name = "mkuki", version, about, long_about = None)]
struct Args {
    /// Kernel image to embed (.linux), e.g. a specific vmlinuz.
    #[arg(long, value_name = "vmlinuz")]
    kernel: PathBuf,

    /// systemd-boot stub PE to graft sections onto (.efi).
    #[arg(long, value_name = "stub.efi")]
    stub: PathBuf,

    /// Root filesystem for the initramfs: a directory, or a (optionally gzipped)
    /// tar such as `docker export` output. Mutually exclusive with --from-docker.
    #[arg(long, value_name = "dir|tar")]
    rootfs: Option<PathBuf>,

    /// Container image to export as the rootfs (runs `docker create`+`export`).
    /// Use --docker to point at podman/nerdctl instead.
    #[arg(long, value_name = "image", conflicts_with = "rootfs")]
    from_docker: Option<String>,

    /// Container engine binary for --from-docker.
    #[arg(long, default_value = "docker")]
    docker: String,

    /// Initramfs layer (dir or tar), repeatable; order is significant (the first
    /// --layer is the first concatenated cpio). Use instead of --rootfs/--from-docker
    /// for layered assembly, e.g. `--layer platform --layer userland`. The kernel
    /// concatenates the independently-gzipped layers at unpack time.
    #[arg(long = "layer", value_name = "dir|tar", conflicts_with_all = ["rootfs", "from_docker"])]
    layers: Vec<PathBuf>,

    /// Kernel command line baked into the UKI (.cmdline). Immutable at boot.
    #[arg(long, default_value = "")]
    cmdline: String,

    /// Kernel version string for the .uname section (optional, display only).
    #[arg(long)]
    uname: Option<String>,

    /// os-release file to embed (.osrel). If omitted, a minimal one is generated.
    #[arg(long, value_name = "file")]
    os_release: Option<PathBuf>,

    /// ID= for the generated os-release (when --os-release is not given).
    #[arg(long, default_value = "diy")]
    id: String,

    /// Output UKI path (.efi).
    #[arg(long, value_name = "linux.efi")]
    out: PathBuf,

    /// PKCS#8 ed25519 private key (PEM) to sign the UKI. Writes <out>.sig.
    #[arg(long, value_name = "release.pem")]
    sign_key: Option<PathBuf>,

    /// Target architecture, used only to label the printed _stage1 snippet.
    #[arg(long, default_value = "x86_64")]
    arch: String,

    /// Increase log verbosity: -v for debug, -vv for trace. Overridden by RUST_LOG.
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Silence everything below errors. Overridden by RUST_LOG.
    #[arg(short, long, conflicts_with = "verbose")]
    quiet: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    init_tracing(args.verbose, args.quiet);

    // Resolve the ordered list of initramfs layers. Either explicit --layer inputs
    // (layered assembly), or a single implicit layer from --rootfs/--from-docker
    // (back-compat: byte-identical to the pre-layering output, so the lone layer
    // keeps the label "rootfs" regardless of the input path).
    let layers = resolve_layers(&args)?;

    // --- initramfs (.initrd) ---
    let initrd = build_initramfs(&layers)?;

    // --- kernel (.linux) ---
    let kernel = std::fs::read(&args.kernel)
        .with_context(|| format!("reading kernel {}", args.kernel.display()))?;

    // --- os-release (.osrel) ---
    let osrel = match &args.os_release {
        Some(p) => std::fs::read(p).with_context(|| format!("reading {}", p.display()))?,
        None => generate_os_release(
            &args.id,
            &kernel,
            args.cmdline.as_bytes(),
            &initrd.layer_hashes,
        )
        .into_bytes(),
    };

    // --- assemble UKI ---
    let stub = std::fs::read(&args.stub)
        .with_context(|| format!("reading stub {}", args.stub.display()))?;
    let image = assemble(&UkiSpec {
        stub: &stub,
        kernel: &kernel,
        initrd: &initrd.data,
        os_release: &osrel,
        cmdline: args.cmdline.as_bytes(),
        uname: args.uname.as_deref(),
    })?;
    std::fs::write(&args.out, &image)
        .with_context(|| format!("writing UKI {}", args.out.display()))?;
    info!(path = %args.out.display(), bytes = image.len(), "wrote UKI");

    // --- admission material ---
    let sha = sign::sha256_hex(&image);
    if let Some(key_path) = &args.sign_key {
        let pem = std::fs::read_to_string(key_path)
            .with_context(|| format!("reading signing key {}", key_path.display()))?;
        let s = sign::sign(&pem, sign::Domain::Stage1Uki, &image)?;
        let sig_path = sig_path(&args.out);
        std::fs::write(&sig_path, &s.signature)
            .with_context(|| format!("writing {}", sig_path.display()))?;
        info!(path = %sig_path.display(), "wrote detached ed25519 signature (64 bytes)");
    }

    // Machine-readable result on stdout — logging goes to stderr, so this stays
    // clean for scripts that capture the hashes.
    println!("\nsha256: {sha}");
    for (label, h) in &initrd.layer_hashes {
        println!("layer {label}: {h}");
    }
    Ok(())
}

/// Resolve the CLI's rootfs flags into the ordered layer list the library builds.
fn resolve_layers(args: &Args) -> Result<Vec<Layer>> {
    if !args.layers.is_empty() {
        args.layers.iter().map(|p| Layer::from_path(p)).collect()
    } else if let Some(image) = &args.from_docker {
        let tar = docker_export(&args.docker, image)?;
        Ok(vec![Layer::new("rootfs", LayerSource::Tar(tar))])
    } else if let Some(rootfs) = &args.rootfs {
        // Force the label "rootfs" (not the path-derived one) so the single-layer
        // os-release stays byte-identical to the pre-layering output.
        Ok(vec![Layer::new("rootfs", LayerSource::from_path(rootfs)?)])
    } else {
        bail!(
            "provide --layer <dir|tar> (repeatable), --rootfs <dir|tar>, or --from-docker <image>"
        );
    }
}

/// Install the tracing subscriber: events go to stderr (stdout stays reserved for
/// the machine-readable hash output). `RUST_LOG` wins when set; otherwise the
/// level comes from `-v`/`-q`.
fn init_tracing(verbose: u8, quiet: bool) {
    let default = if quiet {
        LevelFilter::ERROR
    } else {
        match verbose {
            0 => LevelFilter::INFO,
            1 => LevelFilter::DEBUG,
            _ => LevelFilter::TRACE,
        }
    };
    let filter = EnvFilter::builder()
        .with_default_directive(default.into())
        .from_env_lossy();
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .with_writer(std::io::stderr)
        .init();
}

/// `<out>.sig` — where stage0 expects the detached signature.
fn sig_path(out: &Path) -> PathBuf {
    let mut s = out.as_os_str().to_os_string();
    s.push(".sig");
    PathBuf::from(s)
}
