// SPDX-License-Identifier: MIT OR Apache-2.0

//! `mkuki` — assemble a kernel + container rootfs into a stage0-bootable Unified
//! Kernel Image, with no binutils/objcopy/ukify or systemd on the build host.
//!
//! This crate is both a CLI (`src/main.rs`) and a library. As a library it
//! exposes two layers:
//!
//!  - the low-level building blocks — [`cpio`] (reproducible newc writer),
//!    [`uki`] (in-process PE section grafting), and [`sign`] (ed25519/sha256
//!    matching stage0's admission check); and
//!  - the higher-level steps the CLI is itself built from — [`build_initramfs`]
//!    (ordered layers → `.initrd` + per-layer hashes), [`assemble`] (sections →
//!    UKI), [`generate_os_release`], and [`docker_export`].
//!
//! Logging: library functions emit [`tracing`] events and never install a
//! subscriber, so importers keep control of their own logging. The CLI installs
//! one in `main.rs`.

pub mod cpio;
pub mod sign;
pub mod uki;

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use tracing::{debug, info};

/// One initramfs layer's input: a directory tree, or the (already-decompressed)
/// bytes of a tar such as `docker export` output.
pub enum LayerSource {
    Dir(PathBuf),
    Tar(Vec<u8>),
}

impl LayerSource {
    /// Resolve a path to a source: a directory as-is, or a tar file (transparently
    /// gunzipped if gzipped — the same sniff used for `--rootfs`/`--layer` input).
    pub fn from_path(path: &Path) -> Result<LayerSource> {
        if path.is_dir() {
            return Ok(LayerSource::Dir(path.to_path_buf()));
        }
        let raw = std::fs::read(path)
            .with_context(|| format!("reading layer {}", path.display()))?;
        if raw.starts_with(&[0x1f, 0x8b]) {
            let mut dec = flate2::read::GzDecoder::new(&raw[..]);
            let mut tar = Vec::new();
            dec.read_to_end(&mut tar)?;
            Ok(LayerSource::Tar(tar))
        } else {
            Ok(LayerSource::Tar(raw))
        }
    }
}

/// A named initramfs layer. The `label` is display/metadata only (it appears in
/// the per-layer hash output and the generated os-release `BUILD_ID`); layer
/// *order* is significant — later layers overlay earlier ones at unpack time.
pub struct Layer {
    pub label: String,
    pub source: LayerSource,
}

impl Layer {
    pub fn new(label: impl Into<String>, source: LayerSource) -> Self {
        Layer { label: label.into(), source }
    }

    /// Build a layer from a path, deriving the label from the file name (up to the
    /// first `.`, e.g. `layers/platform` -> "platform", `userland.cpio.gz` ->
    /// "userland").
    pub fn from_path(path: &Path) -> Result<Self> {
        Ok(Layer::new(layer_label(path), LayerSource::from_path(path)?))
    }
}

/// The assembled initramfs: the concatenated `.initrd` bytes plus the per-layer
/// sha256 hashes (label, hex) in layer order.
pub struct Initramfs {
    pub data: Vec<u8>,
    pub layer_hashes: Vec<(String, String)>,
}

/// Build the `.initrd` from ordered `layers`. Each layer becomes its own
/// reproducible, independently-gzipped cpio (each emits its own `TRAILER!!!`, so
/// layers concatenate cleanly) and the kernel unpacks the concatenation as one
/// rootfs — the early-microcode pattern — with later layers overlaying earlier
/// ones.
pub fn build_initramfs(layers: &[Layer]) -> Result<Initramfs> {
    info!(layers = layers.len(), "building initramfs");
    let mut data: Vec<u8> = Vec::new();
    let mut layer_hashes: Vec<(String, String)> = Vec::with_capacity(layers.len());
    for layer in layers {
        let gz = build_layer(&layer.source)?;
        let sha = sign::sha256_hex(&gz);
        debug!(label = %layer.label, %sha, bytes = gz.len(), "layer built");
        layer_hashes.push((layer.label.clone(), sha));
        data.extend_from_slice(&gz);
    }
    Ok(Initramfs { data, layer_hashes })
}

/// The sections that make up a UKI, as already-read bytes. Slices are borrowed so
/// callers can assemble without extra copies.
pub struct UkiSpec<'a> {
    /// systemd-boot stub PE to graft sections onto.
    pub stub: &'a [u8],
    /// Kernel image (`.linux`).
    pub kernel: &'a [u8],
    /// Concatenated initramfs (`.initrd`).
    pub initrd: &'a [u8],
    /// os-release contents (`.osrel`).
    pub os_release: &'a [u8],
    /// Kernel command line (`.cmdline`), immutable at boot.
    pub cmdline: &'a [u8],
    /// Optional kernel version string (`.uname`, display only).
    pub uname: Option<&'a str>,
}

/// Assemble a UKI from `spec`, grafting the sections onto the stub in the fixed
/// ascending-VMA order (`.osrel`, `.cmdline`, optional `.uname`, `.linux`,
/// `.initrd`). Returns the new PE bytes.
pub fn assemble(spec: &UkiSpec) -> Result<Vec<u8>> {
    info!("assembling UKI");
    let mut sections = vec![
        uki::Section { name: ".osrel", data: spec.os_release },
        uki::Section { name: ".cmdline", data: spec.cmdline },
    ];
    if let Some(u) = spec.uname {
        sections.push(uki::Section { name: ".uname", data: u.as_bytes() });
    }
    sections.push(uki::Section { name: ".linux", data: spec.kernel });
    sections.push(uki::Section { name: ".initrd", data: spec.initrd });
    uki::build(spec.stub, &sections)
}

/// Build one layer into an independently-gzipped, reproducible newc cpio archive.
fn build_layer(src: &LayerSource) -> Result<Vec<u8>> {
    let mut b = cpio::CpioBuilder::new();
    match src {
        LayerSource::Dir(p) => b.add_dir(p)?,
        LayerSource::Tar(bytes) => b.add_tar(&bytes[..])?,
    }
    cpio::gzip(&b.finish()?)
}

/// Short, stable label for a layer from its path: the file name up to the first
/// `.`, falling back to "layer".
fn layer_label(p: &Path) -> String {
    p.file_name()
        .map(|s| s.to_string_lossy().split('.').next().unwrap_or("layer").to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "layer".to_string())
}

/// `docker create` + `docker export` a flat rootfs tar, then clean up. `engine`
/// is the container binary (e.g. `docker`, `podman`).
pub fn docker_export(engine: &str, image: &str) -> Result<Vec<u8>> {
    info!(%image, %engine, "exporting rootfs from container image");
    let create = Command::new(engine)
        .args(["create", image])
        .output()
        .with_context(|| format!("running `{engine} create`"))?;
    if !create.status.success() {
        bail!("`{engine} create {image}` failed: {}", String::from_utf8_lossy(&create.stderr));
    }
    let cid = String::from_utf8(create.stdout)?.trim().to_string();

    let export = Command::new(engine)
        .args(["export", &cid])
        .output()
        .with_context(|| format!("running `{engine} export`"))?;

    // Best-effort cleanup regardless of export result.
    let _ = Command::new(engine).args(["rm", "-f", &cid]).output();

    if !export.status.success() {
        bail!("`{engine} export {cid}` failed: {}", String::from_utf8_lossy(&export.stderr));
    }
    Ok(export.stdout)
}

/// Minimal os-release with a BUILD_ID derived from the component hashes, so a
/// rebuild from identical inputs is traceable (mirrors build.sh). The layer
/// hashes already pin the initrd: the `.initrd` section is the deterministic
/// concatenation of those layers, so we describe it from them rather than
/// re-hashing the concatenation.
pub fn generate_os_release(
    id: &str,
    kernel: &[u8],
    cmdline: &[u8],
    layer_hashes: &[(String, String)],
) -> String {
    let short_d = |d: &[u8]| sign::sha256_hex(d)[..8].to_string();
    // Single source (--rootfs/--from-docker): the lone layer hash IS the initrd
    // hash, so emit `.initrd-<h>` — byte-identical to the pre-layering format.
    // Multiple layers: record each individually for independent verifiability.
    let initrd: String = if layer_hashes.len() == 1 {
        format!(".initrd-{}", &layer_hashes[0].1[..8])
    } else {
        layer_hashes
            .iter()
            .map(|(label, h)| format!(".{label}-{}", &h[..8]))
            .collect()
    };
    let build_id = format!(
        "krnl-{}.args-{}{}",
        short_d(kernel),
        short_d(cmdline),
        initrd,
    );
    format!(
        "ID={id}\nNAME=\"{id}\"\nPRETTY_NAME=\"{id}\"\nBUILD_ID={build_id}\n"
    )
}
