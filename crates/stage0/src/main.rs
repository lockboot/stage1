// SPDX-License-Identifier: MIT OR Apache-2.0

//! stage0 — a measured UEFI network bootloader for the lockboot stack.
//!
//! Boots as a pure UEFI application (no Linux kernel), pulls a `_stage0`
//! user-data document from the cloud metadata service, downloads a UEFI payload
//! over raw `EFI_TCP4` (see `tcp4.rs`), admits it via one of two policies —
//! a pinned SHA-256, or an ed25519 signature against a pinned release key
//! (`sig.rs`) — measures it into the TPM via `EFI_TCG2_PROTOCOL` (PCR 14 =
//! SHA-256 of the loaded binary), then chain-loads it.
//!
//! The payload is loaded through a temporary security-arch override (`secauth.rs`)
//! rather than relying on the firmware `db`, so the deployment is not forced to
//! Secure-Boot-sign every late-bound payload. The attestation surface is kept
//! deliberately small: the only thing measured is PCR 14 — "stage0 ran, and it
//! loaded a binary with this hash." The admission signature/key are not measured.

#![no_std]
#![no_main]

extern crate alloc;

mod config;
mod dns4;
mod http;
mod metadata;
mod secauth;
mod sig;
mod tcg2;
mod tcp4;

use alloc::string::String;
use config::Verify;
use sha2::{Digest, Sha256};
use uefi::boot;
use uefi::prelude::*;
use uefi::proto::loaded_image::LoadedImage;
use uefi::{println, CString16};

/// PCR extended with SHA-256 of the loaded payload (matches stage1's binary PCR).
const PCR_BINARY: u8 = 14;

#[entry]
fn main() -> Status {
    uefi::helpers::init().unwrap();
    match run() {
        Ok(()) => {
            println!("stage0: payload returned control to stage0 (unexpected)");
            Status::LOAD_ERROR
        }
        Err(status) => {
            println!("stage0: ERROR {:?}", status);
            // Pause so the failure is visible on the serial console.
            boot::stall(5_000_000);
            status
        }
    }
}

fn run() -> Result<(), Status> {
    println!("stage0: measured UEFI netboot starting");

    // Fetch metadata on its own HTTP instance, then drop it. Small metadata
    // bodies download fine over EFI_HTTP; the payload uses raw TCP4 below.
    let (url, verify, args) = {
        let mut client = http::HttpClient::new()?;
        println!("stage0: network configured");

        let json = metadata::fetch(&mut client)?;
        println!("stage0: fetched {} bytes of user-data", json.len());

        let user_data = config::parse(&json).map_err(|m| {
            println!("stage0: config error: {m}");
            Status::INVALID_PARAMETER
        })?;
        let arch = user_data.stage0.for_this_arch().ok_or_else(|| {
            println!("stage0: no _stage0 config for this architecture");
            Status::UNSUPPORTED
        })?;
        let verify = arch.validate().map_err(|m| {
            println!("stage0: invalid arch config: {m}");
            Status::INVALID_PARAMETER
        })?;
        (arch.url.clone(), verify, user_data.stage0.args.clone())
    };

    // The payload is downloaded over raw TCP4 (EFI_HTTP/HttpDxe won't drain a
    // multi-segment body here; see tcp4.rs). Metadata stays on EFI_HTTP above.
    println!("stage0: downloading payload from {url}");
    let binary = tcp4::download(&url)?;
    println!("stage0: downloaded {} bytes", binary.len());

    // Admission control. PCR 14 always records the SHA-256 of what we load; the
    // policy below only decides whether we are *allowed* to load it.
    let digest = sha256(&binary);
    match &verify {
        Verify::Sha256(expected) => {
            let actual = hex::encode(digest);
            if !actual.eq_ignore_ascii_case(expected) {
                println!("stage0: SHA256 mismatch! expected {expected}, got {actual}");
                return Err(Status::SECURITY_VIOLATION);
            }
            println!("stage0: SHA256 verified");
        }
        Verify::Ed25519(pubkey) => {
            // Detached signature lives alongside the payload at <url>.sig.
            let sig_url = alloc::format!("{url}.sig");
            println!("stage0: fetching signature from {sig_url}");
            let signature = tcp4::download(&sig_url)?;
            sig::verify(pubkey, &binary, &signature).map_err(|m| {
                println!("stage0: ed25519 verification failed: {m}");
                Status::SECURITY_VIOLATION
            })?;
            println!("stage0: ed25519 signature verified");
        }
    }

    // Measure before executing. Only PCR 14 (the binary): the config/key are not
    // measured, so attestation is simply "stage0 ran and loaded this hash".
    // Scoped so the TCG2 protocol is released before chain-loading: stage0 opens
    // it exclusively, and the payload needs to open it too (else ACCESS_DENIED).
    {
        let mut tpm = tcg2::open_tpm().map_err(|e| {
            println!("stage0: TPM unavailable: {e}");
            Status::DEVICE_ERROR
        })?;
        measure(&mut tpm, PCR_BINARY, &digest)?;
    }
    println!("stage0: extended PCR{PCR_BINARY} with the payload measurement");

    // Chain-load the measured payload from memory. The payload is admitted by
    // stage0's own policy above, not the firmware db, so load it through a
    // temporary security-arch override (see secauth.rs).
    let image = secauth::load_image_verified(&binary).inspect_err(|&status| {
        println!("stage0: load_image failed: {status:?}");
    })?;

    // Optionally pass args as UEFI load options; the backing buffer must stay
    // alive until after start_image.
    let _options = set_load_options(image, args.as_deref());

    println!("stage0: starting payload");
    boot::start_image(image).map_err(|e| e.status())?;

    Ok(())
}

/// Extend a PCR with `data` via the TCG2-backed TPM transport.
fn measure(tpm: &mut vaportpm_attest::Tpm, pcr: u8, data: &[u8]) -> Result<(), Status> {
    use vaportpm_attest::PcrOps;
    tpm.pcr_extend(pcr, data).map_err(|e| {
        println!("stage0: pcr_extend(PCR{pcr}) failed: {e}");
        Status::DEVICE_ERROR
    })
}

/// Set the loaded image's load options from `args` (UCS-2). Returns the backing
/// [`CString16`], which the caller must keep alive until `start_image`.
fn set_load_options(image: Handle, args: Option<&[String]>) -> Option<CString16> {
    let args = args?;
    if args.is_empty() {
        return None;
    }
    let options = CString16::try_from(args.join(" ").as_str()).ok()?;
    let mut loaded = boot::open_protocol_exclusive::<LoadedImage>(image).ok()?;
    unsafe {
        loaded.set_load_options(options.as_ptr().cast::<u8>(), options.num_bytes() as u32);
    }
    Some(options)
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}
