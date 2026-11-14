// SPDX-License-Identifier: MIT OR Apache-2.0

//! The boot disk's GPT digests, for the attestation.
//!
//! The firmware measures the boot disk's GPT (`EV_EFI_GPT_EVENT`, PCR5; PCR2 on GCE TDX), and
//! stage2 rewrites that GPT, so a verifier needs the digests to replay the PCR. They are read
//! from the disk here rather than from the firmware event log, which not every platform hands
//! to Linux intact.
//!
//! Identifying the disk duplicates stage2's `blockdev::find_boot_device()` rules (keep them in
//! step): a disk carrying the lockboot data partition, else the one disk with an EFI System
//! Partition; zero or several candidates is an error.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use vaportpm_attest::gpt::uefi_gpt_data_device;
use vaportpm_attest::GptDigests;

/// EFI System Partition type GUID c12a7328-f81f-11d2-ba4b-00a0c93ec93b, in on-disk byte order.
const ESP_TYPE: [u8; 16] = [
    0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b,
];
/// stage2's data partition type GUID 1c8f6b2d-af5e-4d3b-9c4f-2b3c4d5e6f70, in on-disk byte order.
const DATA_TYPE: [u8; 16] = [
    0x2d, 0x6b, 0x8f, 0x1c, 0x5e, 0xaf, 0x3b, 0x4d, 0x9c, 0x4f, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70,
];

/// GPT digests of the boot disk.
pub fn gpt_digests() -> Result<GptDigests> {
    let (dev, data) = find_boot_disk()?;
    eprintln!(
        "stage1: boot disk {} ({} bytes of UEFI_GPT_DATA)",
        dev.display(),
        data.len()
    );
    Ok(GptDigests::of(&data))
}

/// The boot disk and its `UEFI_GPT_DATA`.
fn find_boot_disk() -> Result<(PathBuf, Vec<u8>)> {
    let mut data_disks = Vec::new();
    let mut esp_disks = Vec::new();
    for dev in whole_disks()? {
        let Ok(gpt) = uefi_gpt_data_device(&dev) else {
            continue;
        };
        let types = partition_types(&gpt);
        if types.contains(&DATA_TYPE) {
            data_disks.push((dev, gpt));
        } else if types.contains(&ESP_TYPE) {
            esp_disks.push((dev, gpt));
        }
    }
    match data_disks.len() {
        1 => return Ok(data_disks.remove(0)),
        0 => {}
        n => bail!("{n} disks carry the lockboot data partition -- refusing to guess"),
    }
    match esp_disks.len() {
        1 => Ok(esp_disks.remove(0)),
        0 => bail!("no lockboot boot disk found (no data partition, no ESP)"),
        n => bail!("{n} disks have an ESP -- cannot identify the boot disk"),
    }
}

/// The type GUIDs of the entries in a `UEFI_GPT_DATA` (header, UINT64 count, entries).
fn partition_types(gpt: &[u8]) -> Vec<[u8; 16]> {
    let size = u32::from_le_bytes(gpt[84..88].try_into().unwrap()) as usize;
    gpt[100..]
        .chunks_exact(size)
        .map(|e| e[..16].try_into().unwrap())
        .collect()
}

/// Whole disks under /sys/block, less the kinds that are never the boot disk.
fn whole_disks() -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir("/sys/block").context("read /sys/block")? {
        let name = entry?.file_name();
        let n = name.to_string_lossy();
        if ["loop", "ram", "sr", "dm-", "md", "zram", "fd", "nbd"]
            .iter()
            .any(|p| n.starts_with(p))
        {
            continue;
        }
        out.push(Path::new("/dev").join(&*n));
    }
    Ok(out)
}
