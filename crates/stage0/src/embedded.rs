// SPDX-License-Identifier: MIT OR Apache-2.0

//! Optional `_stage1` metadata embedded in stage0's own PE image.
//!
//! A deployer can bake a `_stage1` document into stage0 as a PE section named
//! [`SECTION`], then `db`-sign the result into a single `netboot.efi`. The section
//! is part of the signed, firmware-measured PE, so the key, URL and args it
//! carries are fixed at signing time, and no metadata service is contacted.
//! When present it is used in place of the cloud metadata fetch.
//!
//! The section must be loaded into the image (mapped at its virtual address with
//! `SizeOfImage` covering it). If embedding leaves it unmapped, [`metadata`]
//! simply returns `None` and stage0 falls back to the metadata service.

use alloc::vec::Vec;

use uefi::boot;
use uefi::proto::loaded_image::LoadedImage;

/// PE section name carrying the embedded `_stage1` JSON (8 bytes, NUL-padded).
const SECTION: &[u8; 8] = b".stage0\0";

/// The embedded `_stage1` document, or `None` if stage0's PE carries no
/// [`SECTION`]. Every read is bounds-checked against the loaded image size; any
/// malformation yields `None` (the caller then falls back to the metadata fetch).
pub fn metadata() -> Option<Vec<u8>> {
    let loaded = boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle()).ok()?;
    let (base, size) = loaded.info();
    if base.is_null() || size == 0 {
        return None;
    }
    // SAFETY: `base..base+size` is stage0's own loaded image (mapped, initialized,
    // readable). The slice is read-only and every access below goes through
    // bounds-checked `get`, so nothing dereferences out of range.
    let img = unsafe { core::slice::from_raw_parts(base as *const u8, size as usize) };

    let (off, len) = find_section(img, SECTION)?;
    let raw = img.get(off..off.checked_add(len)?)?;
    // Drop section zero/whitespace padding so the JSON parses cleanly.
    let end = raw
        .iter()
        .rposition(|&b| b != 0 && !b.is_ascii_whitespace())
        .map_or(0, |i| i + 1);
    (end != 0).then(|| raw[..end].to_vec())
}

/// Locate a named section in a loaded PE image, returning `(offset-from-base,
/// virtual-size)` of its in-memory data. Fully bounds-checked; `None` on any
/// malformation or if the section's mapped range exceeds the image.
fn find_section(img: &[u8], name: &[u8; 8]) -> Option<(usize, usize)> {
    let rd_u16 = |o: usize| Some(u16::from_le_bytes([*img.get(o)?, *img.get(o + 1)?]));
    let rd_u32 = |o: usize| {
        Some(u32::from_le_bytes([
            *img.get(o)?,
            *img.get(o + 1)?,
            *img.get(o + 2)?,
            *img.get(o + 3)?,
        ]))
    };

    if img.get(0..2)? != b"MZ" {
        return None;
    }
    let pe = rd_u32(0x3c)? as usize;
    if img.get(pe..pe.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }
    let coff = pe + 4;
    let num_sections = rd_u16(coff + 2)? as usize;
    let opt_size = rd_u16(coff + 16)? as usize;
    let mut sh = coff.checked_add(20)?.checked_add(opt_size)?; // section table start

    for _ in 0..num_sections {
        let hdr = img.get(sh..sh.checked_add(40)?)?; // sizeof(IMAGE_SECTION_HEADER)
        if &hdr[..8] == name.as_slice() {
            let vsize = rd_u32(sh + 8)? as usize; // VirtualSize
            let vaddr = rd_u32(sh + 12)? as usize; // VirtualAddress = offset in loaded image
            if vaddr >= img.len() {
                return None;
            }
            return Some((vaddr, vsize.min(img.len() - vaddr)));
        }
        sh += 40;
    }
    None
}
