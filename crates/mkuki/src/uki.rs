// SPDX-License-Identifier: MIT OR Apache-2.0

//! Append UKI sections (`.osrel`, `.cmdline`, `.uname`, `.linux`, `.initrd`) to
//! a systemd-boot stub PE, in-process — the native equivalent of the
//! `objcopy --add-section ... --change-section-vma ...` dance in
//! `tools/build-uki/build.sh`, with no binutils/ukify dependency.
//!
//! VMAs are computed dynamically by walking the stub's existing sections and
//! appending after the last one (the v256 stubs use high VMAs; see the project
//! notes), matching ukify's placement so the same stub works across systemd
//! versions.

use anyhow::{bail, ensure, Result};

const SECTION_HEADER_SIZE: usize = 40;
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;

/// One section to graft onto the stub. Order is preserved and determines the
/// ascending VMA layout.
pub struct Section<'a> {
    pub name: &'a str,
    pub data: &'a [u8],
}

struct PeView {
    pe_off: usize,     // offset of "PE\0\0"
    opt_off: usize,    // offset of the optional header
    sect_table: usize, // offset of the first section header
    num_sections: usize,
    section_align: u32,
    file_align: u32,
    size_of_headers: u32,
}

fn rd_u16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}
fn rd_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
fn wr_u16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn wr_u32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn align_up(x: u64, a: u64) -> u64 {
    debug_assert!(a.is_power_of_two());
    (x + a - 1) & !(a - 1)
}

impl PeView {
    fn parse(b: &[u8]) -> Result<PeView> {
        ensure!(b.len() > 0x40 && &b[0..2] == b"MZ", "not a PE/MZ image");
        let pe_off = rd_u32(b, 0x3c) as usize;
        ensure!(
            pe_off + 24 <= b.len() && &b[pe_off..pe_off + 4] == b"PE\0\0",
            "bad PE signature"
        );
        let coff = pe_off + 4;
        let num_sections = rd_u16(b, coff + 2) as usize;
        let size_opt = rd_u16(b, coff + 16) as usize;
        let opt_off = coff + 20;
        // PE32+ (0x20b) is what UEFI images use; the field offsets below assume it.
        let magic = rd_u16(b, opt_off);
        ensure!(
            magic == 0x20b,
            "expected PE32+ image (magic 0x20b), got {magic:#x}"
        );
        let section_align = rd_u32(b, opt_off + 32);
        let file_align = rd_u32(b, opt_off + 36);
        let size_of_headers = rd_u32(b, opt_off + 60);
        let sect_table = opt_off + size_opt;
        ensure!(
            sect_table + num_sections * SECTION_HEADER_SIZE <= b.len(),
            "section table out of bounds"
        );
        Ok(PeView {
            pe_off,
            opt_off,
            sect_table,
            num_sections,
            section_align,
            file_align,
            size_of_headers,
        })
    }
}

/// Build a UKI by appending `sections` to `stub`. Returns the new PE bytes.
pub fn build(stub: &[u8], sections: &[Section]) -> Result<Vec<u8>> {
    let pe = PeView::parse(stub)?;

    // Highest VMA end across existing sections — where ours begin.
    let mut max_va_end: u64 = 0;
    let mut min_raw_ptr: u64 = u64::MAX;
    for i in 0..pe.num_sections {
        let sh = pe.sect_table + i * SECTION_HEADER_SIZE;
        let vsize = rd_u32(stub, sh + 8) as u64;
        let vaddr = rd_u32(stub, sh + 12) as u64;
        let rsize = rd_u32(stub, sh + 16) as u64;
        let rptr = rd_u32(stub, sh + 20) as u64;
        max_va_end = max_va_end.max(vaddr + vsize.max(rsize));
        if rptr > 0 {
            min_raw_ptr = min_raw_ptr.min(rptr);
        }
    }

    // The new section headers must fit in the existing header padding, before
    // the first section's raw data. systemd stubs leave room; if a future stub
    // does not, fail loudly rather than silently corrupting the image.
    let new_headers_end = pe.sect_table + (pe.num_sections + sections.len()) * SECTION_HEADER_SIZE;
    let header_ceiling = (pe.size_of_headers as u64).min(min_raw_ptr) as usize;
    ensure!(
        new_headers_end <= header_ceiling,
        "no room for {} new section headers (need {} bytes, header area ends at {}); \
         the stub has too little header padding",
        sections.len(),
        new_headers_end,
        header_ceiling
    );

    let mut out = stub.to_vec();
    let file_align = pe.file_align as u64;
    let section_align = pe.section_align as u64;

    let mut vma = align_up(max_va_end, section_align);
    let mut headers: Vec<[u8; SECTION_HEADER_SIZE]> = Vec::with_capacity(sections.len());

    for s in sections {
        let name_bytes = s.name.as_bytes();
        ensure!(
            name_bytes.len() <= 8,
            "section name {:?} exceeds 8 bytes",
            s.name
        );

        // Append raw data at an aligned file offset.
        let raw_ptr = align_up(out.len() as u64, file_align);
        out.resize(raw_ptr as usize, 0);
        out.extend_from_slice(s.data);
        let raw_size = align_up(s.data.len() as u64, file_align);
        out.resize((raw_ptr + raw_size) as usize, 0);

        let mut sh = [0u8; SECTION_HEADER_SIZE];
        sh[..name_bytes.len()].copy_from_slice(name_bytes);
        wr_u32(&mut sh, 8, s.data.len() as u32); // VirtualSize
        wr_u32(&mut sh, 12, vma as u32); // VirtualAddress
        wr_u32(&mut sh, 16, raw_size as u32); // SizeOfRawData
        wr_u32(&mut sh, 20, raw_ptr as u32); // PointerToRawData
                                             // PointerToRelocations/Linenumbers + counts stay 0.
        wr_u32(
            &mut sh,
            36,
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
        );
        headers.push(sh);

        vma = align_up(vma + s.data.len() as u64, section_align);
    }

    // Write the new headers into the table and bump the section count.
    for (i, sh) in headers.iter().enumerate() {
        let off = pe.sect_table + (pe.num_sections + i) * SECTION_HEADER_SIZE;
        out[off..off + SECTION_HEADER_SIZE].copy_from_slice(sh);
    }
    let new_count = pe.num_sections + sections.len();
    ensure!(new_count <= u16::MAX as usize, "too many sections");
    wr_u16(&mut out, pe.pe_off + 4 + 2, new_count as u16);

    // SizeOfImage = end of the last section's VMA span, aligned.
    wr_u32(&mut out, pe.opt_off + 56, vma as u32);

    // UEFI ignores the optional-header CheckSum for loading, and we are not
    // Authenticode-signing here (stage0 admits by ed25519/sha256, not `db`).
    // Zero it so no stale/incorrect value is left behind; sbsign would recompute
    // it anyway if this UKI were ever also signed for firmware-direct boot.
    wr_u32(&mut out, pe.opt_off + 64, 0);

    if out.len() > u32::MAX as usize {
        bail!("resulting UKI exceeds 4 GiB");
    }
    Ok(out)
}
