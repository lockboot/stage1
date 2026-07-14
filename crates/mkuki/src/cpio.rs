// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reproducible newc ("070701") cpio writer for the `.initrd` section.
//!
//! Entries are buffered, sorted bytewise by path, and stamped with sequential
//! inodes and `mtime = 0` so the same rootfs always yields byte-identical
//! output (and therefore a stable PCR 14 measurement once wrapped in the UKI).

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::Path;

use anyhow::{bail, Context, Result};
use walkdir::WalkDir;

// st_mode type bits.
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;
const S_IFCHR: u32 = 0o020000;
const S_IFBLK: u32 = 0o060000;
const S_IFIFO: u32 = 0o010000;

struct Entry {
    /// Normalized archive path (no leading `/` or `./`).
    name: String,
    mode: u32,
    nlink: u32,
    rdevmajor: u32,
    rdevminor: u32,
    /// File contents, or the target for a symlink; empty otherwise.
    data: Vec<u8>,
}

/// Accumulates entries and renders a deterministic newc archive.
#[derive(Default)]
pub struct CpioBuilder {
    // Keyed by name so duplicates (later layers winning) collapse and ordering
    // is bytewise-sorted for free.
    entries: BTreeMap<String, Entry>,
}

impl CpioBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingest a flat root filesystem from a directory tree.
    pub fn add_dir(&mut self, root: &Path) -> Result<()> {
        use std::os::unix::fs::FileTypeExt;
        use std::os::unix::fs::MetadataExt;

        for dent in WalkDir::new(root).min_depth(1).sort_by_file_name() {
            let dent = dent?;
            let rel = dent.path().strip_prefix(root)?;
            let name = match normalize(&rel.to_string_lossy()) {
                Some(n) => n,
                None => continue,
            };
            let md = dent.path().symlink_metadata()?;
            let perms = md.mode() & 0o7777;
            let ft = md.file_type();

            let entry = if ft.is_symlink() {
                let target = std::fs::read_link(dent.path())?;
                Entry::new(
                    name,
                    S_IFLNK | 0o777,
                    1,
                    target.to_string_lossy().as_bytes().to_vec(),
                )
            } else if ft.is_dir() {
                Entry::new(name, S_IFDIR | perms, 2, Vec::new())
            } else if ft.is_file() {
                let data = std::fs::read(dent.path())?;
                Entry::new(name, S_IFREG | perms, 1, data)
            } else if ft.is_char_device() {
                Entry::dev(name, S_IFCHR | perms, md.rdev())
            } else if ft.is_block_device() {
                Entry::dev(name, S_IFBLK | perms, md.rdev())
            } else if ft.is_fifo() {
                Entry::new(name, S_IFIFO | perms, 1, Vec::new())
            } else {
                // Sockets and anything else have no place in an initramfs.
                continue;
            };
            self.insert(entry);
        }
        Ok(())
    }

    /// Ingest a flat root filesystem from a tar stream (e.g. `docker export`).
    pub fn add_tar<R: Read>(&mut self, reader: R) -> Result<()> {
        use tar::EntryType;

        let mut ar = tar::Archive::new(reader);
        // Remember regular-file contents so hardlink entries (which carry no
        // data) can be materialized as copies.
        let mut file_data: BTreeMap<String, Vec<u8>> = BTreeMap::new();

        for entry in ar.entries().context("reading tar entries")? {
            let mut e = entry?;
            let header = e.header().clone();
            let path = e.path()?.to_string_lossy().into_owned();
            let name = match normalize(&path) {
                Some(n) => n,
                None => continue,
            };
            let perms = header.mode()? & 0o7777;

            let built = match header.entry_type() {
                EntryType::Directory => Entry::new(name.clone(), S_IFDIR | perms, 2, Vec::new()),
                EntryType::Symlink => {
                    let target = header
                        .link_name()?
                        .context("symlink without target")?
                        .to_string_lossy()
                        .into_owned();
                    Entry::new(name.clone(), S_IFLNK | 0o777, 1, target.into_bytes())
                }
                EntryType::Link => {
                    // Hardlink: copy the data of the already-seen target.
                    let target = header
                        .link_name()?
                        .context("hardlink without target")?
                        .to_string_lossy()
                        .into_owned();
                    let tgt = normalize(&target).unwrap_or(target);
                    let data = file_data.get(&tgt).cloned().unwrap_or_default();
                    Entry::new(name.clone(), S_IFREG | perms, 1, data)
                }
                EntryType::Char => Entry::dev_split(
                    name.clone(),
                    S_IFCHR | perms,
                    header.device_major()?.unwrap_or(0),
                    header.device_minor()?.unwrap_or(0),
                ),
                EntryType::Block => Entry::dev_split(
                    name.clone(),
                    S_IFBLK | perms,
                    header.device_major()?.unwrap_or(0),
                    header.device_minor()?.unwrap_or(0),
                ),
                EntryType::Fifo => Entry::new(name.clone(), S_IFIFO | perms, 1, Vec::new()),
                EntryType::Regular | EntryType::Continuous => {
                    let mut data = Vec::new();
                    e.read_to_end(&mut data)?;
                    file_data.insert(name.clone(), data.clone());
                    Entry::new(name.clone(), S_IFREG | perms, 1, data)
                }
                // PAX/GNU metadata entries are consumed by the tar crate; ignore
                // any other exotic types.
                _ => continue,
            };
            self.insert(built);
        }
        Ok(())
    }

    fn insert(&mut self, e: Entry) {
        self.entries.insert(e.name.clone(), e);
    }

    /// Render the archive bytes (uncompressed).
    pub fn finish(&self) -> Result<Vec<u8>> {
        if self.entries.is_empty() {
            bail!("rootfs produced no cpio entries");
        }
        let mut out = Vec::new();
        // ino 0 is reserved by convention; start at 1.
        for (ino, entry) in self.entries.values().enumerate() {
            entry.write(&mut out, ino as u32 + 1)?;
        }
        write_trailer(&mut out)?;
        Ok(out)
    }
}

impl Entry {
    fn new(name: String, mode: u32, nlink: u32, data: Vec<u8>) -> Self {
        Entry {
            name,
            mode,
            nlink,
            rdevmajor: 0,
            rdevminor: 0,
            data,
        }
    }

    fn dev(name: String, mode: u32, rdev: u64) -> Self {
        // Linux dev_t encoding (glibc gnu_dev_major/minor).
        let major = (((rdev >> 8) & 0xfff) | ((rdev >> 32) & !0xfffu64)) as u32;
        let minor = ((rdev & 0xff) | ((rdev >> 12) & !0xffu64)) as u32;
        Entry {
            name,
            mode,
            nlink: 1,
            rdevmajor: major,
            rdevminor: minor,
            data: Vec::new(),
        }
    }

    fn dev_split(name: String, mode: u32, major: u32, minor: u32) -> Self {
        Entry {
            name,
            mode,
            nlink: 1,
            rdevmajor: major,
            rdevminor: minor,
            data: Vec::new(),
        }
    }

    fn write(&self, out: &mut Vec<u8>, ino: u32) -> Result<()> {
        let namesize = self.name.len() as u32 + 1; // includes trailing NUL
        let filesize = self.data.len() as u32;

        out.extend_from_slice(b"070701");
        for field in [
            ino,
            self.mode,
            0, // uid: normalize to root for reproducibility
            0, // gid
            self.nlink,
            0, // mtime: zeroed for reproducibility
            filesize,
            0, // devmajor (the containing fs; irrelevant for initramfs)
            0, // devminor
            self.rdevmajor,
            self.rdevminor,
            namesize,
            0, // check (unused for newc)
        ] {
            write_hex8(out, field);
        }
        out.extend_from_slice(self.name.as_bytes());
        out.push(0);
        pad4(out); // header(110) + name is aligned to 4

        out.extend_from_slice(&self.data);
        pad4(out);
        Ok(())
    }
}

fn write_trailer(out: &mut Vec<u8>) -> Result<()> {
    let name = b"TRAILER!!!";
    out.extend_from_slice(b"070701");
    for field in [0u32, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, name.len() as u32 + 1, 0] {
        write_hex8(out, field);
    }
    out.extend_from_slice(name);
    out.push(0);
    pad4(out);
    Ok(())
}

fn write_hex8(out: &mut Vec<u8>, v: u32) {
    // Lowercase 8-digit hex; the kernel's newc parser is case-insensitive.
    out.extend_from_slice(format!("{v:08x}").as_bytes());
}

fn pad4(out: &mut Vec<u8>) {
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

/// Strip leading `/` and `./`, collapse to a clean relative path; `None` for the
/// root entry (which the kernel does not need).
fn normalize(path: &str) -> Option<String> {
    let p = path.trim_start_matches("./").trim_start_matches('/');
    let p = p.trim_end_matches('/');
    if p.is_empty() || p == "." {
        None
    } else {
        Some(p.to_string())
    }
}

/// Gzip with a zeroed header (no mtime, no filename) for reproducibility.
pub fn gzip(data: &[u8]) -> Result<Vec<u8>> {
    use flate2::{Compression, GzBuilder};
    let mut buf = Vec::new();
    {
        let mut enc = GzBuilder::new()
            .mtime(0)
            .write(&mut buf, Compression::best());
        enc.write_all(data)?;
        enc.finish()?;
    }
    Ok(buf)
}
