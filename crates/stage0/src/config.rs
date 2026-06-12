// SPDX-License-Identifier: MIT OR Apache-2.0

//! The `_stage0` metadata schema.
//!
//! Mirrors `stage1`'s per-arch `{url, sha256}` structure (plus optional `args`)
//! but under a distinct `_stage0` key, so a UEFI payload is never confused with
//! a Linux `_stage2` binary in the same document.

use alloc::string::String;
use alloc::vec::Vec;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct UserData {
    #[serde(rename = "_stage0")]
    pub stage0: Stage0Config,
}

#[derive(Debug, Deserialize)]
pub struct Stage0Config {
    #[serde(default)]
    pub args: Option<Vec<String>>,
    // Exactly one of these is read per build (see `for_this_arch`); the other
    // is still deserialized so a single multi-arch document works everywhere.
    #[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
    #[serde(default)]
    pub aarch64: Option<ArchConfig>,
    #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
    #[serde(default)]
    pub x86_64: Option<ArchConfig>,
}

#[derive(Debug, Deserialize)]
pub struct ArchConfig {
    pub url: String,
    // Exactly one of these selects the verification mode (see `verify`):
    //   sha256  → pin an exact hash (immutable payload).
    //   ed25519 → pin a long-term release pubkey (base64); the payload may roll
    //             forward without editing metadata, gated by a detached `.sig`.
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub ed25519: Option<String>,
}

/// How stage0 admits the downloaded payload before measuring + loading it.
pub enum Verify {
    /// Payload's SHA-256 must equal this 64-hex string.
    Sha256(String),
    /// Detached ed25519 signature (`<url>.sig`) must verify against this
    /// base64-encoded 32-byte release public key.
    Ed25519(String),
}

impl Stage0Config {
    /// The config entry for the architecture stage0 was built for.
    #[must_use]
    pub fn for_this_arch(&self) -> Option<&ArchConfig> {
        #[cfg(target_arch = "x86_64")]
        {
            self.x86_64.as_ref()
        }
        #[cfg(target_arch = "aarch64")]
        {
            self.aarch64.as_ref()
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            None
        }
    }
}

impl ArchConfig {
    /// Validate the URL and the (single) verification field, returning the
    /// selected [`Verify`] mode.
    pub fn validate(&self) -> Result<Verify, &'static str> {
        if !(self.url.starts_with("http://") || self.url.starts_with("https://")) {
            return Err("url must start with http:// or https://");
        }
        if !self.url.chars().all(|c| c.is_ascii_graphic()) {
            return Err("url must contain only printable ASCII");
        }
        match (&self.sha256, &self.ed25519) {
            (Some(_), Some(_)) => Err("specify only one of sha256 / ed25519"),
            (None, None) => Err("must specify one of sha256 / ed25519"),
            (Some(hex), None) => {
                if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err("sha256 must be exactly 64 hex characters");
                }
                Ok(Verify::Sha256(hex.clone()))
            }
            (None, Some(pubkey)) => {
                // A raw ed25519 public key is 32 bytes.
                match STANDARD.decode(pubkey.trim()) {
                    Ok(bytes) if bytes.len() == 32 => Ok(Verify::Ed25519(pubkey.clone())),
                    Ok(_) => Err("ed25519 pubkey must decode to 32 bytes"),
                    Err(_) => Err("ed25519 pubkey must be base64"),
                }
            }
        }
    }
}

/// Parse the user-data JSON into a [`UserData`].
pub fn parse(json: &[u8]) -> Result<UserData, &'static str> {
    serde_json::from_slice(json).map_err(|_| "invalid JSON or missing _stage0 key")
}
