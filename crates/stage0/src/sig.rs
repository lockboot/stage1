// SPDX-License-Identifier: MIT OR Apache-2.0

//! ed25519 admission control for "signed mode" payloads.
//!
//! In signed mode the metadata pins a long-term **release public key** (32-byte
//! ed25519, base64) instead of an exact SHA-256. The payload at the URL is
//! whatever the latest signed build is; stage0 fetches a detached signature
//! (`<url>.sig`, 64 raw bytes) and verifies it against the pinned key before
//! loading. This lets a release roll forward without editing VM metadata.
//!
//! The signature is *admission control only*: it is not measured, and the key
//! is not measured. The attestation surface stays minimal: PCR 14 records the
//! SHA-256 of whatever binary actually ran, full stop.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_compact::{PublicKey, Signature};

/// Verify a detached ed25519 `signature` over `message` against the base64
/// `pubkey_b64` pinned in the metadata. Verification is constant-work and needs
/// no allocator or RNG.
pub fn verify(pubkey_b64: &str, message: &[u8], signature: &[u8]) -> Result<(), &'static str> {
    let key_bytes = STANDARD
        .decode(pubkey_b64.trim())
        .map_err(|_| "ed25519 pubkey is not valid base64")?;
    let public_key =
        PublicKey::from_slice(&key_bytes).map_err(|_| "ed25519 pubkey wrong length")?;
    let signature =
        Signature::from_slice(signature).map_err(|_| "ed25519 signature wrong length")?;
    public_key
        .verify(message, &signature)
        .map_err(|_| "ed25519 signature verification failed")
}
