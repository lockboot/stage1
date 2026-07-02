// SPDX-License-Identifier: MIT OR Apache-2.0

//! ed25519 signing + sha256, matching stage0's admission check
//! (github.com/lockboot/stage0, crates/stage0/src/sig.rs): the signature is a
//! detached 64-byte ed25519 over the raw payload bytes, the pinned key is the
//! base64 of the 32-byte public key. This MUST stay byte-compatible with what
//! stage0 verifies — the two are a cross-repo wire contract, not a shared crate.

use anyhow::{ensure, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_compact::{KeyPair, Seed};
use sha2::{Digest, Sha256};

pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    hex(&digest)
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub struct Signed {
    /// 64-byte detached ed25519 signature over the payload.
    pub signature: Vec<u8>,
    /// base64 of the 32-byte public key — paste into `_stage1`'s `ed25519`.
    pub pubkey_b64: String,
}

/// Sign `payload` with the PKCS#8 (PEM) ed25519 private key at `pem`.
pub fn sign_payload(pem: &str, payload: &[u8]) -> Result<Signed> {
    let seed = seed_from_pkcs8_pem(pem)?;
    let kp = KeyPair::from_seed(Seed::new(seed));
    let signature = kp.sk.sign(payload, None);
    Ok(Signed {
        signature: signature.to_vec(),
        pubkey_b64: STANDARD.encode(*kp.pk),
    })
}

/// Extract the 32-byte Ed25519 seed from a PKCS#8 PEM private key
/// (RFC 8410). openssl `genpkey -algorithm ed25519` emits the 48-byte DER:
/// `... 04 22 04 20 <32-byte seed>`, so we locate the inner OCTET STRING.
fn seed_from_pkcs8_pem(pem: &str) -> Result<[u8; 32]> {
    let b64: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .concat();
    let der = STANDARD
        .decode(b64.trim())
        .context("private key PEM body is not valid base64")?;

    // Find the `04 22 04 20` wrapper (CurvePrivateKey OCTET STRING containing a
    // 32-byte OCTET STRING) and take the 32 bytes that follow it.
    let marker = [0x04u8, 0x22, 0x04, 0x20];
    if let Some(pos) = der.windows(4).position(|w| w == marker) {
        let start = pos + 4;
        ensure!(start + 32 <= der.len(), "truncated ed25519 private key");
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&der[start..start + 32]);
        return Ok(seed);
    }
    anyhow::bail!("not a PKCS#8 Ed25519 private key (expected 04 22 04 20 marker)")
}
