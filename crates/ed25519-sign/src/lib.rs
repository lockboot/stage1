// SPDX-License-Identifier: MIT OR Apache-2.0

//! ed25519 signing + sha256 — the cross-repo **wire contract** shared by `mkuki` and the
//! `deploy` tool. A signature this produces must verify byte-for-byte against stage0's and
//! stage1's admission check (github.com/lockboot/stage0, crates/stage0/src/sig.rs): the
//! signature is a detached 64-byte ed25519 over the raw payload bytes, and the pinned key
//! is the base64 of the 32-byte public key.

use anyhow::{ensure, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_compact::{KeyPair, PublicKey, Seed, Signature};
use sha2::{Digest, Sha256};

/// Verify a detached ed25519 `signature` over `message` against the base64 `pubkey_b64`
/// (32-byte public key). The verify counterpart of [`sign_payload`] — the on-instance
/// admission check (stage1) and any deploy-side self-check use this.
pub fn verify(pubkey_b64: &str, message: &[u8], signature: &[u8]) -> Result<(), &'static str> {
    let key_bytes = STANDARD
        .decode(pubkey_b64.trim())
        .map_err(|_| "ed25519 pubkey is not valid base64")?;
    let public_key = PublicKey::from_slice(&key_bytes).map_err(|_| "ed25519 pubkey wrong length")?;
    let signature = Signature::from_slice(signature).map_err(|_| "ed25519 signature wrong length")?;
    public_key
        .verify(message, &signature)
        .map_err(|_| "ed25519 signature verification failed")
}

pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut s = String::with_capacity(digest.len() * 2);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub struct Signed {
    /// 64-byte detached ed25519 signature over the payload.
    pub signature: Vec<u8>,
    /// base64 of the 32-byte public key — paste into an `ed25519` metadata field.
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

/// Extract the 32-byte Ed25519 seed from a PKCS#8 PEM private key (RFC 8410). openssl
/// `genpkey -algorithm ed25519` emits the 48-byte DER `... 04 22 04 20 <32-byte seed>`,
/// so we locate the inner OCTET STRING.
fn seed_from_pkcs8_pem(pem: &str) -> Result<[u8; 32]> {
    let b64: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .concat();
    let der = STANDARD
        .decode(b64.trim())
        .context("private key PEM body is not valid base64")?;

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

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a valid PKCS#8 (RFC 8410) ed25519 PEM from a raw seed — the exact DER
    /// `302e020100300506032b657004220420 <seed>` that `openssl genpkey` emits.
    fn pem_from_seed(seed: &[u8; 32]) -> String {
        let mut der: Vec<u8> = vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        der.extend_from_slice(seed);
        let b64 = STANDARD.encode(&der);
        format!("-----BEGIN PRIVATE KEY-----\n{b64}\n-----END PRIVATE KEY-----\n")
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let msg = b"payload bytes";
        let s = sign_payload(&pem_from_seed(&[7u8; 32]), msg).unwrap();
        // sign and verify are the two halves of the same wire contract, proven here together.
        assert!(verify(&s.pubkey_b64, msg, &s.signature).is_ok());
        assert!(verify(&s.pubkey_b64, b"tampered payload!!!!", &s.signature).is_err());
        let mut bad = s.signature.clone();
        bad[0] ^= 1;
        assert!(verify(&s.pubkey_b64, msg, &bad).is_err());
        assert!(verify("not-base64!!", msg, &s.signature).is_err());
    }

    #[test]
    fn sha256_hex_is_lowercase_64() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
