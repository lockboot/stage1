// SPDX-License-Identifier: MIT OR Apache-2.0

//! ed25519 signing + sha256 — the cross-repo **wire contract** shared by `mkuki`, the `deploy`
//! tool, and the stage0/stage1 admission checks. Signatures are **domain-separated**: the ed25519
//! signature is over a fixed 64-byte preimage `sha256(domain_tag) || sha256(message)`, so a
//! signature minted for one role (e.g. a `_stage2` manifest) is structurally invalid in any other
//! (a payload, a different hop, ...). The pinned key is the base64 of the 32-byte public key.
//!
//! A signature this produces must verify byte-for-byte against stage0's copy
//! (github.com/lockboot/stage0, crates/stage0/src/sig.rs) for the shared `stage1.*` domains — see
//! the golden known-answer test below.

use anyhow::{ensure, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_compact::{KeyPair, PublicKey, Seed, Signature};
use sha2::{Digest, Sha256};

/// A signing context. The `tag()` string is the domain-separation namespace mixed into every
/// signature so a signature is only ever valid for its exact (hop, kind). Wire constants — do not
/// change without bumping the `v1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Domain {
    /// `_stage1` payload (the UKI), admitted by stage0.
    Stage1Uki,
    /// `_stage1` LoadOptions (signed args), admitted by stage0.
    Stage1Args,
    /// `_stage1` signed manifest, resolved by stage0.
    Stage1Manifest,
    /// `_stage2` payload, admitted by stage1.
    Stage2Payload,
    /// `_stage2` args, admitted by stage1.
    Stage2Args,
    /// `_stage2` signed manifest, resolved by stage1.
    Stage2Manifest,
}

impl Domain {
    /// The namespace string mixed into the signature preimage.
    #[must_use]
    pub fn tag(self) -> &'static str {
        match self {
            Domain::Stage1Uki => "lockboot.v1.stage1.uki",
            Domain::Stage1Args => "lockboot.v1.stage1.args",
            Domain::Stage1Manifest => "lockboot.v1.stage1.manifest",
            Domain::Stage2Payload => "lockboot.v1.stage2.payload",
            Domain::Stage2Args => "lockboot.v1.stage2.args",
            Domain::Stage2Manifest => "lockboot.v1.stage2.manifest",
        }
    }
}

impl core::str::FromStr for Domain {
    type Err = &'static str;
    /// Parse the short CLI form (`stage2.manifest`); the `lockboot.v1.` prefix is implicit.
    fn from_str(s: &str) -> core::result::Result<Self, Self::Err> {
        Ok(match s {
            "stage1.uki" => Domain::Stage1Uki,
            "stage1.args" => Domain::Stage1Args,
            "stage1.manifest" => Domain::Stage1Manifest,
            "stage2.payload" => Domain::Stage2Payload,
            "stage2.args" => Domain::Stage2Args,
            "stage2.manifest" => Domain::Stage2Manifest,
            _ => return Err("unknown signing domain"),
        })
    }
}

/// The 64-byte signed preimage: `sha256(domain_tag) || sha256(message)`. Hash-then-sign, fixed
/// length regardless of `message` size. For a payload the second half equals the content digest
/// that admission computes on download and pins in sha256 mode.
fn preimage(domain: Domain, message: &[u8]) -> [u8; 64] {
    let dom: [u8; 32] = Sha256::digest(domain.tag().as_bytes()).into();
    let msg: [u8; 32] = Sha256::digest(message).into();
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&dom);
    out[32..].copy_from_slice(&msg);
    out
}

/// Verify a detached ed25519 `signature` for `domain` over `message` against the base64
/// `pubkey_b64` (32-byte public key). Pass the raw `message` (e.g. downloaded bytes); this hashes
/// it. The verify counterpart of [`sign`] — the on-instance admission checks use this.
pub fn verify(
    pubkey_b64: &str,
    domain: Domain,
    message: &[u8],
    signature: &[u8],
) -> Result<(), &'static str> {
    let key_bytes = STANDARD
        .decode(pubkey_b64.trim())
        .map_err(|_| "ed25519 pubkey is not valid base64")?;
    let public_key = PublicKey::from_slice(&key_bytes).map_err(|_| "ed25519 pubkey wrong length")?;
    let signature = Signature::from_slice(signature).map_err(|_| "ed25519 signature wrong length")?;
    public_key
        .verify(preimage(domain, message), &signature)
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
    /// 64-byte detached ed25519 signature over the domain-separated preimage.
    pub signature: Vec<u8>,
    /// base64 of the 32-byte public key — paste into an `ed25519` metadata field.
    pub pubkey_b64: String,
}

/// Sign `message` for `domain` with the PKCS#8 (PEM) ed25519 private key at `pem`.
pub fn sign(pem: &str, domain: Domain, message: &[u8]) -> Result<Signed> {
    let seed = seed_from_pkcs8_pem(pem)?;
    let kp = KeyPair::from_seed(Seed::new(seed));
    let signature = kp.sk.sign(preimage(domain, message), None);
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

/// Build a valid PKCS#8 (RFC 8410) ed25519 PEM from a raw seed — the exact DER
/// `302e020100300506032b657004220420 <seed>` that `openssl genpkey` emits, and the inverse of
/// [`seed_from_pkcs8_pem`]. Used by `deploy keygen` (with a random seed) and the tests.
#[must_use]
pub fn pem_from_seed(seed: &[u8; 32]) -> String {
    let mut der: Vec<u8> = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    der.extend_from_slice(seed);
    let b64 = STANDARD.encode(&der);
    format!("-----BEGIN PRIVATE KEY-----\n{b64}\n-----END PRIVATE KEY-----\n")
}

/// The base64 32-byte public key for a raw seed — the value pinned in an `ed25519` metadata field.
#[must_use]
pub fn pubkey_b64_from_seed(seed: &[u8; 32]) -> String {
    STANDARD.encode(*KeyPair::from_seed(Seed::new(*seed)).pk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_then_verify_roundtrip() {
        let msg = b"payload bytes";
        let s = sign(&pem_from_seed(&[7u8; 32]), Domain::Stage2Payload, msg).unwrap();
        assert!(verify(&s.pubkey_b64, Domain::Stage2Payload, msg, &s.signature).is_ok());
        assert!(verify(&s.pubkey_b64, Domain::Stage2Payload, b"tampered!!!!!", &s.signature).is_err());
        let mut bad = s.signature.clone();
        bad[0] ^= 1;
        assert!(verify(&s.pubkey_b64, Domain::Stage2Payload, msg, &bad).is_err());
        assert!(verify("not-base64!!", Domain::Stage2Payload, msg, &s.signature).is_err());
    }

    #[test]
    fn domain_separation_rejects_cross_use() {
        // Same key, same bytes, different domain -> must not verify.
        let msg = b"identical bytes";
        let s = sign(&pem_from_seed(&[7u8; 32]), Domain::Stage2Manifest, msg).unwrap();
        assert!(verify(&s.pubkey_b64, Domain::Stage2Manifest, msg, &s.signature).is_ok());
        assert!(verify(&s.pubkey_b64, Domain::Stage1Manifest, msg, &s.signature).is_err());
        assert!(verify(&s.pubkey_b64, Domain::Stage2Payload, msg, &s.signature).is_err());
    }

    /// Cross-repo wire-contract anchor: this exact (key, domain, message) -> signature must also
    /// hold in stage0's verifier (github.com/lockboot/stage0). If either repo's framing drifts,
    /// this fails. Values are base64.
    #[test]
    fn golden_kat() {
        let s = sign(&pem_from_seed(&[7u8; 32]), Domain::Stage1Manifest, b"lockboot-kat").unwrap();
        assert_eq!(s.pubkey_b64, "6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=");
        assert_eq!(
            STANDARD.encode(&s.signature),
            "nVZgjXp9d4zjnj9axtTQALlMADGqGKPTnR6RjMr8h8nI3wNpsBy0M4ZBjVfjlLKRZTN0pH3AAsGJqU0tJRTQDA=="
        );
        assert!(verify(&s.pubkey_b64, Domain::Stage1Manifest, b"lockboot-kat", &s.signature).is_ok());
    }

    #[test]
    fn sha256_hex_is_lowercase_64() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
