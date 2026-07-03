// SPDX-License-Identifier: MIT OR Apache-2.0

//! ed25519 signature verification for "signed mode" stage2 payloads.
//!
//! Wire contract — must stay byte-identical to mkuki's signer and stage0's verifier
//! (github.com/lockboot/stage0, crates/stage0/src/sig.rs): message = raw payload bytes,
//! signature = detached 64 raw bytes, pinned key = base64 of the 32-byte public key.
//! Admission control only: neither the signature nor the key is ever measured.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ed25519_compact::{PublicKey, Signature};

/// Verify a detached ed25519 `signature` over `message` against the base64
/// `pubkey_b64` pinned in the metadata.
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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_compact::{KeyPair, Seed};

    #[test]
    fn sign_verify_roundtrip() {
        // Deterministic keypair from a fixed seed (no RNG needed).
        let kp = KeyPair::from_seed(Seed::new([7u8; 32]));
        let pubkey_b64 = STANDARD.encode(*kp.pk);
        let msg = b"stage2 payload bytes";
        let sig = kp.sk.sign(msg, None).to_vec();

        // Correct message + signature verifies.
        assert!(verify(&pubkey_b64, msg, &sig).is_ok());
        // Tampered message is rejected.
        assert!(verify(&pubkey_b64, b"tampered payload!!!!", &sig).is_err());
        // Tampered signature is rejected.
        let mut bad = sig.clone();
        bad[0] ^= 0x01;
        assert!(verify(&pubkey_b64, msg, &bad).is_err());
        // Wrong-length key / sig are rejected.
        assert!(verify("not-base64!!", msg, &sig).is_err());
        assert!(verify(&pubkey_b64, msg, &sig[..63]).is_err());
    }
}
