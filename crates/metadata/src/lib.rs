// SPDX-License-Identifier: MIT OR Apache-2.0

//! Lock.Boot admission metadata -- the `_stage1` / `_stage2` wire types + validation.
//!
//! Shared by the stage1 **verifier** (deserialize + `validate` + `Verify`) and the deploy
//! **emitter** (construct + serialize), so the format has one definition and can't drift.
//! `_stage1` (stage0, the UKI hop) and `_stage2` (stage1, the payload hop) have the same shape;
//! they differ only in transport policy, captured by [`Profile`] -- stage0 is http-only (no TLS),
//! stage1 allows https.
//!
//! Two admission modes per arch entry:
//!   - **sha256** -- pin an exact hash inline (`url` + `sha256`; static payload).
//!   - **ed25519** -- pin a release pubkey + a `manifest_url`. The stage fetches a signed
//!     **manifest** (`{ url, sha256, args, version }`), verifies it against the pinned key, then
//!     admits the payload by the manifest's exact `sha256`. Binding the payload + args under one
//!     signature stops a hostile mirror from mixing-and-matching independently-signed pieces or
//!     swapping the payload, while the release rolls forward by re-signing a new manifest.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A full user-data document. stage1 reads `_stage2`; a deployment carries both.
#[derive(Debug, Serialize, Deserialize)]
pub struct UserData {
    #[serde(rename = "_stage1", default, skip_serializing_if = "Option::is_none")]
    pub stage1: Option<StageConfig>,
    #[serde(rename = "_stage2", default, skip_serializing_if = "Option::is_none")]
    pub stage2: Option<StageConfig>,
}

/// One stage's config: an optional inline `args` (sha256 mode) plus a per-architecture entry.
#[derive(Debug, Serialize, Deserialize)]
pub struct StageConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aarch64: Option<ArchConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x86_64: Option<ArchConfig>,
}

impl StageConfig {
    /// The entry for the architecture this crate was compiled for (used at runtime).
    #[must_use]
    pub fn for_this_arch(&self) -> Option<&ArchConfig> {
        #[cfg(target_arch = "aarch64")]
        {
            self.aarch64.as_ref()
        }
        #[cfg(target_arch = "x86_64")]
        {
            self.x86_64.as_ref()
        }
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        {
            None
        }
    }
}

/// One URL or a fallback list, tried in order. Deserializes from a string or an array, and
/// serializes back to a bare string when singular. Trying mirrors is safe: the payload is
/// cryptographically pinned, so bytes from any URL must still verify.
#[derive(Debug, Clone)]
pub struct UrlList(pub Vec<String>);

impl<'de> Deserialize<'de> for UrlList {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum OneOrMany {
            One(String),
            Many(Vec<String>),
        }
        Ok(match OneOrMany::deserialize(d)? {
            OneOrMany::One(s) => UrlList(vec![s]),
            OneOrMany::Many(v) => UrlList(v),
        })
    }
}

impl Serialize for UrlList {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self.0.as_slice() {
            [one] => one.serialize(s),
            many => many.serialize(s),
        }
    }
}

/// One architecture's admission entry. Exactly one of `sha256` (static, inline `url`+`sha256`)
/// or `ed25519` (roll-forward via a signed manifest at `manifest_url`) selects the mode -- see
/// [`ArchConfig::validate`].
#[derive(Debug, Serialize, Deserialize)]
pub struct ArchConfig {
    /// sha256 mode: the payload URL(s). Unused in ed25519 mode (the manifest carries it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<UrlList>,
    /// sha256 mode: the payload's exact 64-hex digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// ed25519 mode: base64 32-byte release pubkey.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ed25519: Option<String>,
    /// ed25519 mode: where the signed manifest is fetched from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_url: Option<UrlList>,
    /// ed25519 mode: manifest signature location; `{sha256}` -> the retrieved manifest's digest.
    /// Defaults to `<manifest_url>.sig`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_sig_url: Option<UrlList>,
}

/// The signed release manifest (ed25519 mode). Fetched from `manifest_url`, verified against the
/// pinned release key; the payload is then admitted by its `sha256`. The verifier also merges the
/// manifest back into the `_stage2` entry before handing the doc to the payload on stdin.
#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
    /// Payload URL(s) (mirror list). `{sha256}` is replaced with `sha256` below.
    pub url: UrlList,
    /// The payload's exact 64-hex digest.
    pub sha256: String,
    /// Args passed to the payload as argv (stage1) or LoadOptions (stage0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,
    /// Monotonic release version (anti-rollback hint; enforcement is future work).
    #[serde(default)]
    pub version: u64,
}

/// Transport policy per stage: stage0 (the UKI hop) has no TLS, stage1 (the payload hop) does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// `_stage1` -- http:// only.
    Stage0,
    /// `_stage2` -- http:// or https://.
    Stage1,
}

/// Resolved admission mode. `manifest_sig_url` still carries a raw `{sha256}`; the consumer
/// substitutes the retrieved manifest's digest.
pub enum Verify {
    Sha256(String),
    Ed25519 {
        pubkey: String,
        manifest_url: UrlList,
        manifest_sig_url: Option<UrlList>,
    },
}

fn ok_url(s: &str, allow_https: bool) -> bool {
    (s.starts_with("http://") || (allow_https && s.starts_with("https://")))
        && s.chars().all(|c| c.is_ascii_graphic())
}
fn ok_list(l: &UrlList, allow_https: bool) -> bool {
    !l.0.is_empty() && l.0.iter().all(|s| ok_url(s, allow_https))
}
fn ok_sha256(hex: &str) -> bool {
    hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit())
}

impl Manifest {
    /// Parse + validate a fetched manifest (called after its signature is verified).
    pub fn parse(json: &[u8], profile: Profile) -> Result<Manifest, &'static str> {
        let m: Manifest =
            serde_json::from_slice(json).map_err(|_| "manifest is not valid JSON")?;
        let allow_https = matches!(profile, Profile::Stage1);
        if !ok_list(&m.url, allow_https) {
            return Err("manifest url must be a non-empty http(s):// URL (or list), printable ASCII");
        }
        if !ok_sha256(&m.sha256) {
            return Err("manifest sha256 must be exactly 64 hex characters");
        }
        Ok(m)
    }
}

impl ArchConfig {
    /// Validate the arch entry and return the selected [`Verify`] mode. `profile` chooses the
    /// transport policy (see [`Profile`]).
    pub fn validate(&self, profile: Profile) -> Result<Verify, &'static str> {
        let allow_https = matches!(profile, Profile::Stage1);
        if self.manifest_url.as_ref().is_some_and(|l| !ok_list(l, allow_https)) {
            return Err("manifest_url must be http(s):// URL(s), printable ASCII");
        }
        if self.manifest_sig_url.as_ref().is_some_and(|l| !ok_list(l, allow_https)) {
            return Err("manifest_sig_url must be http(s):// URL(s), printable ASCII");
        }
        if self.manifest_sig_url.is_some() && self.manifest_url.is_none() {
            return Err("manifest_sig_url requires manifest_url");
        }
        match (&self.sha256, &self.ed25519) {
            (Some(_), Some(_)) => Err("specify only one of sha256 / ed25519"),
            (None, None) => Err("must specify one of sha256 / ed25519"),
            (Some(hex), None) => {
                if self.manifest_url.is_some() {
                    return Err("manifest_url requires ed25519 signed mode");
                }
                let url = self.url.as_ref().ok_or("sha256 mode requires url")?;
                if !ok_list(url, allow_https) {
                    return Err("url must be a non-empty http(s):// URL (or list), printable ASCII");
                }
                if !ok_sha256(hex) {
                    return Err("sha256 must be exactly 64 hex characters");
                }
                Ok(Verify::Sha256(hex.clone()))
            }
            (None, Some(pubkey)) => {
                let manifest_url = self
                    .manifest_url
                    .clone()
                    .ok_or("ed25519 mode requires manifest_url")?;
                match STANDARD.decode(pubkey.trim()) {
                    Ok(bytes) if bytes.len() == 32 => Ok(Verify::Ed25519 {
                        pubkey: pubkey.clone(),
                        manifest_url,
                        manifest_sig_url: self.manifest_sig_url.clone(),
                    }),
                    Ok(_) => Err("ed25519 pubkey must decode to 32 bytes"),
                    Err(_) => Err("ed25519 pubkey must be base64"),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn pubkey_b64() -> String {
        // base64 of a valid 32-byte ed25519 public key (from a fixed seed).
        use ed25519_compact::{KeyPair, Seed};
        STANDARD.encode(*KeyPair::from_seed(Seed::new([3u8; 32])).pk)
    }

    /// A minimal sha256-mode entry.
    fn sha256_entry(url: &str, sha256: &str) -> ArchConfig {
        ArchConfig {
            url: Some(UrlList(vec![url.into()])),
            sha256: Some(sha256.into()),
            ed25519: None,
            manifest_url: None,
            manifest_sig_url: None,
        }
    }

    /// A minimal ed25519-mode entry.
    fn ed25519_entry(pubkey: &str, manifest_url: &str) -> ArchConfig {
        ArchConfig {
            url: None,
            sha256: None,
            ed25519: Some(pubkey.into()),
            manifest_url: Some(UrlList(vec![manifest_url.into()])),
            manifest_sig_url: None,
        }
    }

    #[test]
    fn sha256_mode_ok() {
        assert!(matches!(
            sha256_entry("http://h/p", HASH64).validate(Profile::Stage1),
            Ok(Verify::Sha256(_))
        ));
    }

    #[test]
    fn ed25519_mode_ok() {
        let pk = pubkey_b64();
        assert!(matches!(
            ed25519_entry(&pk, "http://h/m.json").validate(Profile::Stage1),
            Ok(Verify::Ed25519 { .. })
        ));
    }

    #[test]
    fn https_allowed_on_stage1_only() {
        assert!(sha256_entry("https://h/p", HASH64).validate(Profile::Stage1).is_ok());
        assert!(sha256_entry("https://h/p", HASH64).validate(Profile::Stage0).is_err());
        let pk = pubkey_b64();
        assert!(ed25519_entry(&pk, "https://h/m.json").validate(Profile::Stage1).is_ok());
        assert!(ed25519_entry(&pk, "https://h/m.json").validate(Profile::Stage0).is_err());
    }

    #[test]
    fn ed25519_requires_manifest_url() {
        let pk = pubkey_b64();
        let mut c = ed25519_entry(&pk, "http://h/m.json");
        c.manifest_url = None;
        assert!(c.validate(Profile::Stage1).is_err());
    }

    #[test]
    fn manifest_url_requires_ed25519() {
        let mut c = sha256_entry("http://h/p", HASH64);
        c.manifest_url = Some(UrlList(vec!["http://h/m.json".into()]));
        assert!(c.validate(Profile::Stage1).is_err());
    }

    #[test]
    fn manifest_sig_url_requires_manifest_url() {
        let mut c = sha256_entry("http://h/p", HASH64);
        c.manifest_sig_url = Some(UrlList(vec!["http://h/m.json.sig".into()]));
        assert!(c.validate(Profile::Stage1).is_err());
    }

    #[test]
    fn sha256_mode_requires_url() {
        let mut c = sha256_entry("http://h/p", HASH64);
        c.url = None;
        assert!(c.validate(Profile::Stage1).is_err());
    }

    #[test]
    fn both_modes_is_error() {
        let pk = pubkey_b64();
        let mut c = sha256_entry("http://h/p", HASH64);
        c.ed25519 = Some(pk);
        c.manifest_url = Some(UrlList(vec!["http://h/m.json".into()]));
        assert!(c.validate(Profile::Stage1).is_err());
    }

    #[test]
    fn neither_mode_is_error() {
        let c = ArchConfig { url: None, sha256: None, ed25519: None, manifest_url: None, manifest_sig_url: None };
        assert!(c.validate(Profile::Stage1).is_err());
    }

    #[test]
    fn bad_hex_is_error() {
        assert!(sha256_entry("http://h/p", "zz").validate(Profile::Stage1).is_err());
        let sixtyfour_nonhex = "z".repeat(64);
        assert!(sha256_entry("http://h/p", &sixtyfour_nonhex).validate(Profile::Stage1).is_err());
    }

    #[test]
    fn bad_pubkey_is_error() {
        assert!(ed25519_entry("not-base64!!", "http://h/m.json").validate(Profile::Stage1).is_err());
        assert!(ed25519_entry("AAAA", "http://h/m.json").validate(Profile::Stage1).is_err());
    }

    #[test]
    fn manifest_parse_validates() {
        let good = br#"{ "url": "https://h/p", "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "args": ["--x"], "version": 3 }"#;
        let m = Manifest::parse(good, Profile::Stage1).unwrap();
        assert_eq!(m.sha256.len(), 64);
        assert_eq!(m.version, 3);
        // https rejected under Stage0 (no TLS)
        assert!(Manifest::parse(good, Profile::Stage0).is_err());
        // bad sha256 rejected
        let bad = br#"{ "url": "http://h/p", "sha256": "nope" }"#;
        assert!(Manifest::parse(bad, Profile::Stage1).is_err());
    }

    #[test]
    fn urllist_accepts_string_or_array() {
        let one: UrlList = serde_json::from_str(r#""http://a/x""#).unwrap();
        assert_eq!(one.0, vec!["http://a/x".to_string()]);
        let many: UrlList = serde_json::from_str(r#"["http://a/x","http://b/x"]"#).unwrap();
        assert_eq!(many.0, vec!["http://a/x".to_string(), "http://b/x".to_string()]);
        assert_eq!(serde_json::to_string(&one).unwrap(), r#""http://a/x""#);
        assert_eq!(serde_json::to_string(&many).unwrap(), r#"["http://a/x","http://b/x"]"#);
    }

    #[test]
    fn url_list_validates_and_rejects_empty() {
        let mut c = sha256_entry("http://h/p", HASH64);
        c.url = Some(UrlList(vec!["http://h/p".into(), "https://mirror/p".into()]));
        assert!(c.validate(Profile::Stage1).is_ok());
        c.url = Some(UrlList(vec![]));
        assert!(c.validate(Profile::Stage1).is_err());
    }
}
