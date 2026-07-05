// SPDX-License-Identifier: MIT OR Apache-2.0

//! Lock.Boot admission metadata — the `_stage1` / `_stage2` wire types + validation.
//!
//! Shared by the stage1 **verifier** (deserialize + `validate` + `Verify`) and the
//! deploy **emitter** (construct + serialize), so the format has one definition and can't
//! drift. `_stage1` (stage0, the UKI hop) and `_stage2` (stage1, the payload hop) have the
//! same shape; they differ only in transport policy, captured by [`Profile`] — stage0 is
//! http-only (no TLS), stage1 allows https. Both allow fallback URL lists.

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

/// One stage's config: shared inline `args` plus a per-architecture admission entry.
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

/// One URL or a fallback list, tried in order. Deserializes from a string or an array,
/// and serializes back to a bare string when singular. Trying mirrors is safe: the
/// payload is cryptographically pinned, so bytes from any URL must still verify.
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

/// One architecture's admission entry. Exactly one of `sha256` (pin an exact payload) or
/// `ed25519` (pin a release pubkey; the payload rolls forward via a detached `.sig`) sets
/// the mode — see [`ArchConfig::validate`]. Every URL field takes a string or a fallback
/// list; `sig_url`/`args_url`/`args_sig_url` may contain a `{sha256}` placeholder.
#[derive(Debug, Serialize, Deserialize)]
pub struct ArchConfig {
    pub url: UrlList,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ed25519: Option<String>,
    /// Detached signature location(s); `{sha256}` → payload digest. Defaults to `<url>.sig`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig_url: Option<UrlList>,
    /// Signed remote args (ed25519 only): a JSON string array, verified against the same
    /// key via `args_sig_url` (else `<args_url>.sig`), overriding inline `args`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args_url: Option<UrlList>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args_sig_url: Option<UrlList>,
}

/// Transport policy per stage: stage0 (the UKI hop) has no TLS, stage1 (the payload hop)
/// does. Both allow fallback URL lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// `_stage1` — http:// only.
    Stage0,
    /// `_stage2` — http:// or https://.
    Stage1,
}

/// Resolved admission mode. `*_url` templates still carry a raw `{sha256}`; the consumer
/// substitutes it once the payload digest is known.
pub enum Verify {
    Sha256(String),
    Ed25519 {
        pubkey: String,
        sig_url: Option<UrlList>,
        args_url: Option<UrlList>,
        args_sig_url: Option<UrlList>,
    },
}

impl ArchConfig {
    /// Validate the URL(s) and the single verification field, returning the selected
    /// [`Verify`] mode. `profile` chooses the transport policy (see [`Profile`]).
    pub fn validate(&self, profile: Profile) -> Result<Verify, &'static str> {
        let allow_https = matches!(profile, Profile::Stage1);
        let ok_url = |s: &str| {
            (s.starts_with("http://") || (allow_https && s.starts_with("https://")))
                && s.chars().all(|c| c.is_ascii_graphic())
        };
        let ok_list = |l: &UrlList| !l.0.is_empty() && l.0.iter().all(|s| ok_url(s));
        if !ok_list(&self.url) {
            return Err("url must be a non-empty http(s):// URL (or list of them), printable ASCII");
        }
        if self.sig_url.as_ref().is_some_and(|l| !ok_list(l)) {
            return Err("sig_url must be http(s):// URL(s), printable ASCII");
        }
        if self.args_url.as_ref().is_some_and(|l| !ok_list(l)) {
            return Err("args_url must be http(s):// URL(s), printable ASCII");
        }
        if self.args_sig_url.as_ref().is_some_and(|l| !ok_list(l)) {
            return Err("args_sig_url must be http(s):// URL(s), printable ASCII");
        }
        if self.args_sig_url.is_some() && self.args_url.is_none() {
            return Err("args_sig_url requires args_url");
        }
        match (&self.sha256, &self.ed25519) {
            (Some(_), Some(_)) => Err("specify only one of sha256 / ed25519"),
            (None, None) => Err("must specify one of sha256 / ed25519"),
            (Some(hex), None) => {
                // Signed args need the release key, which only signed mode pins.
                if self.args_url.is_some() {
                    return Err("args_url requires ed25519 signed mode");
                }
                if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err("sha256 must be exactly 64 hex characters");
                }
                Ok(Verify::Sha256(hex.clone()))
            }
            (None, Some(pubkey)) => match STANDARD.decode(pubkey.trim()) {
                Ok(bytes) if bytes.len() == 32 => Ok(Verify::Ed25519 {
                    pubkey: pubkey.clone(),
                    sig_url: self.sig_url.clone(),
                    args_url: self.args_url.clone(),
                    args_sig_url: self.args_sig_url.clone(),
                }),
                Ok(_) => Err("ed25519 pubkey must decode to 32 bytes"),
                Err(_) => Err("ed25519 pubkey must be base64"),
            },
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

    fn ac(url: &str, sha256: Option<&str>, ed25519: Option<&str>) -> ArchConfig {
        ArchConfig {
            url: UrlList(vec![url.into()]),
            sha256: sha256.map(Into::into),
            ed25519: ed25519.map(Into::into),
            sig_url: None,
            args_url: None,
            args_sig_url: None,
        }
    }

    #[test]
    fn sha256_mode_ok() {
        assert!(matches!(ac("http://h/p", Some(HASH64), None).validate(Profile::Stage1), Ok(Verify::Sha256(_))));
    }

    #[test]
    fn https_allowed_on_stage1_only() {
        assert!(ac("https://h/p", Some(HASH64), None).validate(Profile::Stage1).is_ok());
        assert!(ac("https://h/p", Some(HASH64), None).validate(Profile::Stage0).is_err());
        assert!(ac("http://h/p", Some(HASH64), None).validate(Profile::Stage0).is_ok());
    }

    #[test]
    fn ed25519_mode_ok() {
        let pk = pubkey_b64();
        assert!(matches!(ac("http://h/p", None, Some(&pk)).validate(Profile::Stage1), Ok(Verify::Ed25519 { .. })));
    }

    #[test]
    fn both_modes_is_error() {
        let pk = pubkey_b64();
        assert!(ac("http://h/p", Some(HASH64), Some(&pk)).validate(Profile::Stage1).is_err());
    }

    #[test]
    fn neither_mode_is_error() {
        assert!(ac("http://h/p", None, None).validate(Profile::Stage1).is_err());
    }

    #[test]
    fn bad_hex_is_error() {
        assert!(ac("http://h/p", Some("zz"), None).validate(Profile::Stage1).is_err());
        let sixtyfour_nonhex = "z".repeat(64);
        assert!(ac("http://h/p", Some(&sixtyfour_nonhex), None).validate(Profile::Stage1).is_err());
    }

    #[test]
    fn bad_pubkey_is_error() {
        assert!(ac("http://h/p", None, Some("not-base64!!")).validate(Profile::Stage1).is_err());
        assert!(ac("http://h/p", None, Some("AAAA")).validate(Profile::Stage1).is_err());
    }

    #[test]
    fn non_http_url_is_error() {
        assert!(ac("ftp://h/p", Some(HASH64), None).validate(Profile::Stage1).is_err());
    }

    #[test]
    fn args_url_requires_ed25519() {
        let mut c = ac("http://h/p", Some(HASH64), None);
        c.args_url = Some(UrlList(vec!["http://h/args".into()]));
        assert!(c.validate(Profile::Stage1).is_err());
    }

    #[test]
    fn args_sig_url_requires_args_url() {
        let pk = pubkey_b64();
        let mut c = ac("http://h/p", None, Some(&pk));
        c.args_sig_url = Some(UrlList(vec!["http://h/args.sig".into()]));
        assert!(c.validate(Profile::Stage1).is_err());
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
        let mut c = ac("http://h/p", Some(HASH64), None);
        c.url = UrlList(vec!["http://h/p".into(), "https://mirror/p".into()]);
        assert!(c.validate(Profile::Stage1).is_ok());
        c.url = UrlList(vec![]);
        assert!(c.validate(Profile::Stage1).is_err());
    }
}
