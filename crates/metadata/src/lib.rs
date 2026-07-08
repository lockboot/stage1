// SPDX-License-Identifier: MIT OR Apache-2.0

//! Lock.Boot admission metadata — the `_stage1` / `_stage2` wire types + validation.
//!
//! Shared by the stage1 **verifier** (deserialize + `admission`/`validate`) and the deploy
//! **emitter** (construct + serialize), so the format has one definition and can't drift.
//! `_stage1` (stage0, the UKI hop) and `_stage2` (stage1, the payload hop) have the same shape;
//! they differ only in transport policy, captured by [`Profile`] — stage0 is http-only (no TLS),
//! stage1 allows https. Both allow fallback URL lists.
//!
//! Each per-architecture entry ([`ArchConfig`]) is a **discriminated union** — either a
//! [`Payload`] (admit a concrete binary now, by sha256 pin or ed25519-signed) or a [`ManifestRef`]
//! (fetch a signed manifest, itself a user-data fragment, and resolve it). The verifier follows a
//! `manifest` by fetching + verifying it against the pinned key, **deep-merging the whole document
//! into the received user-data at the top level**, and re-evaluating — a loop that terminates at a
//! `payload` (or a cycle). Each hop is appended to [`ArchConfig::resolved_manifests`] (provenance,
//! carrying the resolved hash), which rides along in the doc handed to the payload.

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

/// One stage's config: a per-architecture admission entry (args live inside the [`Payload`]).
#[derive(Debug, Serialize, Deserialize)]
pub struct StageConfig {
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

/// One architecture's admission entry: the discriminated union ([`Entry`]) plus the resolution
/// history accumulated by the manifest loop. The `payload` / `manifest` key selects the mode;
/// `resolved_manifests` is a sibling record, appended one entry per resolved manifest hop.
#[derive(Debug, Serialize, Deserialize)]
pub struct ArchConfig {
    #[serde(flatten)]
    pub entry: Entry,
    /// Provenance of the manifest chain resolved to reach the payload (empty for a direct
    /// `payload` entry). Each record carries the fetched manifest's resolved `sha256`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolved_manifests: Vec<ManifestRef>,
}

/// The per-arch discriminated union: a concrete payload to admit, or a signed manifest to resolve.
#[derive(Debug, Serialize, Deserialize)]
pub enum Entry {
    /// `"payload": { url, (sha256 | ed25519 + sig_url), args… }`.
    #[serde(rename = "payload")]
    Payload(Payload),
    /// `"manifest": { url, ed25519, sig_url?, sha256? }`.
    #[serde(rename = "manifest")]
    Manifest(ManifestRef),
}

/// A concrete payload admission. Exactly one of `sha256` (pin an exact binary) or `ed25519`
/// (pin a release pubkey; the binary rolls forward via a detached `.sig`) selects the mode — see
/// [`Payload::admission`]. `sig_url` / `args_url` / `args_sig_url` may contain a `{sha256}`
/// placeholder (replaced with the payload digest).
#[derive(Debug, Serialize, Deserialize)]
pub struct Payload {
    pub url: UrlList,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ed25519: Option<String>,
    /// Detached signature location(s); `{sha256}` → payload digest. Defaults to `<url>.sig`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig_url: Option<UrlList>,
    /// Inline argv for the payload (overridden by verified `args_url` when present).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,
    /// Signed remote args (ed25519 only): a JSON string array, verified against the same key
    /// via `args_sig_url` (else `<args_url>.sig`), overriding inline `args`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args_url: Option<UrlList>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args_sig_url: Option<UrlList>,
}

/// A pointer to a signed manifest — and the shape of a resolution-history record. The manifest is
/// fetched from `url`, its detached signature (`sig_url`, else `<url>.sig`) verified against the
/// pinned `ed25519` key, then deep-merged into the doc. `sha256` optionally pins the manifest's own
/// bytes; the loop fills it with the resolved hash when recording the hop in `resolved_manifests`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestRef {
    pub url: UrlList,
    pub ed25519: String,
    /// Manifest signature location; `{sha256}` → manifest digest. Defaults to `<url>.sig`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig_url: Option<UrlList>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
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

/// Resolved payload-admission mode. `*_url` templates still carry a raw `{sha256}`; the consumer
/// substitutes it once the payload digest is known.
pub enum Admit {
    Sha256(String),
    Ed25519 {
        pubkey: String,
        sig_url: Option<UrlList>,
        args_url: Option<UrlList>,
        args_sig_url: Option<UrlList>,
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
fn ok_pubkey(s: &str) -> Result<(), &'static str> {
    match STANDARD.decode(s.trim()) {
        Ok(bytes) if bytes.len() == 32 => Ok(()),
        Ok(_) => Err("ed25519 pubkey must decode to 32 bytes"),
        Err(_) => Err("ed25519 pubkey must be base64"),
    }
}

impl ArchConfig {
    /// Validate whichever variant this entry holds, under `profile`'s transport policy.
    pub fn validate(&self, profile: Profile) -> Result<(), &'static str> {
        match &self.entry {
            Entry::Payload(p) => p.admission(profile).map(|_| ()),
            Entry::Manifest(m) => m.validate(profile),
        }
    }
}

impl Payload {
    /// Validate the URL(s) + the single verification field, returning the selected [`Admit`] mode.
    pub fn admission(&self, profile: Profile) -> Result<Admit, &'static str> {
        let allow_https = matches!(profile, Profile::Stage1);
        if !ok_list(&self.url, allow_https) {
            return Err("url must be a non-empty http(s):// URL (or list of them), printable ASCII");
        }
        if self.sig_url.as_ref().is_some_and(|l| !ok_list(l, allow_https)) {
            return Err("sig_url must be http(s):// URL(s), printable ASCII");
        }
        if self.args_url.as_ref().is_some_and(|l| !ok_list(l, allow_https)) {
            return Err("args_url must be http(s):// URL(s), printable ASCII");
        }
        if self.args_sig_url.as_ref().is_some_and(|l| !ok_list(l, allow_https)) {
            return Err("args_sig_url must be http(s):// URL(s), printable ASCII");
        }
        if self.args_sig_url.is_some() && self.args_url.is_none() {
            return Err("args_sig_url requires args_url");
        }
        match (&self.sha256, &self.ed25519) {
            (Some(_), Some(_)) => Err("specify only one of sha256 / ed25519"),
            (None, None) => Err("payload must specify one of sha256 / ed25519"),
            (Some(hex), None) => {
                // Signed args need the release key, which only signed mode pins.
                if self.args_url.is_some() {
                    return Err("args_url requires ed25519 signed mode");
                }
                if !ok_sha256(hex) {
                    return Err("sha256 must be exactly 64 hex characters");
                }
                Ok(Admit::Sha256(hex.clone()))
            }
            (None, Some(pubkey)) => {
                ok_pubkey(pubkey)?;
                Ok(Admit::Ed25519 {
                    pubkey: pubkey.clone(),
                    sig_url: self.sig_url.clone(),
                    args_url: self.args_url.clone(),
                    args_sig_url: self.args_sig_url.clone(),
                })
            }
        }
    }
}

impl ManifestRef {
    /// Validate the manifest pointer under `profile`'s transport policy.
    pub fn validate(&self, profile: Profile) -> Result<(), &'static str> {
        let allow_https = matches!(profile, Profile::Stage1);
        if !ok_list(&self.url, allow_https) {
            return Err("manifest url must be a non-empty http(s):// URL (or list), printable ASCII");
        }
        if self.sig_url.as_ref().is_some_and(|l| !ok_list(l, allow_https)) {
            return Err("manifest sig_url must be http(s):// URL(s), printable ASCII");
        }
        if self.sha256.as_ref().is_some_and(|h| !ok_sha256(h)) {
            return Err("manifest sha256 must be exactly 64 hex characters");
        }
        ok_pubkey(&self.ed25519)
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

    fn payload(url: &str, sha256: Option<&str>, ed25519: Option<&str>) -> Payload {
        Payload {
            url: UrlList(vec![url.into()]),
            sha256: sha256.map(Into::into),
            ed25519: ed25519.map(Into::into),
            sig_url: None,
            args: None,
            args_url: None,
            args_sig_url: None,
        }
    }

    #[test]
    fn sha256_mode_ok() {
        assert!(matches!(payload("http://h/p", Some(HASH64), None).admission(Profile::Stage1), Ok(Admit::Sha256(_))));
    }

    #[test]
    fn https_allowed_on_stage1_only() {
        assert!(payload("https://h/p", Some(HASH64), None).admission(Profile::Stage1).is_ok());
        assert!(payload("https://h/p", Some(HASH64), None).admission(Profile::Stage0).is_err());
        assert!(payload("http://h/p", Some(HASH64), None).admission(Profile::Stage0).is_ok());
    }

    #[test]
    fn ed25519_mode_ok() {
        let pk = pubkey_b64();
        assert!(matches!(payload("http://h/p", None, Some(&pk)).admission(Profile::Stage1), Ok(Admit::Ed25519 { .. })));
    }

    #[test]
    fn both_modes_is_error() {
        let pk = pubkey_b64();
        assert!(payload("http://h/p", Some(HASH64), Some(&pk)).admission(Profile::Stage1).is_err());
    }

    #[test]
    fn neither_mode_is_error() {
        assert!(payload("http://h/p", None, None).admission(Profile::Stage1).is_err());
    }

    #[test]
    fn bad_hex_is_error() {
        assert!(payload("http://h/p", Some("zz"), None).admission(Profile::Stage1).is_err());
        let sixtyfour_nonhex = "z".repeat(64);
        assert!(payload("http://h/p", Some(&sixtyfour_nonhex), None).admission(Profile::Stage1).is_err());
    }

    #[test]
    fn bad_pubkey_is_error() {
        assert!(payload("http://h/p", None, Some("not-base64!!")).admission(Profile::Stage1).is_err());
        assert!(payload("http://h/p", None, Some("AAAA")).admission(Profile::Stage1).is_err());
    }

    #[test]
    fn non_http_url_is_error() {
        assert!(payload("ftp://h/p", Some(HASH64), None).admission(Profile::Stage1).is_err());
    }

    #[test]
    fn args_url_requires_ed25519() {
        let mut p = payload("http://h/p", Some(HASH64), None);
        p.args_url = Some(UrlList(vec!["http://h/args".into()]));
        assert!(p.admission(Profile::Stage1).is_err());
    }

    #[test]
    fn args_sig_url_requires_args_url() {
        let pk = pubkey_b64();
        let mut p = payload("http://h/p", None, Some(&pk));
        p.args_sig_url = Some(UrlList(vec!["http://h/args.sig".into()]));
        assert!(p.admission(Profile::Stage1).is_err());
    }

    #[test]
    fn manifest_validate_ok_and_errors() {
        let pk = pubkey_b64();
        let mut m = ManifestRef { url: UrlList(vec!["http://h/m".into()]), ed25519: pk, sig_url: None, sha256: None };
        assert!(m.validate(Profile::Stage1).is_ok());
        // optional sha256 pin is checked
        m.sha256 = Some("nope".into());
        assert!(m.validate(Profile::Stage1).is_err());
        m.sha256 = Some(HASH64.into());
        assert!(m.validate(Profile::Stage1).is_ok());
        // bad pubkey rejected
        m.ed25519 = "AAAA".into();
        assert!(m.validate(Profile::Stage1).is_err());
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

    // --- Discriminated-union wire representation (the serde-flatten round-trip risk) ---

    #[test]
    fn payload_entry_roundtrips() {
        let json = format!(r#"{{"payload":{{"url":"http://h/p","sha256":"{HASH64}"}}}}"#);
        let ac: ArchConfig = serde_json::from_str(&json).unwrap();
        assert!(matches!(ac.entry, Entry::Payload(_)));
        assert!(ac.resolved_manifests.is_empty());
        // re-serialize keeps the "payload" tag and drops the empty history
        assert_eq!(serde_json::to_string(&ac).unwrap(), json);
    }

    #[test]
    fn manifest_entry_roundtrips() {
        let pk = pubkey_b64();
        let json = format!(r#"{{"manifest":{{"url":"http://h/m","ed25519":"{pk}"}}}}"#);
        let ac: ArchConfig = serde_json::from_str(&json).unwrap();
        assert!(matches!(ac.entry, Entry::Manifest(_)));
        assert_eq!(serde_json::to_string(&ac).unwrap(), json);
    }

    #[test]
    fn resolved_manifests_is_a_sibling_of_the_union() {
        // The flatten case: the union key AND resolved_manifests coexist on one object.
        let pk = pubkey_b64();
        let json = format!(
            r#"{{"payload":{{"url":"http://h/p","sha256":"{HASH64}"}},"resolved_manifests":[{{"url":"http://h/m","ed25519":"{pk}","sha256":"{HASH64}"}}]}}"#
        );
        let ac: ArchConfig = serde_json::from_str(&json).unwrap();
        assert!(matches!(ac.entry, Entry::Payload(_)));
        assert_eq!(ac.resolved_manifests.len(), 1);
        assert_eq!(ac.resolved_manifests[0].sha256.as_deref(), Some(HASH64));
        assert_eq!(serde_json::to_string(&ac).unwrap(), json);
    }

    #[test]
    fn arch_validate_dispatches_on_variant() {
        let pk = pubkey_b64();
        let p: ArchConfig = serde_json::from_str(&format!(r#"{{"payload":{{"url":"http://h/p","sha256":"{HASH64}"}}}}"#)).unwrap();
        assert!(p.validate(Profile::Stage1).is_ok());
        let m: ArchConfig = serde_json::from_str(&format!(r#"{{"manifest":{{"url":"http://h/m","ed25519":"{pk}"}}}}"#)).unwrap();
        assert!(m.validate(Profile::Stage1).is_ok());
    }
}
