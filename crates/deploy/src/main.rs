// SPDX-License-Identifier: MIT OR Apache-2.0

//! Lock.Boot deploy tool. Signs (or hashes) the UKI + stage2 for an architecture, composes
//! mirror URL lists from repeated `--base-url`, and emits an upload-ready directory plus a
//! merged `user-data.json` carrying `_stage1` (the UKI hop, admitted by stage0) and
//! `_stage2` (the payload hop, admitted by stage1). Uses the shared `metadata` types (so
//! what we emit is exactly what the verifiers accept) and the shared `ed25519-sign` signer.

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use ed25519_sign::{sha256_hex, sign_payload};
use metadata::{ArchConfig, Manifest, Profile, StageConfig, UrlList, UserData};
use serde_json::{Map, Value};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "lockboot-deploy", version, about = "Sign payloads, compose mirror URLs, and emit Lock.Boot user-data + an upload-ready directory.")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Sign/pin the UKI and stage2 for one arch, compose mirror URLs, emit into --out.
    Create(CreateArgs),
    /// Validate a user-data doc (both _stage1 and _stage2) against the admission rules.
    Validate {
        /// A user-data.json file, or a directory containing one.
        path: PathBuf,
    },
    /// Edit an existing deployment's user-data.json: add/remove mirror base URLs.
    Modify(ModifyArgs),
}

#[derive(Args)]
struct CreateArgs {
    #[arg(long, value_parser = ["x86_64", "aarch64"])]
    arch: String,
    /// The UKI (linux.efi) served for the _stage1 hop (admitted by stage0).
    #[arg(long)]
    uki: PathBuf,
    /// The stage2 payload served for the _stage2 hop (admitted by stage1).
    #[arg(long)]
    stage2: PathBuf,
    /// ed25519 PKCS#8 PEM. Given → emit a signed manifest per payload and pin the pubkey
    /// (roll-forward); omitted → pin an exact sha256 of each inline.
    #[arg(long)]
    key: Option<PathBuf>,
    /// Mirror base URL (repeatable). http:// only — stage0 has no TLS; integrity is the pin.
    /// URLs are composed as `<base>/<arch>/<file>`.
    #[arg(long = "base-url", required = true)]
    base_url: Vec<String>,
    /// Args for stage2: a JSON array of strings, e.g. '["--flag","v"]'. In ed25519 mode these
    /// ride inside the signed manifest; in sha256 mode they are inline in the (trusted) user-data.
    #[arg(long)]
    args: Option<String>,
    /// Release version stamped into the signed manifest (ed25519 mode); an anti-rollback hint.
    #[arg(long, default_value_t = 1)]
    version: u64,
    /// Output directory (created if missing). user-data.json is merged across arches.
    #[arg(long)]
    out: PathBuf,
}

#[derive(Args)]
struct ModifyArgs {
    /// A user-data.json file, or a directory containing one.
    path: PathBuf,
    #[arg(long = "add-base-url")]
    add_base_url: Vec<String>,
    #[arg(long = "remove-base-url")]
    remove_base_url: Vec<String>,
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Create(a) => create(a),
        Cmd::Validate { path } => validate(&path),
        Cmd::Modify(a) => modify(a),
    }
}

fn compose_urls(bases: &[String], arch: &str, filename: &str) -> UrlList {
    UrlList(bases.iter().map(|b| format!("{b}/{arch}/{filename}")).collect())
}

/// Write `src`'s bytes into `<arch_dir>/<filename>` (served), then admit-pin it. With a key
/// (ed25519 mode) emit a **signed manifest** — `{ url, sha256, args, version }` written to
/// `<filename>.manifest.json` (+ `.sig`) — and return an entry pointing at it. Without a key
/// (sha256 mode) return an inline `{ url, sha256 }` entry (`args`/`version` are unused there).
fn build_entry(
    arch_dir: &Path,
    arch: &str,
    bases: &[String],
    filename: &str,
    src: &Path,
    key_pem: Option<&str>,
    args: Option<&[String]>,
    version: u64,
) -> Result<ArchConfig> {
    let bytes = fs::read(src).with_context(|| format!("reading {}", src.display()))?;
    fs::write(arch_dir.join(filename), &bytes)
        .with_context(|| format!("writing {}/{filename}", arch_dir.display()))?;
    let url = compose_urls(bases, arch, filename);
    match key_pem {
        Some(pem) => {
            let manifest = Manifest {
                url,
                sha256: sha256_hex(&bytes),
                args: args.map(<[String]>::to_vec),
                version,
            };
            let manifest_json = serde_json::to_vec_pretty(&manifest)?;
            let manifest_name = format!("{filename}.manifest.json");
            fs::write(arch_dir.join(&manifest_name), &manifest_json)?;
            let s = sign_payload(pem, &manifest_json)?;
            fs::write(arch_dir.join(format!("{manifest_name}.sig")), &s.signature)?;
            Ok(ArchConfig {
                url: None,
                sha256: None,
                ed25519: Some(s.pubkey_b64),
                manifest_url: Some(compose_urls(bases, arch, &manifest_name)),
                manifest_sig_url: None, // verifier defaults to <manifest_url>.sig (co-located)
            })
        }
        None => Ok(ArchConfig {
            url: Some(url),
            sha256: Some(sha256_hex(&bytes)),
            ed25519: None,
            manifest_url: None,
            manifest_sig_url: None,
        }),
    }
}

fn create(a: CreateArgs) -> Result<()> {
    let bases: Vec<String> = a.base_url.iter().map(|b| b.trim_end_matches('/').to_string()).collect();
    for b in &bases {
        if !b.starts_with("http://") {
            bail!("--base-url must be http:// (stage0 admits the UKI over plain HTTP; integrity is the pin, not TLS): {b}");
        }
    }
    let arch_dir = a.out.join(&a.arch);
    fs::create_dir_all(&arch_dir).with_context(|| format!("creating {}", arch_dir.display()))?;

    let key_pem = a
        .key
        .as_ref()
        .map(|p| fs::read_to_string(p).with_context(|| format!("reading key {}", p.display())))
        .transpose()?;

    // stage2 args: in ed25519 mode they ride inside the signed manifest; in sha256 mode they are
    // inline in the (trusted) user-data. The UKI (_stage1) takes no args here.
    let args_parsed: Option<Vec<String>> = a
        .args
        .as_ref()
        .map(|j| serde_json::from_str(j).context("--args must be a JSON array of strings"))
        .transpose()?;
    let signed = key_pem.is_some();
    let manifest_args = if signed { args_parsed.as_deref() } else { None };
    let inline_args = if signed { None } else { args_parsed.clone() };

    let uki_entry =
        build_entry(&arch_dir, &a.arch, &bases, "linux.efi", &a.uki, key_pem.as_deref(), None, a.version)?;
    let stage2_entry = build_entry(
        &arch_dir, &a.arch, &bases, "stage2", &a.stage2, key_pem.as_deref(), manifest_args, a.version,
    )?;

    // Fail early on a bad config, in the profile each hop will actually be checked under.
    uki_entry.validate(Profile::Stage0).map_err(|m| anyhow!("_stage1 entry invalid: {m}"))?;
    stage2_entry.validate(Profile::Stage1).map_err(|m| anyhow!("_stage2 entry invalid: {m}"))?;

    let ud_path = a.out.join("user-data.json");
    merge_user_data(&ud_path, &a.arch, uki_entry, stage2_entry, inline_args)?;
    let mode = if key_pem.is_some() { "ed25519 (signed)" } else { "sha256 (pinned)" };
    println!("wrote {} + {}/ artifacts [{mode}, {} mirror(s)]", ud_path.display(), a.arch, bases.len());
    Ok(())
}

/// Merge one arch's `_stage1`/`_stage2` entries into `user-data.json` (creating it if absent),
/// preserving any other arch already present.
fn merge_user_data(
    path: &Path,
    arch: &str,
    uki: ArchConfig,
    stage2: ArchConfig,
    inline_args: Option<Vec<String>>,
) -> Result<()> {
    let mut doc: Value = if path.exists() {
        serde_json::from_str(&fs::read_to_string(path)?).context("parsing existing user-data.json")?
    } else {
        Value::Object(Map::new())
    };
    let obj = doc.as_object_mut().ok_or_else(|| anyhow!("user-data must be a JSON object"))?;
    set_arch(obj, "_stage1", arch, serde_json::to_value(&uki)?, None)?;
    set_arch(obj, "_stage2", arch, serde_json::to_value(&stage2)?, inline_args)?;
    fs::write(path, format!("{}\n", serde_json::to_string_pretty(&doc)?))
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn set_arch(
    obj: &mut Map<String, Value>,
    stage_key: &str,
    arch: &str,
    entry: Value,
    inline_args: Option<Vec<String>>,
) -> Result<()> {
    let stage = obj.entry(stage_key).or_insert_with(|| Value::Object(Map::new()));
    let smap = stage.as_object_mut().ok_or_else(|| anyhow!("{stage_key} must be a JSON object"))?;
    smap.insert(arch.to_string(), entry);
    if let Some(args) = inline_args {
        smap.insert("args".to_string(), serde_json::to_value(args)?);
    }
    Ok(())
}

fn validate(path: &Path) -> Result<()> {
    let path = doc_path(path);
    let text = fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let ud: UserData = serde_json::from_str(&text).context("parsing user-data JSON")?;
    let mut errors = Vec::new();
    check_stage(&ud.stage1, Profile::Stage0, "_stage1", &mut errors);
    check_stage(&ud.stage2, Profile::Stage1, "_stage2", &mut errors);
    if ud.stage1.is_none() && ud.stage2.is_none() {
        errors.push("document has neither _stage1 nor _stage2".to_string());
    }
    if errors.is_empty() {
        println!("{}: valid", path.display());
        Ok(())
    } else {
        for e in &errors {
            eprintln!("  {e}");
        }
        bail!("{} invalid ({} problem(s))", path.display(), errors.len())
    }
}

fn check_stage(stage: &Option<StageConfig>, profile: Profile, name: &str, errors: &mut Vec<String>) {
    let Some(s) = stage else { return };
    for (arch, entry) in [("x86_64", &s.x86_64), ("aarch64", &s.aarch64)] {
        if let Some(e) = entry {
            if let Err(m) = e.validate(profile) {
                errors.push(format!("{name}.{arch}: {m}"));
            }
        }
    }
}

fn modify(a: ModifyArgs) -> Result<()> {
    let path = doc_path(&a.path);
    let mut doc: Value =
        serde_json::from_str(&fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?)
            .context("parsing user-data JSON")?;
    let adds: Vec<String> = a.add_base_url.iter().map(|b| b.trim_end_matches('/').to_string()).collect();
    let rems: Vec<String> = a.remove_base_url.iter().map(|b| b.trim_end_matches('/').to_string()).collect();
    let obj = doc.as_object_mut().ok_or_else(|| anyhow!("user-data must be a JSON object"))?;
    for stage_key in ["_stage1", "_stage2"] {
        let Some(stage) = obj.get_mut(stage_key).and_then(|v| v.as_object_mut()) else { continue };
        for (arch, entry) in stage.iter_mut() {
            if arch == "args" {
                continue;
            }
            let Some(em) = entry.as_object_mut() else { continue };
            for field in ["url", "manifest_url", "manifest_sig_url"] {
                if let Some(v) = em.get_mut(field) {
                    *v = rewrite_urls(v, &adds, &rems)?;
                }
            }
        }
    }
    fs::write(&path, format!("{}\n", serde_json::to_string_pretty(&doc)?))?;
    println!("updated {} (+{} / -{} mirror(s))", path.display(), adds.len(), rems.len());
    Ok(())
}

/// Rewrite a url field (string or array): drop entries under any removed base, and append
/// `<add-base><path-suffix>` for each add base (suffix taken from the first entry). Collapses
/// back to a bare string when a single URL remains.
fn rewrite_urls(v: &Value, adds: &[String], rems: &[String]) -> Result<Value> {
    let mut list: Vec<String> = match v {
        Value::String(s) => vec![s.clone()],
        Value::Array(a) => a.iter().filter_map(|x| x.as_str().map(String::from)).collect(),
        _ => bail!("url field must be a string or array of strings"),
    };
    let suffix = list.first().map(|u| url_path(u).to_string());
    list.retain(|u| !rems.iter().any(|b| u.starts_with(&format!("{b}/"))));
    if let Some(suffix) = suffix {
        for b in adds {
            let cand = format!("{b}{suffix}");
            if !list.contains(&cand) {
                list.push(cand);
            }
        }
    }
    Ok(if list.len() == 1 {
        Value::String(list.remove(0))
    } else {
        Value::Array(list.into_iter().map(Value::String).collect())
    })
}

/// The path portion of an http(s) URL, e.g. `http://cdn/x86_64/linux.efi` → `/x86_64/linux.efi`.
fn url_path(u: &str) -> &str {
    let after = u.strip_prefix("http://").or_else(|| u.strip_prefix("https://")).unwrap_or(u);
    match after.find('/') {
        Some(i) => &after[i..],
        None => "",
    }
}

fn doc_path(p: &Path) -> PathBuf {
    if p.is_dir() {
        p.join("user-data.json")
    } else {
        p.to_path_buf()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compose_and_url_path() {
        let l = compose_urls(&["http://a".into(), "http://b".into()], "x86_64", "linux.efi");
        assert_eq!(l.0, vec!["http://a/x86_64/linux.efi", "http://b/x86_64/linux.efi"]);
        assert_eq!(url_path("http://cdn/x86_64/linux.efi"), "/x86_64/linux.efi");
        assert_eq!(url_path("https://h:8000/p/q"), "/p/q");
    }

    #[test]
    fn rewrite_urls_add_then_remove() {
        let v = Value::String("http://cdn1/x86_64/stage2".into());
        let v = rewrite_urls(&v, &["http://cdn2".into()], &[]).unwrap();
        assert_eq!(v, serde_json::json!(["http://cdn1/x86_64/stage2", "http://cdn2/x86_64/stage2"]));
        // removing back to one entry collapses to a bare string
        let v = rewrite_urls(&v, &[], &["http://cdn1".into()]).unwrap();
        assert_eq!(v, Value::String("http://cdn2/x86_64/stage2".into()));
    }

    #[test]
    fn create_sha256_roundtrips_through_validate() {
        let dir = std::env::temp_dir().join(format!("deploy-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let uki = dir.join("uki.bin");
        fs::write(&uki, b"fake uki").unwrap();
        let s2 = dir.join("s2.bin");
        fs::write(&s2, b"fake stage2").unwrap();
        let out = dir.join("out");

        create(CreateArgs {
            arch: "x86_64".into(),
            uki,
            stage2: s2,
            key: None,
            base_url: vec!["http://cdn1".into(), "http://cdn2".into()],
            args: None,
            version: 1,
            out: out.clone(),
        })
        .unwrap();

        // The emitted doc validates and re-parses into the shared type with both mirrors.
        validate(&out).unwrap();
        let ud: UserData =
            serde_json::from_str(&fs::read_to_string(out.join("user-data.json")).unwrap()).unwrap();
        assert_eq!(ud.stage2.unwrap().x86_64.unwrap().url.unwrap().0.len(), 2);
        assert!(ud.stage1.unwrap().x86_64.unwrap().sha256.is_some());
        let _ = fs::remove_dir_all(&dir);
    }

    /// PKCS#8 PEM for an ed25519 key with a fixed 32-byte seed (matches ed25519-sign's format).
    fn test_pem() -> String {
        use base64::Engine as _;
        let mut der = vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        der.extend_from_slice(&[7u8; 32]);
        let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
        format!("-----BEGIN PRIVATE KEY-----\n{b64}\n-----END PRIVATE KEY-----\n")
    }

    #[test]
    fn create_ed25519_emits_verifiable_manifest() {
        let dir = std::env::temp_dir().join(format!("deploy-test-ed-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let uki = dir.join("uki.bin");
        fs::write(&uki, b"fake uki").unwrap();
        let s2 = dir.join("s2.bin");
        fs::write(&s2, b"fake stage2").unwrap();
        let key = dir.join("key.pem");
        fs::write(&key, test_pem()).unwrap();
        let out = dir.join("out");

        create(CreateArgs {
            arch: "x86_64".into(),
            uki,
            stage2: s2,
            key: Some(key),
            base_url: vec!["http://cdn1".into()],
            args: Some(r#"["--serve","0.0.0.0:8080"]"#.into()),
            version: 7,
            out: out.clone(),
        })
        .unwrap();

        // The emitted user-data validates and pins the pubkey + manifest_url (no inline payload).
        validate(&out).unwrap();
        let ud: UserData =
            serde_json::from_str(&fs::read_to_string(out.join("user-data.json")).unwrap()).unwrap();
        let s2e = ud.stage2.unwrap().x86_64.unwrap();
        assert!(s2e.ed25519.is_some());
        assert!(s2e.manifest_url.is_some());
        assert!(s2e.url.is_none());

        // The emitted manifest verifies against the pinned key and carries args + version.
        let mbytes = fs::read(out.join("x86_64/stage2.manifest.json")).unwrap();
        let sig = fs::read(out.join("x86_64/stage2.manifest.json.sig")).unwrap();
        ed25519_sign::verify(&s2e.ed25519.unwrap(), &mbytes, &sig).unwrap();
        let m = Manifest::parse(&mbytes, Profile::Stage1).unwrap();
        assert_eq!(m.version, 7);
        assert_eq!(m.args.unwrap(), vec!["--serve", "0.0.0.0:8080"]);
        let _ = fs::remove_dir_all(&dir);
    }
}
