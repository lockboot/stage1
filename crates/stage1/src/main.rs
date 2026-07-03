// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use vaportpm_attest::{Tpm, PcrOps};
use reqwest::blocking::Client;
use rustls::crypto::CryptoProvider;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use vaportpm_attest as tpm;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod sig;

const EC2_TOKEN_URL: &str = "http://169.254.169.254/latest/api/token";
const EC2_METADATA_URL: &str = "http://169.254.169.254/latest/user-data";
const GCP_METADATA_URL: &str = "http://metadata.google.internal/computeMetadata/v1/instance/attributes/user-data";
const AZURE_METADATA_URL: &str = "http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-02-01&format=text";
const TMP_DIR: &str = "/tmp";

// stage1 measures only loaded code: PCR 14 = SHA-256 of the stage2 binary, nothing else.
// Config (and the admission pin/key) is left for the app to measure if it cares.
const PCR_BINARY: u8 = 14;

/// One URL or a fallback list, tried in order. Deserializes from a string or an array,
/// and serializes back to a bare string when singular. Trying mirrors is safe: the
/// payload is cryptographically pinned, so bytes from any URL must still verify.
#[derive(Debug, Clone)]
struct UrlList(Vec<String>);

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

#[derive(Debug, Serialize, Deserialize)]
struct UserData {
    _stage2: Stage2Config,
}

#[derive(Debug, Serialize, Deserialize)]
struct Stage2Config {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    args: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    aarch64: Option<ArchConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    x86_64: Option<ArchConfig>,
}

/// One architecture's stage2 entry. Exactly one of `sha256` (pin an exact payload) or
/// `ed25519` (pin a release pubkey; the payload rolls forward via a detached `.sig`) sets
/// the admission mode — see [`ArchConfig::validate`]. Every URL field takes a string or a
/// fallback list; `sig_url`/`args_url`/`args_sig_url` may contain a `{sha256}` placeholder.
#[derive(Debug, Serialize, Deserialize)]
struct ArchConfig {
    url: UrlList,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ed25519: Option<String>,
    /// Detached signature location(s); `{sha256}` → payload digest. Defaults to `<url>.sig`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sig_url: Option<UrlList>,
    /// Signed remote args (ed25519 only): a JSON string array, verified against the same
    /// key via `args_sig_url` (else `<args_url>.sig`), overriding inline `args`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    args_url: Option<UrlList>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    args_sig_url: Option<UrlList>,
}

/// Resolved admission mode for a stage2 payload. `*_url` templates still carry a raw
/// `{sha256}`; the consumer substitutes it once the payload digest is known.
enum Verify {
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
    /// [`Verify`] mode. Unlike stage0 (a plain-HTTP UEFI stack), stage1 has TLS, so
    /// `https://` is allowed alongside `http://`.
    fn validate(&self) -> Result<Verify, &'static str> {
        let ok_url = |s: &str| {
            (s.starts_with("http://") || s.starts_with("https://"))
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

fn main() {
    let result = main_inner();

    // Flush output before exiting (especially important when running as PID 1)
    let _ = io::stdout().flush();
    let _ = io::stderr().flush();

    // Handle errors explicitly to ensure stderr is flushed before exit
    if let Err(e) = result {
        eprintln!("Error: {:#}", e);
        let _ = io::stderr().flush();
        poweroff();
    }
}

fn main_inner() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    // This runs when: PID is 1 (init process) OR no arguments provided
    if is_pid1() || args.len() <= 1 {
        return stage2(fetch_cloud_metadata()?);
    }
    // Handle --attest command
    if args[1] == "--attest" {
        let nonce = if args.len() > 2 {
            args[2].as_bytes().to_vec()
        } else {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("System time before UNIX epoch")
                .as_secs()
                .to_string()
                .into_bytes()
        };
        return Ok(println!("{}", tpm::attest(&nonce)?));
    }
    // Handle --make-config command (sha256 pin: download the payload and hash it)
    if args[1] == "--make-config" {
        if args.len() < 4 || args.len() > 5 {
            return Err(anyhow!("Usage: stage1 --make-config <aarch64|x86_64> <URL> [config.json]"));
        }
        let arch = &args[2];
        if arch != "aarch64" && arch != "x86_64" {
            return Err(anyhow!("Architecture must be either 'aarch64' or 'x86_64'"));
        }
        return make_config(arch, &args[3], args.get(4).map(|s| s.as_str()));
    }
    // Handle --make-config-ed25519 command (signed mode: pin a release pubkey)
    if args[1] == "--make-config-ed25519" {
        if args.len() < 5 || args.len() > 6 {
            return Err(anyhow!("Usage: stage1 --make-config-ed25519 <aarch64|x86_64> <URL> <PUBKEY_B64> [config.json]"));
        }
        let arch = &args[2];
        if arch != "aarch64" && arch != "x86_64" {
            return Err(anyhow!("Architecture must be either 'aarch64' or 'x86_64'"));
        }
        return make_config_ed25519(arch, &args[3], &args[4], args.get(5).map(|s| s.as_str()));
    }
    // Handle other arguments (--url, --file)
    if args.len() == 3 {
        return stage2(
            parse_json_to_config(
                match args[1].as_str() {
                    "--url" => fetch_from_url(&args[2])?,
                    "--file" => read_from_file(&args[2])?,
                    _ => return Err(anyhow!("Invalid argument. Use --url <URL> or --file <PATH>"))
        })?);
    }
    Err(anyhow!(
        "Usage: stage1 [--url <URL> | --file <PATH> | --make-config <ARCH> <URL> [config.json] | --make-config-ed25519 <ARCH> <URL> <PUBKEY_B64> [config.json] | --attest]\n\
         If no arguments are provided (or pid==1): fetches from EC2 metadata service.\n\
         --make-config: Download a file, compute SHA256, and output a JSON config with _stage2.<ARCH> (sha256 pin).\n\
         --make-config-ed25519: Emit a signed-mode config pinning the base64 ed25519 <PUBKEY_B64> (payload rolls forward).\n\
                        ARCH must be 'aarch64' or 'x86_64'. Either can be run repeatedly with the same config.json\n\
                        to build a multi-arch config. Add fallback URLs / {{sha256}}-templated sig URLs by editing the JSON.\n\
         --attest: Generate TPM attestation with EK certificates, PCRs, and certified signing key"
    ))
}

/// Get kernel-style timestamp string: [    2.231397]
/// Uses clock_gettime with CLOCK_BOOTTIME for accurate system uptime
fn kts() -> String {
    unsafe {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // CLOCK_BOOTTIME = time since boot including suspend time
        if libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) == 0 {
            let secs = ts.tv_sec as u64;
            let micros = (ts.tv_nsec / 1000) as u32;
            return format!("[{:>5}.{:06}]", secs, micros);
        }
    }
    // Fallback if clock_gettime fails
    "[    ?.??????]".to_string()
}

/// Macro for eprintln with kernel-style timestamp
macro_rules! ktseprintln {
    ($($arg:tt)*) => {
        eprintln!("{} stage1: {}", kts(), format_args!($($arg)*))
    };
}

/// Compute SHA256 hash of one or more byte slices
macro_rules! sha256 {
    ($($item:expr),+ $(,)?) => {{
        let mut hasher = Sha256::new();
        $(hasher.update($item);)+
        <[u8; 32]>::from(hasher.finalize())
    }};
}

/// Check if running as root (UID == 0)
fn is_root() -> bool {
    unsafe { libc::getuid() == 0 }
}

fn is_pid1() -> bool {
    std::process::id() == 1
}

/// Get the appropriate architecture config based on the target architecture
fn get_arch_config(stage2: &Stage2Config) -> Result<&ArchConfig> {
    #[cfg(target_arch = "aarch64")]
    let arch_config = stage2.aarch64.as_ref();

    #[cfg(target_arch = "x86_64")]
    let arch_config = stage2.x86_64.as_ref();

    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    let arch_config: Option<&ArchConfig> = None;

    arch_config.ok_or_else(|| {
        #[cfg(target_arch = "aarch64")]
        return anyhow!("No aarch64 configuration found in _stage2");

        #[cfg(target_arch = "x86_64")]
        return anyhow!("No x86_64 configuration found in _stage2");

        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        return anyhow!("Unsupported architecture");
    })
}

fn poweroff() {
    if is_pid1() {
        unsafe {
            libc::sync();
            thread::sleep(Duration::from_secs(60));
            libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF);
        }
    } else {
        std::process::exit(1);
    }
}

struct ParsedData {
    config: UserData,
    raw_json: Vec<u8>,
}

fn parse_json_to_config(data: Vec<u8>) -> Result<ParsedData> {
    Ok(ParsedData {
        config: serde_json::from_slice(&data).context("Failed to parse JSON")?,
        raw_json: data,
    })
}

/// Merge one arch entry into `_stage2` of an existing (or new) config doc and print it.
fn emit_config(arch: &str, arch_config: ArchConfig, config_file: Option<&str>) -> Result<()> {
    // Read existing config if provided, otherwise start with empty object
    let mut config: serde_json::Value = if let Some(path) = config_file {
        let contents = fs::read_to_string(path)
            .context(format!("Failed to read config file: {}", path))?;
        serde_json::from_str(&contents)
            .context("Failed to parse config JSON")?
    } else {
        serde_json::json!({})
    };

    if !config.is_object() {
        return Err(anyhow!("Config file must contain a JSON object"));
    }

    let config_obj = config.as_object_mut().unwrap();

    // Get or create _stage2 object
    let stage2_value = config_obj
        .entry("_stage2")
        .or_insert_with(|| serde_json::json!({}));

    if !stage2_value.is_object() {
        return Err(anyhow!("_stage2 must be a JSON object"));
    }

    // Add the architecture-specific config
    let stage2_obj = stage2_value.as_object_mut().unwrap();
    stage2_obj.insert(arch.to_string(), serde_json::to_value(arch_config)?);

    println!("{}", serde_json::to_string_pretty(&config)?);
    Ok(())
}

/// sha256-pin config: download the payload, hash it, emit `{url, sha256}`.
fn make_config(arch: &str, url: &str, config_file: Option<&str>) -> Result<()> {
    let binary_data = download_binary(url)?;
    let sha256_hash = hex::encode(sha256!(&binary_data));
    emit_config(
        arch,
        ArchConfig {
            url: UrlList(vec![url.to_string()]),
            sha256: Some(sha256_hash),
            ed25519: None,
            sig_url: None,
            args_url: None,
            args_sig_url: None,
        },
        config_file,
    )
}

/// signed-mode config: emit `{url, ed25519}` pinning the release pubkey. No download —
/// the payload rolls forward; stage1 fetches `<url>.sig` at boot and verifies it.
fn make_config_ed25519(arch: &str, url: &str, pubkey_b64: &str, config_file: Option<&str>) -> Result<()> {
    let arch_config = ArchConfig {
        url: UrlList(vec![url.to_string()]),
        sha256: None,
        ed25519: Some(pubkey_b64.to_string()),
        sig_url: None,
        args_url: None,
        args_sig_url: None,
    };
    // Validate the url + pubkey up front so a bad config fails at generation time.
    arch_config.validate().map_err(|m| anyhow!("invalid ed25519 config: {m}"))?;
    emit_config(arch, arch_config, config_file)
}

/// Quote the pre-exec PCR state, binding the about-to-run binary via extra_data (PCR 14
/// does not yet contain it). Code only — config is deliberately not bound.
fn generate_pre_execution_attestation(binary_data: &[u8]) -> Result<()> {
    let path = format!("{}/stage1.attest", TMP_DIR);
    let contents = tpm::attest(&sha256!(binary_data))?;
    fs::write(&path, contents).context(format!("Failed to write attestation to {}", &path))?;
    Ok(())
}

/// Extend PCR 14 with the stage2 binary hash — the only thing stage1 measures.
fn extend_pcrs(binary_data: &[u8]) -> Result<()> {
    let mut tpm = Tpm::open()?;
    tpm.pcr_extend(PCR_BINARY, &sha256!(binary_data))?;
    Ok(())
}

/// Replace `{sha256}` in each URL with the payload's hex digest (content-addressing).
fn substitute(urls: &[String], hash: &str) -> Vec<String> {
    urls.iter().map(|u| u.replace("{sha256}", hash)).collect()
}

/// Download the first URL that responds (fallback across mirrors for resiliency).
fn download_first(urls: &[String]) -> Result<Vec<u8>> {
    let mut last: Option<anyhow::Error> = None;
    for url in urls {
        match download_binary(url) {
            Ok(bytes) => return Ok(bytes),
            Err(e) => {
                ktseprintln!("url unavailable: {url} ({e:#})");
                last = Some(e);
            }
        }
    }
    Err(last.unwrap_or_else(|| anyhow!("no url provided")))
}

/// Fetch + verify signed remote args (a JSON string array) against `pubkey`, returning
/// argv that overrides inline args. Signature from `args_sig_url`, else `<args_url>.sig`.
fn fetch_signed_args(
    args_url: &UrlList,
    args_sig_url: Option<&UrlList>,
    pubkey: &str,
    payload_hash: &str,
) -> Result<Vec<String>> {
    let args_urls = substitute(&args_url.0, payload_hash);
    let args_sig_urls = match args_sig_url {
        Some(u) => substitute(&u.0, payload_hash),
        None => args_urls.iter().map(|u| format!("{u}.sig")).collect(),
    };
    let args_bytes = download_first(&args_urls)?;
    let signature = download_first(&args_sig_urls)?;
    sig::verify(pubkey, &args_bytes, &signature)
        .map_err(|m| anyhow!("signed args verification failed: {m}"))?;
    let args: Vec<String> = serde_json::from_slice(&args_bytes)
        .context("signed args must be a JSON array of strings")?;
    ktseprintln!("args: {} signed (ed25519)", args.len());
    Ok(args)
}

/// Try each payload URL until one downloads and admits (mirrors are safe — every
/// candidate must still pass the same pin/signature).
fn admit_payload(urls: &[String], mode: &Verify) -> Result<(Vec<u8>, Option<Vec<String>>)> {
    let mut last: Option<anyhow::Error> = None;
    for url in urls {
        match admit_from(url, mode) {
            Ok(result) => return Ok(result),
            Err(e) => {
                ktseprintln!("payload url rejected: {url} ({e:#})");
                last = Some(e);
            }
        }
    }
    Err(last.unwrap_or_else(|| anyhow!("no payload url provided")))
}

/// Download one payload candidate and run admission control (a GATE — never measured).
fn admit_from(url: &str, mode: &Verify) -> Result<(Vec<u8>, Option<Vec<String>>)> {
    let binary = download_binary(url)?;
    let hash = hex::encode(sha256!(&binary));
    let mut signed_args = None;
    match mode {
        Verify::Sha256(expected) => {
            verify_checksum(&binary, expected)?;
            ktseprintln!("verified: sha256:{hash} (sha256 pin)");
        }
        Verify::Ed25519 { pubkey, sig_url, args_url, args_sig_url } => {
            let sig_urls = match sig_url {
                Some(u) => substitute(&u.0, &hash),
                None => vec![format!("{url}.sig")],
            };
            let signature = download_first(&sig_urls)?;
            sig::verify(pubkey, &binary, &signature)
                .map_err(|m| anyhow!("ed25519 verification failed: {m}"))?;
            ktseprintln!("verified: sha256:{hash} (ed25519 key:{pubkey})");
            if let Some(au) = args_url {
                signed_args = Some(fetch_signed_args(au, args_sig_url.as_ref(), pubkey, &hash)?);
            }
        }
    }
    Ok((binary, signed_args))
}

fn stage2(parsed: ParsedData) -> Result<()> {
    let arch_config = get_arch_config(&parsed.config._stage2)?;
    let mode = arch_config
        .validate()
        .map_err(|m| anyhow!("invalid _stage2 config: {m}"))?;

    let (binary_data, signed_args) = admit_payload(&arch_config.url.0, &mode)?;

    if is_root() {
        generate_pre_execution_attestation(&binary_data)?;
        extend_pcrs(&binary_data)?;
    }

    // Signed remote args, when present, override inline args.
    let inline_args = parsed.config._stage2.args.as_deref().unwrap_or(&[]);
    let args: &[String] = signed_args.as_deref().unwrap_or(inline_args);
    execute_binary(&binary_data, args, &parsed.raw_json)?;
    Ok(())
}

fn log_hash(label: &str, data: &[u8]) {
    ktseprintln!("{} sha256={}", label, hex::encode(sha256!(data)));
}

fn http_client() -> Result<Client> {
    // Install rustls-rustcrypto as the default crypto provider (only needs to be done once)
    let _ = CryptoProvider::install_default(rustls_rustcrypto::provider());
    Client::builder()
        .use_rustls_tls()
        .build()
        .context("Failed to build HTTP client")
}

/// Try to fetch user-data from AWS EC2 IMDSv2
fn try_fetch_ec2(client: &Client) -> Result<ParsedData> {
    // IMDSv2: First, obtain a session token
    let token = client
        .put(EC2_TOKEN_URL)
        .header("X-aws-ec2-metadata-token-ttl-seconds", "21600") // 6 hours
        .send()
        .context("Failed to obtain IMDSv2 session token")?
        .text()
        .context("Failed to read IMDSv2 token response")?;
    // IMDSv2: Use the token to fetch user-data
    let body = client
        .get(EC2_METADATA_URL)
        .header("X-aws-ec2-metadata-token", &token)
        .send()
        .context("Failed to fetch EC2 user-data")?
        .bytes()
        .context("Failed to read EC2 user-data response")?
        .to_vec();
    log_hash(EC2_METADATA_URL, &body);
    Ok(parse_json_to_config(body)?)
}

/// Try to fetch user-data from GCP metadata service
/// See: https://cloud.google.com/compute/docs/storing-retrieving-metadata
fn try_fetch_gcp(client: &Client) -> Result<ParsedData> {
    let body = client
        .get(GCP_METADATA_URL)
        .header("Metadata-Flavor", "Google")
        .send()
        .context("Failed to fetch GCP user-data")?
        .bytes()
        .context("Failed to read GCP user-data response")?
        .to_vec();
    log_hash(GCP_METADATA_URL, &body);
    Ok(parse_json_to_config(body)?)
}

/// Try to fetch user-data from Azure IMDS
/// See: https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service?tabs=linux#get-user-data
/// See: https://learn.microsoft.com/en-us/azure/virtual-machines/user-data
fn try_fetch_azure(client: &Client) -> Result<ParsedData> {
    let body = client
        .get(AZURE_METADATA_URL)
        .header("Metadata", "true")
        .send()
        .context("Failed to fetch Azure user-data")?
        .text()
        .context("Failed to read Azure user-data response")?;
    // Azure returns base64-encoded data, so decode it
    let decoded = STANDARD
        .decode(&body)
        .context("Failed to decode base64-encoded Azure user-data")?;
    log_hash(AZURE_METADATA_URL, &decoded);
    let parsed = parse_json_to_config(decoded)?;
    Ok(parsed)
}

/// Try to fetch metadata from all cloud providers
fn fetch_cloud_metadata() -> Result<ParsedData> {
    let client = http_client()?;
    try_fetch_ec2(&client)
        .or_else(|_| try_fetch_gcp(&client))
        .or_else(|_| try_fetch_azure(&client))
        .context("Failed to fetch metadata from any cloud provider (tried EC2, GCP, Azure)")
}

fn fetch_from_url(url: &str) -> Result<Vec<u8>> {
    let body = http_client()?
        .get(url)
        .send()
        .context("Failed to fetch user-data from URL")?
        .bytes()
        .context("Failed to read response from URL")?
        .to_vec();
    log_hash(url, &body);
    Ok(body)
}

fn read_from_file(path: &str) -> Result<Vec<u8>> {
    let data = fs::read(path)
        .context(format!("Failed to read file: {}", path))?;
    log_hash(path, data.as_slice());
    Ok(data)
}

fn download_binary(url: &str) -> Result<Vec<u8>> {
    let client = http_client()?;
    let binary_data = client
        .get(url)
        .send()
        .context("Failed to download binary")?
        .error_for_status()
        .context("Server returned an error status")?
        .bytes()
        .context("Failed to read binary data")?
        .to_vec();
    log_hash(url, binary_data.as_slice());
    Ok(binary_data)
}

fn verify_checksum(data: &[u8], expected_hex: &str) -> Result<()> {
    let actual_hex = hex::encode(sha256!(data));
    if actual_hex.to_lowercase() != expected_hex.to_lowercase() {
        return Err(anyhow!(
            "SHA256 checksum mismatch!\nExpected: {}\nActual:   {}",
            expected_hex, actual_hex));
    }
    Ok(())
}

fn execute_binary(data: &[u8], args: &[String], json_config: &[u8]) -> Result<()> {
    let tmp_path = format!("{}/stage2.exe", TMP_DIR);
    fs::write(&tmp_path, data)
        .context(format!("Failed to write binary to {}", tmp_path))?;

    // Make the binary executable
    let mut perms = fs::metadata(&tmp_path)
        .context("Failed to get file metadata")?
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&tmp_path, perms)
        .context("Failed to set executable permissions")?;

    let json_path = format!("{}/stage2-config.json", TMP_DIR);
    fs::write(&json_path, json_config)
        .context(format!("Failed to write config to {}", json_path))?;

    ktseprintln!("{}: {:?}\n", tmp_path, args);

    let err = Command::new(&tmp_path)
        .args(args)
        .exec();
    Err(anyhow!("Failed to exec binary: {}", err))
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
        assert!(matches!(ac("http://h/p", Some(HASH64), None).validate(), Ok(Verify::Sha256(_))));
    }

    #[test]
    fn https_is_allowed() {
        assert!(ac("https://h/p", Some(HASH64), None).validate().is_ok());
    }

    #[test]
    fn ed25519_mode_ok() {
        let pk = pubkey_b64();
        assert!(matches!(ac("http://h/p", None, Some(&pk)).validate(), Ok(Verify::Ed25519 { .. })));
    }

    #[test]
    fn both_modes_is_error() {
        let pk = pubkey_b64();
        assert!(ac("http://h/p", Some(HASH64), Some(&pk)).validate().is_err());
    }

    #[test]
    fn neither_mode_is_error() {
        assert!(ac("http://h/p", None, None).validate().is_err());
    }

    #[test]
    fn bad_hex_is_error() {
        assert!(ac("http://h/p", Some("zz"), None).validate().is_err());
        let sixtyfour_nonhex = "z".repeat(64);
        assert!(ac("http://h/p", Some(&sixtyfour_nonhex), None).validate().is_err());
    }

    #[test]
    fn bad_pubkey_is_error() {
        assert!(ac("http://h/p", None, Some("not-base64!!")).validate().is_err()); // not base64
        assert!(ac("http://h/p", None, Some("AAAA")).validate().is_err());          // wrong length
    }

    #[test]
    fn non_http_url_is_error() {
        assert!(ac("ftp://h/p", Some(HASH64), None).validate().is_err());
    }

    #[test]
    fn args_url_requires_ed25519() {
        let mut c = ac("http://h/p", Some(HASH64), None);
        c.args_url = Some(UrlList(vec!["http://h/args".into()]));
        assert!(c.validate().is_err());
    }

    #[test]
    fn args_sig_url_requires_args_url() {
        let pk = pubkey_b64();
        let mut c = ac("http://h/p", None, Some(&pk));
        c.args_sig_url = Some(UrlList(vec!["http://h/args.sig".into()]));
        assert!(c.validate().is_err());
    }

    #[test]
    fn urllist_accepts_string_or_array() {
        let one: UrlList = serde_json::from_str(r#""http://a/x""#).unwrap();
        assert_eq!(one.0, vec!["http://a/x".to_string()]);
        let many: UrlList = serde_json::from_str(r#"["http://a/x","http://b/x"]"#).unwrap();
        assert_eq!(many.0, vec!["http://a/x".to_string(), "http://b/x".to_string()]);
        // serializes back as a bare string when single, array when multiple
        assert_eq!(serde_json::to_string(&one).unwrap(), r#""http://a/x""#);
        assert_eq!(serde_json::to_string(&many).unwrap(), r#"["http://a/x","http://b/x"]"#);
    }

    #[test]
    fn url_list_validates_and_rejects_empty() {
        let mut c = ac("http://h/p", Some(HASH64), None);
        c.url = UrlList(vec!["http://h/p".into(), "https://mirror/p".into()]);
        assert!(c.validate().is_ok());
        c.url = UrlList(vec![]);
        assert!(c.validate().is_err());
    }

    #[test]
    fn substitute_replaces_sha256_in_each() {
        let urls = vec!["http://h/{sha256}.sig".to_string(), "http://m/x".to_string()];
        let out = substitute(&urls, "deadbeef");
        assert_eq!(out, vec!["http://h/deadbeef.sig".to_string(), "http://m/x".to_string()]);
    }

    #[test]
    fn parse_ed25519_with_fallback_and_templated_args() {
        let pk = pubkey_b64();
        let json = format!(
            r#"{{"url":["http://a/p","http://b/p"],"ed25519":"{pk}","args_url":"http://a/args-{{sha256}}.json"}}"#
        );
        let c: ArchConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(c.url.0.len(), 2);
        match c.validate().unwrap() {
            Verify::Ed25519 { args_url: Some(a), .. } => assert!(a.0[0].contains("{sha256}")),
            _ => panic!("expected ed25519 mode"),
        }
    }
}
