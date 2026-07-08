// SPDX-License-Identifier: MIT OR Apache-2.0

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use bytes::Bytes;
use metadata::{Manifest, Profile, UrlList, UserData, Verify};
use reqwest::blocking::Client;
use rustls::crypto::CryptoProvider;
use sha2::{Digest, Sha256};
use vaportpm_attest::{PcrOps, Tpm};
use vaportpm_attest as tpm;
use std::ffi::CString;
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStringExt;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const EC2_TOKEN_URL: &str = "http://169.254.169.254/latest/api/token";
const EC2_METADATA_URL: &str = "http://169.254.169.254/latest/user-data";
const GCP_METADATA_URL: &str = "http://metadata.google.internal/computeMetadata/v1/instance/attributes/user-data";
const AZURE_METADATA_URL: &str = "http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-02-01&format=text";
const TMP_DIR: &str = "/tmp";

// stage1 measures only loaded code: PCR 14 = SHA-256 of the stage2 binary, nothing else.
// Config (and the admission pin/key) is left for the app to measure if it cares.
const PCR_BINARY: u8 = 14;

fn main() {
    // Single failure path: any error OR panic converges on `poweroff()`. As PID 1 an
    // unhandled panic aborts into a kernel panic and skips the log-drain wait; route it
    // through the same shutdown so it fails closed and its logs reach the serial console.
    std::panic::set_hook(Box::new(|info| {
        eprintln!("stage1: PANIC: {info}");
        let _ = io::stderr().flush();
        poweroff();
    }));

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
    // A user-data document piped on stdin wins over everything (the Unix way): stage0
    // passes no args to stage1, and stage1 takes no config flags -- pipe whatever you
    // want in (`stage1 < user-data.json`). In production, PID 1's stdin is the console
    // (a tty), so this is skipped and the cloud metadata service is used instead.
    if let Some(bytes) = stdin_config()? {
        return stage2(parse_json_to_config(bytes)?);
    }

    // --attest is a standalone diagnostic (print a TPM attestation and exit).
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--attest") {
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

    // Default (and the PID-1 boot path): fetch the user-data doc from cloud metadata.
    stage2(fetch_cloud_metadata()?)
}

/// A user-data document piped on stdin, or `None` when nothing is piped. Only reads when
/// fd 0 is a pipe or a regular file -- never a tty/char device (the PID-1 console) -- so
/// it can never block waiting for input that will not come.
fn stdin_config() -> Result<Option<Vec<u8>>> {
    let fd = io::stdin().as_raw_fd();
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Ok(None);
    }
    let kind = st.st_mode as u32 & libc::S_IFMT as u32;
    if kind != libc::S_IFREG as u32 && kind != libc::S_IFIFO as u32 {
        return Ok(None); // tty / char device / socket -> not a piped config
    }
    let mut buf = Vec::new();
    io::stdin().read_to_end(&mut buf).context("read config from stdin")?;
    if buf.is_empty() {
        return Ok(None);
    }
    log_hash("stdin", &buf);
    Ok(Some(buf))
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
fn download_first(urls: &[String]) -> Result<Bytes> {
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

/// Admit the payload. sha256 mode downloads from the inline `url` and checks the pin; ed25519
/// mode fetches + verifies a signed manifest, then admits the payload by the manifest's hash.
/// Returns the payload bytes, the manifest's `args` (ed25519 only), and the verified manifest
/// (so the caller can merge it into the doc handed to stage2 on stdin).
fn admit_payload(
    mode: &Verify,
    sha256_urls: Option<&UrlList>,
) -> Result<(Bytes, Option<Vec<String>>, Option<Manifest>)> {
    match mode {
        Verify::Sha256(expected) => {
            let urls = sha256_urls.ok_or_else(|| anyhow!("sha256 mode requires url"))?;
            let binary = admit_by_hash(&urls.0, expected)?;
            Ok((binary, None, None))
        }
        Verify::Ed25519 { pubkey, manifest_url, manifest_sig_url } => {
            // One signed manifest binds the payload hash + args under one key, so a hostile
            // mirror can neither mix-and-match nor swap the payload.
            let manifest = fetch_manifest(pubkey, manifest_url, manifest_sig_url.as_ref())?;
            let urls = substitute(&manifest.url.0, &manifest.sha256);
            let binary = admit_by_hash(&urls, &manifest.sha256)?;
            let args = manifest.args.clone();
            Ok((binary, args, Some(manifest)))
        }
    }
}

/// Try each mirror until one downloads and matches `expected` (content is pinned, so any mirror
/// yielding the right bytes is acceptable).
fn admit_by_hash(urls: &[String], expected: &str) -> Result<Bytes> {
    let mut last: Option<anyhow::Error> = None;
    for url in urls {
        match download_binary(url).and_then(|b| {
            verify_checksum(&b, expected)?;
            ktseprintln!("verified: sha256:{}", hex::encode(sha256!(&b)));
            Ok(b)
        }) {
            Ok(binary) => return Ok(binary),
            Err(e) => {
                ktseprintln!("payload url rejected: {url} ({e:#})");
                last = Some(e);
            }
        }
    }
    Err(last.unwrap_or_else(|| anyhow!("no payload url provided")))
}

/// Fetch + verify the signed release manifest (ed25519 mode). Tries each `manifest_url` mirror;
/// a candidate is accepted only if it downloads, its detached signature verifies against
/// `pubkey`, and it parses as a valid [`Manifest`]. The signature comes from `manifest_sig_url`
/// (`{sha256}` -> the retrieved manifest's digest), else `<manifest_url>.sig`.
fn fetch_manifest(
    pubkey: &str,
    manifest_url: &UrlList,
    manifest_sig_url: Option<&UrlList>,
) -> Result<Manifest> {
    let mut last: Option<anyhow::Error> = None;
    for murl in &manifest_url.0 {
        match try_fetch_manifest(pubkey, murl, manifest_sig_url) {
            Ok(m) => return Ok(m),
            Err(e) => {
                ktseprintln!("manifest rejected: {murl} ({e:#})");
                last = Some(e);
            }
        }
    }
    Err(last.unwrap_or_else(|| anyhow!("no manifest url provided")))
}

fn try_fetch_manifest(
    pubkey: &str,
    murl: &str,
    manifest_sig_url: Option<&UrlList>,
) -> Result<Manifest> {
    let bytes = download_binary(murl)?;
    let mhash = hex::encode(sha256!(&bytes));
    let sig_urls = match manifest_sig_url {
        Some(u) => substitute(&u.0, &mhash),
        None => vec![format!("{murl}.sig")],
    };
    let signature = download_first(&sig_urls)?;
    ed25519_sign::verify(pubkey, &bytes, &signature)
        .map_err(|m| anyhow!("manifest verification failed: {m}"))?;
    let manifest = Manifest::parse(&bytes, Profile::Stage1)
        .map_err(|m| anyhow!("invalid manifest: {m}"))?;
    ktseprintln!(
        "manifest verified (sha256:{}, version {}, ed25519 key:{pubkey})",
        manifest.sha256,
        manifest.version
    );
    Ok(manifest)
}

fn stage2(parsed: ParsedData) -> Result<()> {
    let stage2 = parsed
        .config
        .stage2
        .as_ref()
        .ok_or_else(|| anyhow!("no _stage2 section in user-data"))?;
    let arch_config = stage2
        .for_this_arch()
        .ok_or_else(|| anyhow!("no _stage2 config for this architecture"))?;
    let mode = arch_config
        .validate(Profile::Stage1)
        .map_err(|m| anyhow!("invalid _stage2 config: {m}"))?;

    let (binary_data, manifest_args, manifest) = admit_payload(&mode, arch_config.url.as_ref())?;

    if is_root() {
        generate_pre_execution_attestation(&binary_data)?;
        extend_pcrs(&binary_data)?;
    }

    // argv: the signed manifest's args (ed25519 mode) override inline `_stage2.args`.
    let inline_args = stage2.args.as_deref().unwrap_or(&[]);
    let args: &[String] = manifest_args.as_deref().unwrap_or(inline_args);

    // stdin: the received user-data with the verified manifest merged into `_stage2.<arch>`
    // (sha256 mode passes the doc through unchanged). Top-level operator keys pass through.
    let stdin_config = build_stdin_config(&parsed.raw_json, manifest.as_ref())?;
    execute_binary(&binary_data, args, &stdin_config)?;
    Ok(())
}

/// The doc handed to stage2 on stdin. In ed25519 mode the verified manifest is merged
/// **additively** into `_stage2.<arch>` (the `{ed25519, manifest_url}` pointer stays; `url` /
/// `sha256` / `args` / `version` are added), so the payload sees resolved, release-signed values
/// alongside the operator's top-level keys. In sha256 mode the received doc is returned unchanged.
fn build_stdin_config(raw_json: &[u8], manifest: Option<&Manifest>) -> Result<Vec<u8>> {
    let manifest = match manifest {
        Some(m) => m,
        None => return Ok(raw_json.to_vec()),
    };
    let mut doc: serde_json::Value =
        serde_json::from_slice(raw_json).context("re-parse user-data for manifest merge")?;
    let arch = if cfg!(target_arch = "aarch64") { "aarch64" } else { "x86_64" };
    let entry = doc
        .get_mut("_stage2")
        .and_then(|s| s.get_mut(arch))
        .and_then(|e| e.as_object_mut())
        .ok_or_else(|| anyhow!("_stage2.{arch} object vanished on re-parse"))?;
    let merged = serde_json::to_value(manifest).context("serialize manifest for merge")?;
    for (k, v) in merged.as_object().expect("Manifest serializes to an object") {
        entry.insert(k.clone(), v.clone());
    }
    serde_json::to_vec(&doc).context("re-serialize merged user-data")
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

fn download_binary(url: &str) -> Result<Bytes> {
    let client = http_client()?;
    // reqwest already owns the body as `Bytes`; hand it back as-is (no extra copy).
    let binary_data = client
        .get(url)
        .send()
        .context("Failed to download binary")?
        .error_for_status()
        .context("Server returned an error status")?
        .bytes()
        .context("Failed to read binary data")?;
    log_hash(url, &binary_data);
    Ok(binary_data)
}

fn verify_checksum(data: &[u8], expected_hex: &str) -> Result<()> {
    let actual_hex = hex::encode(sha256!(data));
    if actual_hex.to_lowercase() != expected_hex.to_lowercase() {
        return Err(anyhow!(
            "SHA256 checksum mismatch!\nExpected: {}\nActual:   {}",
            expected_hex, actual_hex
        ));
    }
    Ok(())
}

// Linux 6.3+: ask for an executable memfd explicitly (hardened kernels default new
// memfds to non-executable). Older kernels reject the flag with EINVAL, so we retry
// without it. Kept local because older libc releases don't export the constant.
const MFD_EXEC: libc::c_uint = 0x0010;

/// Stage bytes into an anonymous in-memory file (never a named path). When `seal`, the
/// contents are made immutable (F_SEAL_WRITE) so they cannot change after this returns;
/// when `exec`, the file is created executable.
fn make_memfd(name: &str, data: &[u8], seal: bool, exec: bool) -> Result<OwnedFd> {
    let cname = CString::new(name).expect("memfd name has no interior NUL");
    let base: libc::c_uint = libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING;
    let mut raw = unsafe { libc::memfd_create(cname.as_ptr(), base | if exec { MFD_EXEC } else { 0 }) };
    if raw < 0 && exec && io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
        // Pre-6.3 kernel: no MFD_EXEC. New memfds are executable by default there.
        raw = unsafe { libc::memfd_create(cname.as_ptr(), base) };
    }
    if raw < 0 {
        return Err(io::Error::last_os_error()).context("memfd_create");
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    let mut rest = data;
    while !rest.is_empty() {
        let n = unsafe {
            libc::write(fd.as_raw_fd(), rest.as_ptr() as *const libc::c_void, rest.len())
        };
        if n < 0 {
            return Err(io::Error::last_os_error()).context("write to memfd");
        }
        rest = &rest[n as usize..];
    }

    if seal {
        // No writable mmap is outstanding (we only wrote via write(2)), so F_SEAL_WRITE
        // takes. SHRINK/GROW/SEAL lock the size and the seal set itself.
        let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_ADD_SEALS, seals) } < 0 {
            return Err(io::Error::last_os_error()).context("F_ADD_SEALS on payload");
        }
    }
    Ok(fd)
}

/// Build a NULL-terminated C array from owned CStrings (the CStrings must outlive it).
fn null_terminated(v: &[CString]) -> Vec<*const libc::c_char> {
    v.iter().map(|c| c.as_ptr()).chain(std::iter::once(std::ptr::null())).collect()
}

/// Exec the stage2 payload from a sealed, anonymous memfd (nothing on any named path):
/// the bytes measured into PCR 14 are sealed immutable and are exactly what runs. Config
/// (the raw user-data JSON) is delivered on stdin from a second memfd -- a universal
/// channel that needs no extra-fd convention (which trips up runtimes like Bun/Node
/// single-file executables) and, being an in-memory file, has no pipe-size limit.
fn execute_binary(data: &[u8], args: &[String], json_config: &[u8]) -> Result<()> {
    let exe = make_memfd("stage2", data, /*seal=*/ true, /*exec=*/ true)?;

    let cfg = make_memfd("stage2-config", json_config, false, false)?;
    if unsafe { libc::lseek(cfg.as_raw_fd(), 0, libc::SEEK_SET) } < 0 {
        return Err(io::Error::last_os_error()).context("rewind config memfd");
    }
    if unsafe { libc::dup2(cfg.as_raw_fd(), 0) } < 0 {
        return Err(io::Error::last_os_error()).context("wire config memfd to stdin");
    }

    // argv[0] = "stage2", then the (signed or inline) args; envp = inherited environment.
    let argv_owned: Vec<CString> = std::iter::once("stage2".to_string())
        .chain(args.iter().cloned())
        .map(|s| CString::new(s).map_err(|_| anyhow!("stage2 argument has an interior NUL")))
        .collect::<Result<_>>()?;
    let envp_owned: Vec<CString> = std::env::vars_os()
        .filter_map(|(k, v)| {
            let mut kv = k;
            kv.push("=");
            kv.push(v);
            CString::new(kv.into_vec()).ok()
        })
        .collect();
    let argv = null_terminated(&argv_owned);
    let envp = null_terminated(&envp_owned);
    let empty = CString::new("").unwrap();

    ktseprintln!("exec stage2 (sealed memfd, config on stdin): {:?}", args);

    // execveat(fd, "", ..., AT_EMPTY_PATH) execs the fd directly -- no /proc dependency,
    // unlike glibc's fexecve fallback. Only returns on failure.
    unsafe {
        libc::syscall(
            libc::SYS_execveat,
            exe.as_raw_fd(),
            empty.as_ptr(),
            argv.as_ptr(),
            envp.as_ptr(),
            libc::AT_EMPTY_PATH,
        );
    }
    Err(anyhow!("execveat stage2 failed: {}", io::Error::last_os_error()))
}
