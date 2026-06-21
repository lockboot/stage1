// SPDX-License-Identifier: MIT OR Apache-2.0

//! Minimal HTTP/1.1 client for stage0, built directly on the raw `EFI_TCP4`
//! transport ([`crate::tcp4`]) plus `EFI_DNS4` resolution ([`crate::dns4`]), not
//! `EFI_HTTP`/HttpDxe. HttpDxe is avoided for two reasons: it does not drain a
//! multi-segment response body (see `tcp4.rs`), and as the optional HTTP-Boot
//! driver it is the network protocol least likely to be present on a given
//! firmware (e.g. Azure's). It also layers on TCP4/DNS4, so depending on those
//! directly is the more portable subset. TLS is intentionally not handled: stage0
//! admits payloads by pinned sha256 / ed25519, so transport security is not
//! load-bearing. Network bring-up (drivers + DHCP) lives in [`crate::net`].

use alloc::string::String;
use alloc::vec::Vec;

use uefi::Status;

use crate::tcp4;

/// HTTP request method. Only GET/PUT are used (the IMDSv2 token fetch is a PUT).
#[derive(Clone, Copy, Debug)]
pub enum HttpMethod {
    Get,
    Put,
}

impl HttpMethod {
    fn as_str(self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Put => "PUT",
        }
    }
}

/// `true` for a 2xx status code.
#[must_use]
pub fn is_ok(status: u16) -> bool {
    (200..300).contains(&status)
}

/// Perform one HTTP/1.1 request over TCP4 and return `(status, body)`. A hostname
/// is resolved via `EFI_DNS4`; an IPv4 literal connects directly. The request asks
/// for `Connection: close`, so the body is delimited by the peer closing. A `Host`
/// header in `headers` overrides the URL-derived one (used for GCP metadata).
pub fn fetch(
    method: HttpMethod,
    url: &str,
    headers: &[(&str, &str)],
) -> Result<(u16, Vec<u8>), Status> {
    let (host, port, path) = parse_http_url(url).ok_or_else(|| {
        crate::slog!("stage0:   unsupported URL (need http://host[:port]/path): {url}");
        Status::INVALID_PARAMETER
    })?;

    let ip = match parse_ipv4(host) {
        Some(ip) => ip,
        None => crate::dns4::resolve(host)?,
    };

    let mut req = String::new();
    req.push_str(method.as_str());
    req.push(' ');
    req.push_str(path);
    req.push_str(" HTTP/1.1\r\n");
    // Caller's Host wins (servers reject requests without one); else derive it.
    if !headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("host")) {
        req.push_str("Host: ");
        req.push_str(host);
        req.push_str("\r\n");
    }
    for (name, value) in headers {
        req.push_str(name);
        req.push_str(": ");
        req.push_str(value);
        req.push_str("\r\n");
    }
    req.push_str("Connection: close\r\nUser-Agent: stage0\r\n\r\n");
    crate::sdbg!("stage0:   HTTP {} {url}", method.as_str());

    let raw = tcp4::exchange(ip, port, req.as_bytes())?;

    let sep = find_subslice(&raw, b"\r\n\r\n").ok_or_else(|| {
        crate::slog!("stage0:   response had no header terminator");
        Status::PROTOCOL_ERROR
    })?;
    let status = parse_status_code(&raw[..sep]).ok_or_else(|| {
        crate::slog!("stage0:   could not parse HTTP status line");
        Status::PROTOCOL_ERROR
    })?;
    let body = raw[sep + 4..].to_vec();
    crate::sdbg!("stage0:     response {status}, {} body bytes", body.len());
    Ok((status, body))
}

/// GET `url`, require a 2xx status, and return the body. Used for the payload.
pub fn download(url: &str) -> Result<Vec<u8>, Status> {
    let (status, body) = fetch(HttpMethod::Get, url, &[])?;
    if !is_ok(status) {
        crate::slog!("stage0:   download got non-2xx status {status}");
        return Err(Status::ABORTED);
    }
    Ok(body)
}

/// Parse the numeric status from an `HTTP/1.x NNN Reason` status line (the first
/// line of `head`).
fn parse_status_code(head: &[u8]) -> Option<u16> {
    let line = head.split(|&b| b == b'\n').next()?;
    let line = core::str::from_utf8(line).ok()?;
    line.split_whitespace().nth(1)?.parse::<u16>().ok()
}

/// Parse `http://<host>[:port]/<path>` → (host, port, path). The host may be an
/// IPv4 literal or a name (resolved by the caller via EFI_DNS4).
fn parse_http_url(url: &str) -> Option<(&str, u16, &str)> {
    let rest = url.strip_prefix("http://")?;
    let slash = rest.find('/').unwrap_or(rest.len());
    let authority = &rest[..slash];
    let path = if slash < rest.len() {
        &rest[slash..]
    } else {
        "/"
    };
    let (host, port) = match authority.split_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().ok()?),
        None => (authority, 80),
    };
    Some((host, port, path))
}

fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let mut octets = [0u8; 4];
    let mut parts = s.split('.');
    for o in octets.iter_mut() {
        *o = parts.next()?.parse::<u8>().ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(octets)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
