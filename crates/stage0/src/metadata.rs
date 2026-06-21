// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cloud metadata-service user-data fetching.
//!
//! Mirrors `stage1`'s provider order and endpoints (EC2 IMDSv2 → GCP → Azure),
//! plus a best-effort Aliyun path, using fixed link-local IPs so no DNS is
//! needed to reach the metadata service itself. Requests go over the raw-TCP4
//! HTTP client ([`crate::http`]); the network must be brought up first.

use alloc::string::String;
use alloc::vec::Vec;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use sha2::{Digest, Sha256};

use crate::http::{self, is_ok, HttpMethod};
use uefi::Status;

const EC2_TOKEN_URL: &str = "http://169.254.169.254/latest/api/token";
const EC2_USERDATA_URL: &str = "http://169.254.169.254/latest/user-data";
const GCP_USERDATA_URL: &str =
    "http://169.254.169.254/computeMetadata/v1/instance/attributes/user-data";
const AZURE_USERDATA_URL: &str =
    "http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-02-01&format=text";
const ALIYUN_USERDATA_URL: &str = "http://100.100.100.200/latest/user-data";

/// A metadata provider: name + a fetch function returning the raw user-data.
type Provider = fn() -> Result<Vec<u8>, Status>;

/// Try each cloud provider in turn; return the first user-data document found.
pub fn fetch() -> Result<Vec<u8>, Status> {
    let providers: [(&str, Provider); 4] = [
        ("EC2 (IMDSv2)", try_ec2),
        ("GCP", try_gcp),
        ("Azure", try_azure),
        ("Aliyun", try_aliyun),
    ];
    for (name, try_fn) in providers {
        crate::sdbg!("stage0:   trying metadata provider: {name}");
        match try_fn() {
            Ok(data) => {
                let h = hex::encode(Sha256::digest(&data));
                crate::slog!("stage0: metadata: {name} {} bytes sha256:{h}", data.len());
                return Ok(data);
            }
            Err(e) => crate::sdbg!("stage0:   {name} failed: {:?}", e),
        }
    }
    crate::slog!("stage0: no metadata provider responded");
    Err(Status::NOT_FOUND)
}

/// AWS EC2 IMDSv2: obtain a session token (PUT), then GET user-data.
fn try_ec2() -> Result<Vec<u8>, Status> {
    let (status, token) = http::fetch(
        HttpMethod::Put,
        EC2_TOKEN_URL,
        &[("X-aws-ec2-metadata-token-ttl-seconds", "21600")],
    )?;
    if !is_ok(status) {
        return Err(Status::ABORTED);
    }
    let token = String::from_utf8(token).map_err(|_| Status::ABORTED)?;
    let token = token.trim();

    let (status, body) = http::fetch(
        HttpMethod::Get,
        EC2_USERDATA_URL,
        &[("X-aws-ec2-metadata-token", token)],
    )?;
    if !is_ok(status) {
        return Err(Status::ABORTED);
    }
    Ok(body)
}

/// GCP compute metadata (reachable at the link-local IP; requires the flavor header).
fn try_gcp() -> Result<Vec<u8>, Status> {
    let (status, body) = http::fetch(
        HttpMethod::Get,
        GCP_USERDATA_URL,
        &[
            ("Metadata-Flavor", "Google"),
            ("Host", "metadata.google.internal"),
        ],
    )?;
    if !is_ok(status) {
        return Err(Status::ABORTED);
    }
    Ok(body)
}

/// Azure IMDS: user-data is returned base64-encoded.
fn try_azure() -> Result<Vec<u8>, Status> {
    let (status, body) = http::fetch(HttpMethod::Get, AZURE_USERDATA_URL, &[("Metadata", "true")])?;
    if !is_ok(status) {
        return Err(Status::ABORTED);
    }
    let text = String::from_utf8(body).map_err(|_| Status::ABORTED)?;
    STANDARD.decode(text.trim()).map_err(|_| Status::ABORTED)
}

/// Aliyun ECS metadata (best-effort; v1 plain GET of user-data).
fn try_aliyun() -> Result<Vec<u8>, Status> {
    let (status, body) = http::fetch(HttpMethod::Get, ALIYUN_USERDATA_URL, &[])?;
    if !is_ok(status) {
        return Err(Status::ABORTED);
    }
    Ok(body)
}
