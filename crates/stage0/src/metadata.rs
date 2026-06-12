// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cloud metadata-service user-data fetching.
//!
//! Mirrors `stage1`'s provider order and endpoints (EC2 IMDSv2 → GCP → Azure),
//! plus a best-effort Aliyun path, using fixed link-local IPs so no DNS is
//! needed to reach the metadata service itself.

use alloc::string::String;
use alloc::vec::Vec;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use crate::http::{is_ok, HttpClient, HttpMethod};
use uefi::{println, Status};

const EC2_TOKEN_URL: &str = "http://169.254.169.254/latest/api/token";
const EC2_USERDATA_URL: &str = "http://169.254.169.254/latest/user-data";
const GCP_USERDATA_URL: &str =
    "http://169.254.169.254/computeMetadata/v1/instance/attributes/user-data";
const AZURE_USERDATA_URL: &str =
    "http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-02-01&format=text";
const ALIYUN_USERDATA_URL: &str = "http://100.100.100.200/latest/user-data";

/// A metadata provider: name + a fetch function returning the raw user-data.
type Provider = fn(&mut HttpClient) -> Result<Vec<u8>, Status>;

/// Try each cloud provider in turn; return the first user-data document found.
pub fn fetch(client: &mut HttpClient) -> Result<Vec<u8>, Status> {
    let providers: [(&str, Provider); 4] = [
        ("EC2 (IMDSv2)", try_ec2),
        ("GCP", try_gcp),
        ("Azure", try_azure),
        ("Aliyun", try_aliyun),
    ];
    for (name, try_fn) in providers {
        println!("stage0: trying metadata provider: {name}");
        match try_fn(client) {
            Ok(data) => {
                println!("stage0:   {name} returned {} bytes", data.len());
                return Ok(data);
            }
            Err(e) => println!("stage0:   {name} failed: {:?}", e),
        }
    }
    println!("stage0: no metadata provider responded");
    Err(Status::NOT_FOUND)
}

/// AWS EC2 IMDSv2: obtain a session token (PUT), then GET user-data.
fn try_ec2(client: &mut HttpClient) -> Result<Vec<u8>, Status> {
    let (status, token) = client.fetch(
        HttpMethod::PUT,
        EC2_TOKEN_URL,
        &[("X-aws-ec2-metadata-token-ttl-seconds", "21600")],
    )?;
    if !is_ok(status) {
        return Err(Status::ABORTED);
    }
    let token = String::from_utf8(token).map_err(|_| Status::ABORTED)?;
    let token = token.trim();

    let (status, body) = client.fetch(
        HttpMethod::GET,
        EC2_USERDATA_URL,
        &[("X-aws-ec2-metadata-token", token)],
    )?;
    if !is_ok(status) {
        return Err(Status::ABORTED);
    }
    Ok(body)
}

/// GCP compute metadata (reachable at the link-local IP; requires the flavor header).
fn try_gcp(client: &mut HttpClient) -> Result<Vec<u8>, Status> {
    let (status, body) = client.fetch(
        HttpMethod::GET,
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
fn try_azure(client: &mut HttpClient) -> Result<Vec<u8>, Status> {
    let (status, body) =
        client.fetch(HttpMethod::GET, AZURE_USERDATA_URL, &[("Metadata", "true")])?;
    if !is_ok(status) {
        return Err(Status::ABORTED);
    }
    let text = String::from_utf8(body).map_err(|_| Status::ABORTED)?;
    STANDARD.decode(text.trim()).map_err(|_| Status::ABORTED)
}

/// Aliyun ECS metadata (best-effort; v1 plain GET of user-data).
fn try_aliyun(client: &mut HttpClient) -> Result<Vec<u8>, Status> {
    let (status, body) = client.fetch(HttpMethod::GET, ALIYUN_USERDATA_URL, &[])?;
    if !is_ok(status) {
        return Err(Status::ABORTED);
    }
    Ok(body)
}
