// SPDX-License-Identifier: MIT OR Apache-2.0

//! Minimal HTTP/1.0 client over `EFI_HTTP_PROTOCOL`.
//!
//! uefi-rs ships an `HttpHelper`, but its request path only emits a `Host`
//! header. The cloud metadata services need custom headers (IMDSv2 token,
//! `Metadata-Flavor`, `Metadata: true`) and the EC2 token handshake needs
//! `PUT`, so we drive the raw `Http` protocol directly.
//!
//! Integrity of downloaded payloads comes from the SHA-256 pinned in the
//! (trusted) metadata document, so plain HTTP is sufficient and we avoid the
//! inconsistently-available `EFI_TLS_PROTOCOL`.

use alloc::ffi::CString;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::ffi::{c_char, c_void, CStr};

use uefi::boot::{
    self, EventType, OpenProtocolAttributes, OpenProtocolParams, ScopedProtocol, TimerTrigger, Tpl,
};
use uefi::proto::network::http::{Http, HttpBinding};
use uefi::proto::network::ip4config2::Ip4Config2;
use uefi::{println, CString16, Event, Handle, Status};
use uefi_raw::protocol::network::http::{
    HttpAccessPoint, HttpConfigData, HttpHeader, HttpMessage, HttpRequestData, HttpResponseData,
    HttpStatusCode, HttpToken, HttpV4AccessPoint, HttpVersion,
};

pub use uefi_raw::protocol::network::http::HttpMethod;

/// Body is read one TCP segment at a time. Packet captures show OVMF's HttpDxe
/// pulls exactly one segment into a `Response()` body buffer and then stalls
/// unless the buffer is full (or Content-Length is reached) — it will not drain
/// further buffered segments within one call. Sizing the buffer to one MSS
/// (1460 = 1500 MTU − 20 IP − 20 TCP) makes each `Response()` fill exactly and
/// complete, so a loop drains the whole body one segment per call.
const CHUNK: usize = 1460;

/// Per-request timeout reported to the HTTP driver (milliseconds).
const HTTP_TIMEOUT_MS: u32 = 8_000;

/// Hard wall-clock cap for a single request/response token, in 100ns units.
/// A bit longer than HTTP_TIMEOUT_MS so the driver's own timeout fires first;
/// this only guards against a driver that never completes the token at all.
const POLL_DEADLINE_100NS: u64 = 12 * 10_000_000; // 12 seconds

/// An HTTP connection bound to one NIC, configured for IPv4 + DHCP.
pub struct HttpClient {
    child: Handle,
    binding: ScopedProtocol<HttpBinding>,
    // `Option` so the protocol is dropped before we destroy the child handle.
    http: Option<ScopedProtocol<Http>>,
}

impl HttpClient {
    /// Find a NIC with the HTTP service binding, bring it up via DHCP, and
    /// create a configured HTTP protocol instance on it.
    pub fn new() -> Result<Self, Status> {
        // On a fresh boot the firmware often hasn't connected the network stack
        // yet, so the HTTP service binding isn't present. Connect all drivers
        // first, then locate the binding.
        connect_all_controllers();

        let nic = match boot::get_handle_for_protocol::<HttpBinding>() {
            Ok(h) => h,
            Err(e) => {
                println!(
                    "stage0:   no EFI_HTTP service binding found ({:?}) -- firmware lacks the HTTP/network stack?",
                    e.status()
                );
                return Err(e.status());
            }
        };
        println!("stage0:   found HTTP service binding on NIC handle");

        // Bring the interface up (DHCP). No-op if already up.
        {
            let mut ip4 = Ip4Config2::new(nic).map_err(|e| e.status())?;
            ip4.ifup(true).map_err(|e| {
                println!("stage0:   DHCP failed: {:?}", e.status());
                e.status()
            })?;
        }

        let mut binding = unsafe {
            boot::open_protocol::<HttpBinding>(
                OpenProtocolParams {
                    handle: nic,
                    agent: boot::image_handle(),
                    controller: None,
                },
                OpenProtocolAttributes::GetProtocol,
            )
            .map_err(|e| e.status())?
        };

        let child = binding.create_child().map_err(|e| e.status())?;

        let mut http = unsafe {
            boot::open_protocol::<Http>(
                OpenProtocolParams {
                    handle: child,
                    agent: boot::image_handle(),
                    controller: None,
                },
                OpenProtocolAttributes::GetProtocol,
            )
            .map_err(|e| {
                let _ = binding.destroy_child(child);
                e.status()
            })?
        };

        let ip4 = HttpV4AccessPoint {
            use_default_addr: true.into(),
            ..Default::default()
        };
        let config = HttpConfigData {
            http_version: HttpVersion::HTTP_VERSION_10,
            time_out_millisec: HTTP_TIMEOUT_MS,
            local_addr_is_ipv6: false.into(),
            access_point: HttpAccessPoint { ipv4_node: &ip4 },
        };
        http.configure(&config).map_err(|e| {
            println!("stage0:   HTTP configure failed: {:?}", e.status());
            e.status()
        })?;
        println!("stage0:   HTTP protocol configured");

        Ok(Self {
            child,
            binding,
            http: Some(http),
        })
    }

    fn http(&mut self) -> &mut Http {
        self.http.as_mut().unwrap()
    }

    /// Send one HTTP request (does not read the response).
    fn send_request(
        &mut self,
        method: HttpMethod,
        url: &str,
        headers: &[(&str, &str)],
    ) -> Result<(), Status> {
        println!("stage0:   HTTP {:?} {}", method, url);
        let url16 = CString16::try_from(url).map_err(|_| Status::INVALID_PARAMETER)?;

        // Backing storage for the header C strings; must outlive the request.
        // Always send a Host header (servers reject requests without one) unless
        // the caller already supplied one.
        let mut cstrings: Vec<(CString, CString)> = Vec::with_capacity(headers.len() + 1);
        let has_host = headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("host"));
        if !has_host {
            if let Some(host) = host_from_url(url) {
                cstrings.push((
                    CString::new("Host").map_err(|_| Status::INVALID_PARAMETER)?,
                    CString::new(host).map_err(|_| Status::INVALID_PARAMETER)?,
                ));
            }
        }
        for (name, value) in headers {
            cstrings.push((
                CString::new(*name).map_err(|_| Status::INVALID_PARAMETER)?,
                CString::new(*value).map_err(|_| Status::INVALID_PARAMETER)?,
            ));
        }
        let mut hdrs: Vec<HttpHeader> = cstrings
            .iter()
            .map(|(name, value)| HttpHeader {
                field_name: name.as_ptr().cast::<u8>(),
                field_value: value.as_ptr().cast::<u8>(),
            })
            .collect();

        let mut req = HttpRequestData {
            method,
            url: url16.as_ptr().cast::<u16>(),
        };
        let mut tx_msg = HttpMessage::default();
        tx_msg.data.request = &mut req;
        tx_msg.header_count = hdrs.len();
        tx_msg.header = hdrs.as_mut_ptr();

        let event = make_wait_event()?;
        let mut tx_token = HttpToken {
            event: event.as_ptr(),
            status: Status::NOT_READY,
            message: &mut tx_msg,
        };
        let res = self
            .http()
            .request(&mut tx_token)
            .map_err(|e| {
                println!("stage0:     request() rejected: {:?}", e.status());
                e.status()
            })
            .and_then(|()| self.await_completion(&tx_token, &event, "request"));
        let _ = boot::close_event(unsafe { event.unsafe_clone() });
        res?;
        if tx_token.status != Status::SUCCESS {
            println!("stage0:     request failed: {:?}", tx_token.status);
            return Err(tx_token.status);
        }
        Ok(())
    }

    /// Read the first part of the response: status, headers (Content-Length),
    /// and up to `cap` body bytes. Mirrors uefi-rs `HttpHelper::response_first`.
    fn read_first(
        &mut self,
        cap: usize,
    ) -> Result<(HttpStatusCode, Option<usize>, Vec<u8>), Status> {
        let mut rsp = HttpResponseData {
            status_code: HttpStatusCode::STATUS_UNSUPPORTED,
        };
        let mut buf = vec![0u8; cap];
        let mut rx_msg = HttpMessage::default();
        rx_msg.data.response = &mut rsp;
        rx_msg.body_length = buf.len();
        rx_msg.body = buf.as_mut_ptr().cast::<c_void>();
        let event = make_wait_event()?;
        let mut rx_token = HttpToken {
            event: event.as_ptr(),
            status: Status::NOT_READY,
            message: &mut rx_msg,
        };
        let res = self
            .http()
            .response(&mut rx_token)
            .map_err(|e| e.status())
            .and_then(|()| self.await_completion(&rx_token, &event, "response"));
        let _ = boot::close_event(unsafe { event.unsafe_clone() });
        res?;
        // HTTP_ERROR means a response with a non-2xx status; still inspectable.
        if rx_token.status != Status::SUCCESS && rx_token.status != Status::HTTP_ERROR {
            println!("stage0:     response failed: {:?}", rx_token.status);
            return Err(rx_token.status);
        }
        let status_code = rsp.status_code;
        let content_length = parse_content_length(&rx_msg);
        let got = rx_msg.body_length;
        println!(
            "stage0:     response {:?}, content-length={:?}, first {} B",
            status_code, content_length, got
        );
        Ok((status_code, content_length, buf[..got].to_vec()))
    }

    /// Read up to `cap` more body bytes. Mirrors `HttpHelper::response_more`.
    fn read_more(&mut self, cap: usize) -> Result<Vec<u8>, Status> {
        let mut buf = vec![0u8; cap];
        let mut rx_msg = HttpMessage {
            body_length: buf.len(),
            body: buf.as_mut_ptr().cast::<c_void>(),
            ..Default::default()
        };
        let event = make_wait_event()?;
        let mut rx_token = HttpToken {
            event: event.as_ptr(),
            status: Status::NOT_READY,
            message: &mut rx_msg,
        };
        let res = self
            .http()
            .response(&mut rx_token)
            .map_err(|e| e.status())
            .and_then(|()| self.await_completion(&rx_token, &event, "response-more"));
        let _ = boot::close_event(unsafe { event.unsafe_clone() });
        res?;
        if rx_token.status != Status::SUCCESS {
            return Ok(Vec::new());
        }
        Ok(buf[..rx_msg.body_length].to_vec())
    }

    /// Send a request and read the whole response body in 16 KiB chunks — the
    /// multi-segment-safe pattern uefi-rs's HttpHelper uses. Returns (status, body).
    pub fn fetch(
        &mut self,
        method: HttpMethod,
        url: &str,
        headers: &[(&str, &str)],
    ) -> Result<(HttpStatusCode, Vec<u8>), Status> {
        self.send_request(method, url, headers)?;
        let (status, content_length, mut body) = self.read_first(CHUNK)?;

        // Pull the rest in chunks until we've read Content-Length bytes. We stop
        // as soon as we have enough, so we never issue a Response() with nothing
        // left to deliver (that would block until the timeout).
        if let Some(total) = content_length {
            while body.len() < total {
                let chunk = self.read_more(CHUNK)?;
                if chunk.is_empty() {
                    break;
                }
                body.extend_from_slice(&chunk);
                println!("stage0:     body {}/{} B", body.len(), total);
            }
        }
        Ok((status, body))
    }

    /// Block until the async HTTP token completes, driven by the firmware's
    /// event loop rather than a tight `poll()` spin. The token carries a wait
    /// event that HttpDxe signals on completion; `WaitForEvent` lets the
    /// network stack's timer/MNP events fire (which a busy poll loop can starve).
    /// Bounded by a one-shot timer so a wedged driver can't hang the loader.
    fn await_completion(&self, token: &HttpToken, event: &Event, what: &str) -> Result<(), Status> {
        let timer = unsafe { boot::create_event(EventType::TIMER, Tpl::CALLBACK, None, None) }
            .map_err(|e| e.status())?;
        if let Err(e) = boot::set_timer(&timer, TimerTrigger::Relative(POLL_DEADLINE_100NS)) {
            let _ = boot::close_event(timer);
            return Err(e.status());
        }

        let result = loop {
            if token.status != Status::NOT_READY {
                break Ok(());
            }
            let mut events = [unsafe { event.unsafe_clone() }, unsafe {
                timer.unsafe_clone()
            }];
            match boot::wait_for_event(&mut events) {
                Ok(0) => {} // completion event signaled; re-check token.status
                Ok(_) => {
                    println!("stage0:     [{what}] TIMEOUT (event wait)");
                    break Err(Status::TIMEOUT);
                }
                Err(e) => break Err(e.status()),
            }
        };

        let _ = boot::set_timer(&timer, TimerTrigger::Cancel);
        let _ = boot::close_event(timer);
        result
    }
}

/// Create a plain, waitable event for an async HTTP token (no notify function,
/// so it can be passed to `WaitForEvent`; HttpDxe signals it on completion).
fn make_wait_event() -> Result<Event, Status> {
    unsafe { boot::create_event(EventType::empty(), Tpl::CALLBACK, None, None) }
        .map_err(|e| e.status())
}

/// Connect all drivers to all handles (best-effort), forcing the firmware to
/// bind its network stack so the HTTP service binding becomes available even on
/// the first boot before BDS has connected everything.
fn connect_all_controllers() {
    let handles = match boot::locate_handle_buffer(boot::SearchType::AllHandles) {
        Ok(h) => h,
        Err(e) => {
            println!("stage0:   locate_handle_buffer failed: {:?}", e.status());
            return;
        }
    };
    let mut connected = 0usize;
    for handle in handles.iter() {
        if boot::connect_controller(*handle, None, None, true).is_ok() {
            connected += 1;
        }
    }
    println!(
        "stage0:   connected drivers on {}/{} handles",
        connected,
        handles.len()
    );
}

impl Drop for HttpClient {
    fn drop(&mut self) {
        // Protocol must be closed before the child handle is destroyed.
        self.http = None;
        let _ = self.binding.destroy_child(self.child);
    }
}

/// `true` if the status code is 200 OK.
#[must_use]
pub fn is_ok(status: HttpStatusCode) -> bool {
    status == HttpStatusCode::STATUS_200_OK
}

/// Extract the authority (`host[:port]`) from an `http://host/...` URL.
fn host_from_url(url: &str) -> Option<&str> {
    // "http://HOST/path" -> split on '/' -> ["http:", "", "HOST", "path", ...]
    url.split('/').nth(2).filter(|h| !h.is_empty())
}

/// Parse the `Content-Length` response header, if present.
fn parse_content_length(msg: &HttpMessage) -> Option<usize> {
    for i in 0..msg.header_count {
        unsafe {
            let h = &*msg.header.add(i);
            let name = CStr::from_ptr(h.field_name.cast::<c_char>())
                .to_str()
                .ok()?;
            if name.eq_ignore_ascii_case("content-length") {
                let value = CStr::from_ptr(h.field_value.cast::<c_char>())
                    .to_str()
                    .ok()?;
                return value.trim().parse::<usize>().ok();
            }
        }
    }
    None
}

/// Collect the response headers as lowercased name/value pairs (unused by the
/// happy path but handy for diagnostics).
#[allow(dead_code)]
fn collect_headers(msg: &HttpMessage) -> Vec<(String, String)> {
    let mut headers = Vec::new();
    for i in 0..msg.header_count {
        unsafe {
            let h = &*msg.header.add(i);
            let name = CStr::from_ptr(h.field_name.cast::<c_char>());
            let value = CStr::from_ptr(h.field_value.cast::<c_char>());
            if let (Ok(n), Ok(v)) = (name.to_str(), value.to_str()) {
                headers.push((n.to_lowercase(), String::from(v)));
            }
        }
    }
    headers
}
