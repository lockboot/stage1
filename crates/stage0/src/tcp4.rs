// SPDX-License-Identifier: MIT OR Apache-2.0

//! Minimal HTTP/1.0 client over `EFI_TCP4_PROTOCOL`.
//!
//! OVMF/EDK2's `EFI_HTTP_PROTOCOL` (HttpDxe) will not deliver a multi-segment
//! response body in our usage: packet captures show the whole body arrives and
//! is ACKed by the firmware's TCP stack, but HttpDxe pulls only the first
//! segment and never drains the rest of its receive buffer. (Hardened firmware
//! such as AWS Nitro may additionally refuse plain `http://` via EFI_HTTP when
//! `PcdAllowHttpConnections=FALSE`.) So the payload download drops one layer to
//! raw TCP4 and runs its own `Receive()` loop — the exact step HttpDxe skips.
//!
//! `uefi-raw` 0.11 does not expose TCP4, so the FFI bindings (straight from the
//! UEFI spec, EFI_TCP4_PROTOCOL) are defined here.

use alloc::vec;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::ptr;

use uefi::boot::{self, OpenProtocolAttributes, OpenProtocolParams};
use uefi::proto::unsafe_protocol;
use uefi::{println, Status};
use uefi_raw::protocol::driver::ServiceBindingProtocol;
use uefi_raw::{Boolean, Event, Ipv4Address};

// ---- EFI_TCP4_PROTOCOL FFI (UEFI spec) ----

#[repr(C)]
struct AccessPoint {
    use_default_address: Boolean,
    station_address: Ipv4Address,
    subnet_mask: Ipv4Address,
    station_port: u16,
    remote_address: Ipv4Address,
    remote_port: u16,
    active_flag: Boolean,
}

#[repr(C)]
struct ConfigData {
    type_of_service: u8,
    time_to_live: u8,
    access_point: AccessPoint,
    control_option: *const c_void,
}

#[repr(C)]
struct CompletionToken {
    event: Event,
    status: Status,
}

#[repr(C)]
struct ConnectionToken {
    completion_token: CompletionToken,
}

#[repr(C)]
struct FragmentData {
    fragment_length: u32,
    fragment_buffer: *mut c_void,
}

#[repr(C)]
struct TxData {
    push: Boolean,
    urgent: Boolean,
    data_length: u32,
    fragment_count: u32,
    fragment_table: [FragmentData; 1],
}

#[repr(C)]
struct RxData {
    urgent_flag: Boolean,
    data_length: u32,
    fragment_count: u32,
    fragment_table: [FragmentData; 1],
}

#[repr(C)]
union Packet {
    rx_data: *mut RxData,
    tx_data: *mut TxData,
}

#[repr(C)]
struct IoToken {
    completion_token: CompletionToken,
    packet: Packet,
}

/// `EFI_TCP4_PROTOCOL` method table. Slots we don't call keep the correct
/// order/size but use a placeholder signature (never invoked).
#[repr(C)]
struct Tcp4Protocol {
    get_mode_data: unsafe extern "efiapi" fn() -> Status,
    configure: unsafe extern "efiapi" fn(*mut Tcp4Protocol, *const ConfigData) -> Status,
    routes: unsafe extern "efiapi" fn() -> Status,
    connect: unsafe extern "efiapi" fn(*mut Tcp4Protocol, *mut ConnectionToken) -> Status,
    accept: unsafe extern "efiapi" fn() -> Status,
    transmit: unsafe extern "efiapi" fn(*mut Tcp4Protocol, *mut IoToken) -> Status,
    receive: unsafe extern "efiapi" fn(*mut Tcp4Protocol, *mut IoToken) -> Status,
    close: unsafe extern "efiapi" fn() -> Status,
    cancel: unsafe extern "efiapi" fn() -> Status,
    poll: unsafe extern "efiapi" fn(*mut Tcp4Protocol) -> Status,
}

#[unsafe_protocol("00720665-67eb-4a99-baf7-d3c33a1c7cc9")]
struct Tcp4Sb(ServiceBindingProtocol);

#[unsafe_protocol("65530bc7-a359-410f-b010-5aadc7ec2b62")]
struct Tcp4(Tcp4Protocol);

/// Drive an async token to completion by polling its volatile `status`, pumping
/// the driver via `Poll()` and stalling 1ms between checks. Bounded by `budget_ms`.
unsafe fn pump(tcp: *mut Tcp4Protocol, status: *const Status, budget_ms: u32) -> Status {
    let mut waited = 0;
    loop {
        let s = ptr::read_volatile(status);
        if s != Status::NOT_READY {
            return s;
        }
        let _ = ((*tcp).poll)(tcp);
        boot::stall(1000);
        waited += 1;
        if waited >= budget_ms {
            return Status::TIMEOUT;
        }
    }
}

fn new_event() -> Result<Event, Status> {
    unsafe {
        boot::create_event(
            uefi::boot::EventType::empty(),
            uefi::boot::Tpl::CALLBACK,
            None,
            None,
        )
    }
    .map(|e| e.as_ptr())
    .map_err(|e| e.status())
}

/// Connect to `ip:port`, send `request`, and read the full response until the
/// peer closes the connection (so requests must ask for `Connection: close`).
fn exchange(ip: [u8; 4], port: u16, request: &[u8]) -> Result<Vec<u8>, Status> {
    let nic = boot::get_handle_for_protocol::<Tcp4Sb>().map_err(|e| {
        println!("stage0:   no EFI_TCP4 service binding: {:?}", e.status());
        e.status()
    })?;
    let mut sb = unsafe {
        boot::open_protocol::<Tcp4Sb>(
            OpenProtocolParams {
                handle: nic,
                agent: boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
        .map_err(|e| e.status())?
    };

    let mut child: uefi_raw::Handle = ptr::null_mut();
    let st = unsafe { (sb.0.create_child)(&mut sb.0, &mut child) };
    if st != Status::SUCCESS {
        return Err(st);
    }
    let child_handle = unsafe { uefi::Handle::from_ptr(child).ok_or(Status::DEVICE_ERROR)? };

    let result = exchange_on_child(child_handle, ip, port, request);

    // Tear the TCP4 child down regardless of outcome.
    let _ = unsafe { (sb.0.destroy_child)(&mut sb.0, child) };
    result
}

fn exchange_on_child(
    child: uefi::Handle,
    ip: [u8; 4],
    port: u16,
    request: &[u8],
) -> Result<Vec<u8>, Status> {
    let mut tcp = unsafe {
        boot::open_protocol::<Tcp4>(
            OpenProtocolParams {
                handle: child,
                agent: boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
        .map_err(|e| e.status())?
    };
    let tcp_ptr: *mut Tcp4Protocol = &mut tcp.0;

    // Configure: default (DHCP) station address, active open to ip:port.
    let cfg = ConfigData {
        type_of_service: 0,
        time_to_live: 64,
        access_point: AccessPoint {
            use_default_address: Boolean::from(true),
            station_address: Ipv4Address([0, 0, 0, 0]),
            subnet_mask: Ipv4Address([0, 0, 0, 0]),
            station_port: 0,
            remote_address: Ipv4Address(ip),
            remote_port: port,
            active_flag: Boolean::from(true),
        },
        control_option: ptr::null(),
    };
    let st = unsafe { ((*tcp_ptr).configure)(tcp_ptr, &cfg) };
    if st != Status::SUCCESS {
        println!("stage0:   TCP4 configure failed: {st:?}");
        return Err(st);
    }

    // Connect.
    let event = new_event()?;
    let mut ct = ConnectionToken {
        completion_token: CompletionToken {
            event,
            status: Status::NOT_READY,
        },
    };
    let st = unsafe { ((*tcp_ptr).connect)(tcp_ptr, &mut ct) };
    let st = if st == Status::SUCCESS {
        unsafe { pump(tcp_ptr, &ct.completion_token.status, 10_000) }
    } else {
        st
    };
    let _ = unsafe { uefi::Event::from_ptr(event).map(boot::close_event) };
    if st != Status::SUCCESS {
        println!("stage0:   TCP4 connect failed: {st:?}");
        let _ = unsafe { ((*tcp_ptr).configure)(tcp_ptr, ptr::null()) };
        return Err(st);
    }
    println!(
        "stage0:   TCP4 connected to {}.{}.{}.{}:{}",
        ip[0], ip[1], ip[2], ip[3], port
    );

    let send_res = tcp_send(tcp_ptr, request);
    let recv_res = send_res.and_then(|()| tcp_recv_all(tcp_ptr));

    // Reset the instance (also closes the connection).
    let _ = unsafe { ((*tcp_ptr).configure)(tcp_ptr, ptr::null()) };
    recv_res
}

fn tcp_send(tcp_ptr: *mut Tcp4Protocol, data: &[u8]) -> Result<(), Status> {
    let mut tx = TxData {
        push: Boolean::from(true),
        urgent: Boolean::from(false),
        data_length: data.len() as u32,
        fragment_count: 1,
        fragment_table: [FragmentData {
            fragment_length: data.len() as u32,
            fragment_buffer: data.as_ptr() as *mut c_void,
        }],
    };
    let event = new_event()?;
    let mut tok = IoToken {
        completion_token: CompletionToken {
            event,
            status: Status::NOT_READY,
        },
        packet: Packet { tx_data: &mut tx },
    };
    let st = unsafe { ((*tcp_ptr).transmit)(tcp_ptr, &mut tok) };
    let st = if st == Status::SUCCESS {
        unsafe { pump(tcp_ptr, &tok.completion_token.status, 10_000) }
    } else {
        st
    };
    let _ = unsafe { uefi::Event::from_ptr(event).map(boot::close_event) };
    if st != Status::SUCCESS {
        println!("stage0:   TCP4 transmit failed: {st:?}");
        return Err(st);
    }
    Ok(())
}

fn tcp_recv_all(tcp_ptr: *mut Tcp4Protocol) -> Result<Vec<u8>, Status> {
    let mut out: Vec<u8> = Vec::new();
    loop {
        let mut buf = vec![0u8; 32 * 1024];
        let mut rx = RxData {
            urgent_flag: Boolean::from(false),
            data_length: buf.len() as u32,
            fragment_count: 1,
            fragment_table: [FragmentData {
                fragment_length: buf.len() as u32,
                fragment_buffer: buf.as_mut_ptr().cast(),
            }],
        };
        let event = new_event()?;
        let mut tok = IoToken {
            completion_token: CompletionToken {
                event,
                status: Status::NOT_READY,
            },
            packet: Packet { rx_data: &mut rx },
        };
        let call = unsafe { ((*tcp_ptr).receive)(tcp_ptr, &mut tok) };
        let st = if call == Status::SUCCESS {
            unsafe { pump(tcp_ptr, &tok.completion_token.status, 10_000) }
        } else {
            call
        };
        let _ = unsafe { uefi::Event::from_ptr(event).map(boot::close_event) };

        if st == Status::SUCCESS {
            let got = (rx.data_length as usize).min(buf.len());
            if got == 0 {
                break;
            }
            out.extend_from_slice(&buf[..got]);
        } else {
            // EFI_CONNECTION_FIN / reset / timeout — peer closed or done.
            break;
        }
    }
    Ok(out)
}

/// Download `url` over raw TCP4 and return the response body. The host may be an
/// IPv4 literal or a name resolved over EFI_DNS4. Uses `Connection: close` so the
/// body is delimited by the peer closing.
pub fn download(url: &str) -> Result<Vec<u8>, Status> {
    let (host, port, path) = parse_http_url(url).ok_or_else(|| {
        println!("stage0:   TCP4 download: unsupported URL (need http://host[:port]/path): {url}");
        Status::INVALID_PARAMETER
    })?;

    // IPv4 literal connects directly; a hostname is resolved over EFI_DNS4.
    let ip = match parse_ipv4(host) {
        Some(ip) => ip,
        None => crate::dns4::resolve(host)?,
    };

    let mut req = alloc::string::String::new();
    req.push_str("GET ");
    req.push_str(path);
    req.push_str(" HTTP/1.1\r\nHost: ");
    req.push_str(host);
    req.push_str("\r\nConnection: close\r\nUser-Agent: stage0\r\n\r\n");
    println!("stage0:   TCP4 GET {url}");

    let raw = exchange(ip, port, req.as_bytes())?;
    println!("stage0:   TCP4 received {} bytes total", raw.len());

    // Split headers/body on the blank line.
    let sep = find_subslice(&raw, b"\r\n\r\n").ok_or_else(|| {
        println!("stage0:   TCP4 response had no header terminator");
        Status::PROTOCOL_ERROR
    })?;
    let head = &raw[..sep];
    let body = raw[sep + 4..].to_vec();

    // Status line: "HTTP/1.x NNN ..."
    let status_ok = head
        .split(|&b| b == b'\n')
        .next()
        .map(|line| find_subslice(line, b" 200 ").is_some() || line.ends_with(b" 200"))
        .unwrap_or(false);
    if !status_ok {
        let line = core::str::from_utf8(head.split(|&b| b == b'\n').next().unwrap_or(b""))
            .unwrap_or("<non-utf8>");
        println!("stage0:   TCP4 non-200 status: {}", line.trim_end());
        return Err(Status::ABORTED);
    }
    Ok(body)
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
