// SPDX-License-Identifier: MIT OR Apache-2.0

//! Raw `EFI_TCP4_PROTOCOL` transport: connect to an IPv4 host, send a request,
//! and read the whole response until the peer closes. The byte pipe the HTTP/1.1
//! client in `http.rs` rides on; it knows nothing about HTTP.
//!
//! Do NOT replace this with `EFI_HTTP`/HttpDxe: HttpDxe does not drain a
//! multi-segment response body. The whole body arrives and is ACKed by the
//! firmware's TCP stack, but HttpDxe delivers only the first segment and never
//! returns the rest; the `Receive()` loop in [`exchange`] is the step it skips.
//! (HttpDxe also layers on TCP4/DNS4, so TCP4 alone is the more portable subset.)
//!
//! `uefi-raw` 0.11 does not expose TCP4, so the FFI bindings (UEFI spec,
//! EFI_TCP4_PROTOCOL) are defined here.

use alloc::vec;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::ptr;

use uefi::boot::{self, OpenProtocolAttributes, OpenProtocolParams};
use uefi::proto::unsafe_protocol;
use uefi::Status;
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

/// Drive an async token to completion by spinning on its volatile `status` and
/// pumping the driver via `Poll()`, with no inter-poll stall. The TCP4 driver only
/// services the network when `Poll()` runs, so any stall between polls throttles
/// receive throughput to ~one TCP segment per stall, so keep the spin tight. Bounded
/// by a wall-clock `budget_ms` (via the boot clock) so a wedged driver gives up.
unsafe fn pump(tcp: *mut Tcp4Protocol, status: *const Status, budget_ms: u64) -> Status {
    let start = crate::timing::since_boot_ms();
    loop {
        let s = ptr::read_volatile(status);
        if s != Status::NOT_READY {
            return s;
        }
        let _ = ((*tcp).poll)(tcp);
        if crate::timing::since_boot_ms().wrapping_sub(start) >= budget_ms {
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
/// This is the transport primitive the HTTP client in `http.rs` builds on.
pub fn exchange(ip: [u8; 4], port: u16, request: &[u8]) -> Result<Vec<u8>, Status> {
    let nic = boot::get_handle_for_protocol::<Tcp4Sb>().map_err(|e| {
        crate::slog!("stage0:   no EFI_TCP4 service binding: {:?}", e.status());
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
        crate::slog!("stage0:   TCP4 configure failed: {st:?}");
        return Err(st);
    }

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
        crate::slog!("stage0:   TCP4 connect failed: {st:?}");
        let _ = unsafe { ((*tcp_ptr).configure)(tcp_ptr, ptr::null()) };
        return Err(st);
    }
    crate::sdbg!(
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
        crate::slog!("stage0:   TCP4 transmit failed: {st:?}");
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
            // End of stream: peer FIN (clean), reset, or pump timeout. A truncated
            // body is caught downstream by the sha256/size admission check.
            crate::sdbg!("stage0:   TCP4 recv: {} B total", out.len());
            break;
        }
    }
    Ok(out)
}
