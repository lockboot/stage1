// SPDX-License-Identifier: MIT OR Apache-2.0

//! Hostname resolution over `EFI_DNS4_PROTOCOL`.
//!
//! Metadata is reached at fixed link-local IPs, but a payload URL may name a host
//! (e.g. an S3/GCS bucket). The HTTP client (`http.rs`) calls [`resolve`] for any
//! non-literal host, turning it into an IPv4 address before the TCP connect.
//!
//! The DNS instance is configured statically from the IPv4 lease `http.rs` already
//! established (station address + DHCP-provided DNS server list, read from
//! `EFI_IP4_CONFIG2`). Do NOT switch to `UseDefaultSetting = TRUE`: it makes the
//! DNS driver bring its own IP4/UDP4 child up via a second DHCP, multiple seconds
//! for a query that resolves in milliseconds. `uefi-raw` 0.11 does not expose DNS4,
//! so the FFI bindings (UEFI spec, EFI_DNS4_PROTOCOL) are defined here.

use alloc::vec::Vec;
use core::ffi::c_void;
use core::ptr;

use uefi::boot::{self, OpenProtocolAttributes, OpenProtocolParams};
use uefi::proto::network::ip4config2::Ip4Config2;
use uefi::proto::unsafe_protocol;
use uefi::{CString16, Status};
use uefi_raw::protocol::driver::ServiceBindingProtocol;
use uefi_raw::protocol::network::ip4_config2::Ip4Config2DataType;
use uefi_raw::{Boolean, Event, Ipv4Address};

// ---- EFI_DNS4_PROTOCOL FFI (UEFI spec) ----

#[repr(C)]
struct Dns4ConfigData {
    dns_server_list_count: usize,
    dns_server_list: *mut Ipv4Address,
    use_default_setting: Boolean,
    enable_dns_cache: Boolean,
    protocol: u8,
    station_ip: Ipv4Address,
    subnet_mask: Ipv4Address,
    local_port: u16,
    retry_count: u32,
    retry_interval: u32,
}

#[repr(C)]
struct Dns4CompletionToken {
    event: Event,
    status: Status,
    retry_count: u32,
    retry_interval: u32,
    // Union of response pointers; for HostNameToIp it is the H2AData pointer.
    rsp_data: *mut Dns4HostToAddrData,
}

#[repr(C)]
struct Dns4HostToAddrData {
    ip_count: u32,
    ip_list: *mut Ipv4Address,
}

/// `EFI_DNS4_PROTOCOL` method table. Unused slots keep the spec order/size but
/// a placeholder signature (never invoked).
#[repr(C)]
struct Dns4Protocol {
    get_mode_data: unsafe extern "efiapi" fn() -> Status,
    configure: unsafe extern "efiapi" fn(*mut Dns4Protocol, *const Dns4ConfigData) -> Status,
    host_name_to_ip: unsafe extern "efiapi" fn(
        *mut Dns4Protocol,
        *const u16,
        *mut Dns4CompletionToken,
    ) -> Status,
    ip_to_host_name: unsafe extern "efiapi" fn() -> Status,
    general_lookup: unsafe extern "efiapi" fn() -> Status,
    update_dns_cache: unsafe extern "efiapi" fn() -> Status,
    poll: unsafe extern "efiapi" fn(*mut Dns4Protocol) -> Status,
    cancel: unsafe extern "efiapi" fn() -> Status,
}

#[unsafe_protocol("b625b186-e063-44f7-8905-6a74dc6f52b4")]
struct Dns4Sb(ServiceBindingProtocol);

#[unsafe_protocol("ae3d28cc-e05b-4fa1-a011-7eb55a3f1401")]
struct Dns4(Dns4Protocol);

/// EFI_IP_PROTO_UDP: DNS queries ride UDP.
const IP_PROTO_UDP: u8 = 17;

/// Spin on the token's volatile `status`, pumping the driver via `Poll()` with no
/// inter-poll stall (see the matching note in `tcp4::pump`). Bounded by a real
/// wall-clock `budget_ms` via the boot clock.
unsafe fn pump(dns: *mut Dns4Protocol, status: *const Status, budget_ms: u64) -> Status {
    let start = crate::timing::since_boot_ms();
    loop {
        let s = ptr::read_volatile(status);
        if s != Status::NOT_READY {
            return s;
        }
        let _ = ((*dns).poll)(dns);
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

/// The DHCP lease `http.rs` already established: station address plus DNS server
/// list. Reused so the DNS instance can configure statically (see module docs).
struct Ip4Lease {
    dns_servers: Vec<Ipv4Address>,
    station_ip: Ipv4Address,
    subnet_mask: Ipv4Address,
}

/// Read the existing IPv4 lease (address + DHCP-provided DNS servers) from
/// `EFI_IP4_CONFIG2` on the NIC. `None` if anything is missing; the caller then
/// falls back to letting the DNS driver bring up its own setting.
fn ip4_lease() -> Option<Ip4Lease> {
    let handle = boot::get_handle_for_protocol::<Ip4Config2>().ok()?;
    let mut ip4 = Ip4Config2::new(handle).ok()?;
    let info = ip4.get_interface_info().ok()?;
    // DNS_SERVER data is a packed array of EFI_IPv4_ADDRESS (4 bytes each).
    let dns_servers: Vec<Ipv4Address> = ip4
        .get_data(Ip4Config2DataType::DNS_SERVER)
        .ok()?
        .chunks_exact(4)
        .map(|c| Ipv4Address([c[0], c[1], c[2], c[3]]))
        .collect();
    if dns_servers.is_empty() || info.station_addr.0 == [0, 0, 0, 0] {
        return None;
    }
    Some(Ip4Lease {
        dns_servers,
        station_ip: info.station_addr,
        subnet_mask: info.subnet_mask,
    })
}

/// Resolve `host` to an IPv4 address using the DHCP-provided DNS servers.
pub fn resolve(host: &str) -> Result<[u8; 4], Status> {
    crate::sdbg!("stage0:   EFI_DNS4 resolving {host}");
    let sb_handle = boot::get_handle_for_protocol::<Dns4Sb>().map_err(|e| {
        crate::slog!("stage0:   no EFI_DNS4 service binding: {:?}", e.status());
        e.status()
    })?;
    let mut sb = unsafe {
        boot::open_protocol::<Dns4Sb>(
            OpenProtocolParams {
                handle: sb_handle,
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
        crate::slog!("stage0:   EFI_DNS4 create_child failed: {st:?}");
        return Err(st);
    }
    let child_handle = unsafe { uefi::Handle::from_ptr(child).ok_or(Status::DEVICE_ERROR)? };

    let result = resolve_on_child(child_handle, host);

    let _ = unsafe { (sb.0.destroy_child)(&mut sb.0, child) };
    result
}

fn resolve_on_child(child: uefi::Handle, host: &str) -> Result<[u8; 4], Status> {
    let mut dns = unsafe {
        boot::open_protocol::<Dns4>(
            OpenProtocolParams {
                handle: child,
                agent: boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
        .map_err(|e| e.status())?
    };
    let dns_ptr: *mut Dns4Protocol = &mut dns.0;

    // Static config from the existing lease (see module docs). `lease` must outlive
    // `configure`, since `cfg` borrows its DNS-server Vec by raw pointer.
    let lease = ip4_lease();
    let cfg = match &lease {
        Some(l) => Dns4ConfigData {
            dns_server_list_count: l.dns_servers.len(),
            dns_server_list: l.dns_servers.as_ptr() as *mut Ipv4Address,
            use_default_setting: Boolean::from(false),
            enable_dns_cache: Boolean::from(false),
            protocol: IP_PROTO_UDP,
            station_ip: l.station_ip,
            subnet_mask: l.subnet_mask,
            local_port: 0,
            retry_count: 2,
            retry_interval: 0,
        },
        // No readable lease: fall back to UseDefaultSetting (driver does its own DHCP).
        None => Dns4ConfigData {
            dns_server_list_count: 0,
            dns_server_list: ptr::null_mut(),
            use_default_setting: Boolean::from(true),
            enable_dns_cache: Boolean::from(false),
            protocol: IP_PROTO_UDP,
            station_ip: Ipv4Address([0, 0, 0, 0]),
            subnet_mask: Ipv4Address([0, 0, 0, 0]),
            local_port: 0,
            retry_count: 2,
            retry_interval: 0,
        },
    };
    let st = unsafe { ((*dns_ptr).configure)(dns_ptr, &cfg) };
    if st != Status::SUCCESS {
        crate::slog!("stage0:   EFI_DNS4 configure failed: {st:?} (no DHCP-provided DNS server?)");
        return Err(st);
    }
    crate::sdbg!(
        "stage0:   EFI_DNS4 configured ({}), sending query",
        if lease.is_some() { "static, reusing lease" } else { "UseDefaultSetting" }
    );

    let name = CString16::try_from(host).map_err(|_| Status::INVALID_PARAMETER)?;
    let event = new_event()?;
    let mut token = Dns4CompletionToken {
        event,
        status: Status::NOT_READY,
        retry_count: 0,
        retry_interval: 0,
        rsp_data: ptr::null_mut(),
    };
    let call = unsafe { ((*dns_ptr).host_name_to_ip)(dns_ptr, name.as_ptr().cast(), &mut token) };
    let st = if call == Status::SUCCESS {
        unsafe { pump(dns_ptr, &token.status, 10_000) }
    } else {
        call
    };
    let _ = unsafe { uefi::Event::from_ptr(event).map(boot::close_event) };

    // Reset the instance regardless of outcome.
    let _ = unsafe { ((*dns_ptr).configure)(dns_ptr, ptr::null()) };

    if st != Status::SUCCESS {
        crate::slog!("stage0:   EFI_DNS4 HostNameToIp({host}) failed: {st:?}");
        return Err(st);
    }

    let h2a = token.rsp_data;
    if h2a.is_null() {
        crate::slog!("stage0:   EFI_DNS4 returned no response data for {host}");
        return Err(Status::DEVICE_ERROR);
    }
    let ip = unsafe {
        let data = &*h2a;
        if data.ip_count == 0 || data.ip_list.is_null() {
            free_h2a(h2a);
            crate::slog!("stage0:   EFI_DNS4 found no addresses for {host}");
            return Err(Status::NOT_FOUND);
        }
        (*data.ip_list).0
    };
    unsafe { free_h2a(h2a) };
    crate::sdbg!(
        "stage0:   resolved {host} -> {}.{}.{}.{}",
        ip[0], ip[1], ip[2], ip[3]
    );
    Ok(ip)
}

/// Free the driver-allocated response data (the IP list and the struct itself).
unsafe fn free_h2a(h2a: *mut Dns4HostToAddrData) {
    let data = &*h2a;
    if let Some(p) = ptr::NonNull::new(data.ip_list.cast::<c_void>()) {
        let _ = boot::free_pool(p.cast());
    }
    if let Some(p) = ptr::NonNull::new(h2a.cast::<c_void>()) {
        let _ = boot::free_pool(p.cast());
    }
}
