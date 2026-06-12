// SPDX-License-Identifier: MIT OR Apache-2.0

//! Hostname resolution over `EFI_DNS4_PROTOCOL`.
//!
//! Metadata is reached at fixed link-local IPs, but a payload URL may name a
//! host (e.g. an S3/GCS bucket). `tcp4::download` calls [`resolve`] for any
//! non-literal host, turning it into an IPv4 address before the TCP connect.
//!
//! The DNS server list is taken from DHCP (`UseDefaultSetting = TRUE`), the same
//! lease `http.rs` established to fetch metadata. `uefi-raw` 0.11 does not expose
//! DNS4, so the FFI bindings (UEFI spec, EFI_DNS4_PROTOCOL) are defined here.

use core::ffi::c_void;
use core::ptr;

use uefi::boot::{self, OpenProtocolAttributes, OpenProtocolParams};
use uefi::proto::unsafe_protocol;
use uefi::{println, CString16, Status};
use uefi_raw::protocol::driver::ServiceBindingProtocol;
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

/// EFI_IP_PROTO_UDP — DNS queries ride UDP.
const IP_PROTO_UDP: u8 = 17;

unsafe fn pump(dns: *mut Dns4Protocol, status: *const Status, budget_ms: u32) -> Status {
    let mut waited = 0;
    loop {
        let s = ptr::read_volatile(status);
        if s != Status::NOT_READY {
            return s;
        }
        let _ = ((*dns).poll)(dns);
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

/// Resolve `host` to an IPv4 address using the DHCP-provided DNS servers.
pub fn resolve(host: &str) -> Result<[u8; 4], Status> {
    let sb_handle = boot::get_handle_for_protocol::<Dns4Sb>().map_err(|e| {
        println!("stage0:   no EFI_DNS4 service binding: {:?}", e.status());
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
        println!("stage0:   EFI_DNS4 create_child failed: {st:?}");
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

    // Configure with the DHCP-obtained DNS server list (same lease as metadata).
    let cfg = Dns4ConfigData {
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
    };
    let st = unsafe { ((*dns_ptr).configure)(dns_ptr, &cfg) };
    if st != Status::SUCCESS {
        println!("stage0:   EFI_DNS4 configure failed: {st:?} (no DHCP-provided DNS server?)");
        return Err(st);
    }

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
        println!("stage0:   EFI_DNS4 HostNameToIp({host}) failed: {st:?}");
        return Err(st);
    }

    let h2a = token.rsp_data;
    if h2a.is_null() {
        println!("stage0:   EFI_DNS4 returned no response data for {host}");
        return Err(Status::DEVICE_ERROR);
    }
    let ip = unsafe {
        let data = &*h2a;
        if data.ip_count == 0 || data.ip_list.is_null() {
            free_h2a(h2a);
            println!("stage0:   EFI_DNS4 found no addresses for {host}");
            return Err(Status::NOT_FOUND);
        }
        (*data.ip_list).0
    };
    unsafe { free_h2a(h2a) };
    println!(
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
