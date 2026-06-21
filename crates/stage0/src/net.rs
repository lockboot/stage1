// SPDX-License-Identifier: MIT OR Apache-2.0

//! Link/IP-layer network bring-up: connect the firmware's network drivers and
//! obtain a DHCP lease, so the TCP4 transport, DNS4, and HTTP client can assume
//! the interface is addressed. Nothing here is HTTP-specific.

use uefi::boot;
use uefi::proto::network::ip4config2::Ip4Config2;
use uefi::Status;
use uefi_raw::protocol::network::ip4_config2::Ip4Config2Policy;

/// How often to poll for the DHCP lease. Fine-grained so bring-up returns promptly
/// (the crate's `ifup` polls at 1s granularity); small enough that the firmware's
/// IP4/DHCP timers still run during the stall.
const DHCP_POLL_INTERVAL_MS: u64 = 10;
/// Give up on DHCP after this long.
const DHCP_TIMEOUT_MS: u64 = 30_000;

/// Bring the network up: connect the firmware's drivers, then obtain a DHCP lease.
/// Call once before any networking.
pub fn bringup() -> Result<(), Status> {
    connect_all_controllers();
    let nic = boot::get_handle_for_protocol::<Ip4Config2>().map_err(|e| {
        crate::slog!(
            "stage0:   no EFI_IP4_CONFIG2 (firmware lacks the IPv4 stack?): {:?}",
            e.status()
        );
        e.status()
    })?;
    let mut ip4 = Ip4Config2::new(nic).map_err(|e| e.status())?;
    dhcp_up(&mut ip4)
}

/// Bring the interface up via DHCP and wait for the lease, polling at
/// [`DHCP_POLL_INTERVAL_MS`]. The DHCP exchange itself is firmware-paced; this just
/// returns the instant the lease lands. No-op if the interface is already addressed.
fn dhcp_up(ip4: &mut Ip4Config2) -> Result<(), Status> {
    let addr = |a: uefi_raw::Ipv4Address| a.0;
    let info = ip4.get_interface_info().map_err(|e| e.status())?;
    if addr(info.station_addr) != [0, 0, 0, 0] {
        let a = addr(info.station_addr);
        crate::slog!("stage0: network: OK {}.{}.{}.{} (already up)", a[0], a[1], a[2], a[3]);
        return Ok(());
    }

    ip4.set_policy(Ip4Config2Policy::DHCP).map_err(|e| {
        crate::slog!("stage0:   DHCP set-policy failed: {:?}", e.status());
        e.status()
    })?;

    let start = crate::timing::since_boot_ms();
    loop {
        boot::stall((DHCP_POLL_INTERVAL_MS * 1000) as usize);
        let info = ip4.get_interface_info().map_err(|e| e.status())?;
        let a = addr(info.station_addr);
        if a != [0, 0, 0, 0] {
            let took = crate::timing::since_boot_ms().wrapping_sub(start);
            crate::slog!("stage0: network: OK {}.{}.{}.{} (DHCP {took} ms)", a[0], a[1], a[2], a[3]);
            return Ok(());
        }
        if crate::timing::since_boot_ms().wrapping_sub(start) >= DHCP_TIMEOUT_MS {
            crate::slog!("stage0:   DHCP timed out after {DHCP_TIMEOUT_MS} ms");
            return Err(Status::TIMEOUT);
        }
    }
}

/// Connect all drivers to all handles (best-effort), forcing the firmware to bind
/// its network stack so the TCP4/IP4 service bindings become available even on the
/// first boot before BDS has connected everything.
fn connect_all_controllers() {
    let handles = match boot::locate_handle_buffer(boot::SearchType::AllHandles) {
        Ok(h) => h,
        Err(e) => {
            crate::slog!("stage0:   locate_handle_buffer failed: {:?}", e.status());
            return;
        }
    };
    let mut connected = 0usize;
    for handle in handles.iter() {
        if boot::connect_controller(*handle, None, None, true).is_ok() {
            connected += 1;
        }
    }
    crate::sdbg!(
        "stage0:   connected drivers on {}/{} handles",
        connected,
        handles.len()
    );
}
