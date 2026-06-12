// SPDX-License-Identifier: MIT OR Apache-2.0

//! Loading a payload that the UEFI `db` did not sign.
//!
//! Under Secure Boot, DXE core's `LoadImage` does not decide accept/reject
//! itself — it delegates to the architectural security protocols. For a
//! memory-buffer load the authoritative gate is
//! `EFI_SECURITY2_ARCH_PROTOCOL.FileAuthentication`, whose default
//! implementation runs the `db`/`dbx` check and returns `ACCESS_DENIED` for an
//! unsigned image. Older firmware without Security2 falls back to
//! `EFI_SECURITY_ARCH_PROTOCOL.FileAuthenticationState`.
//!
//! These are plain function pointers in boot-services memory. stage0 — already
//! a `db`-signed, measured image — temporarily swaps in an allow-all decision
//! around a single `LoadImage`, then restores it. This is exactly shim's
//! `security_policy_install()`/`uninstall()`: the firmware still does all the
//! real PE loading, relocation and handle setup; only the *verdict* is replaced.
//!
//! stage0 has already verified the buffer (ed25519 signature against the pinned
//! release key, or pinned SHA-256) before we get here, so the trust does not
//! weaken — it moves from the firmware `db` (which is not remotely attestable
//! and, under our ephemeral-key lockdown, cannot sign late-bound payloads) into
//! stage0's own policy. The payload is still measured into PCR 14, so the
//! attestation chain is unbroken: stage0 ran, and it loaded *this* hash.

use uefi::boot::{
    self, LoadImageSource, OpenProtocolAttributes, OpenProtocolParams, ScopedProtocol,
};
use uefi::proto::unsafe_protocol;
use uefi::{Handle, Status};
use uefi_raw::Boolean;

use core::ffi::c_void;

// ---- EFI_SECURITY2_ARCH_PROTOCOL (94ab2f58-...) ----

type Security2FileAuth = unsafe extern "efiapi" fn(
    this: *const c_void,        // EFI_SECURITY2_ARCH_PROTOCOL*
    device_path: *const c_void, // EFI_DEVICE_PATH_PROTOCOL*
    file_buffer: *mut c_void,
    file_size: usize,
    boot_policy: Boolean,
) -> Status;

#[repr(C)]
struct Security2Interface {
    file_authentication: Security2FileAuth,
}

#[unsafe_protocol("94ab2f58-1438-4ef1-9152-18941a3a0e68")]
struct Security2(Security2Interface);

// ---- EFI_SECURITY_ARCH_PROTOCOL, v1 fallback (a46423e3-...) ----

type SecurityFileAuthState = unsafe extern "efiapi" fn(
    this: *const c_void, // EFI_SECURITY_ARCH_PROTOCOL*
    authentication_status: u32,
    file: *const c_void, // EFI_DEVICE_PATH_PROTOCOL*
) -> Status;

#[repr(C)]
struct SecurityInterface {
    file_authentication_state: SecurityFileAuthState,
}

#[unsafe_protocol("a46423e3-4617-49f1-b9ff-d1bfa9115839")]
struct Security(SecurityInterface);

/// allow-all replacement for `Security2.FileAuthentication`.
unsafe extern "efiapi" fn allow_security2(
    _this: *const c_void,
    _device_path: *const c_void,
    _file_buffer: *mut c_void,
    _file_size: usize,
    _boot_policy: Boolean,
) -> Status {
    Status::SUCCESS
}

/// allow-all replacement for `Security.FileAuthenticationState`.
unsafe extern "efiapi" fn allow_security(
    _this: *const c_void,
    _authentication_status: u32,
    _file: *const c_void,
) -> Status {
    Status::SUCCESS
}

/// RAII guard: on construction, replaces the security-arch authentication hooks
/// with allow-all; on drop, restores the originals. The window is kept to a
/// single `LoadImage` call so no other image load is affected.
struct AuthOverride {
    security2: Option<(ScopedProtocol<Security2>, Security2FileAuth)>,
    security: Option<(ScopedProtocol<Security>, SecurityFileAuthState)>,
}

impl AuthOverride {
    fn install() -> Self {
        // EFI_SECURITY2_ARCH_PROTOCOL — authoritative for buffer loads on all
        // modern edk2/OVMF firmware (our targets).
        let security2 = open::<Security2>().map(|mut sp| {
            let iface: *mut Security2Interface = &mut sp.0;
            let saved = unsafe { (*iface).file_authentication };
            unsafe { (*iface).file_authentication = allow_security2 };
            (sp, saved)
        });

        // EFI_SECURITY_ARCH_PROTOCOL — only consulted when Security2 is absent,
        // but override it too so we behave on older firmware.
        let security = open::<Security>().map(|mut sp| {
            let iface: *mut SecurityInterface = &mut sp.0;
            let saved = unsafe { (*iface).file_authentication_state };
            unsafe { (*iface).file_authentication_state = allow_security };
            (sp, saved)
        });

        Self {
            security2,
            security,
        }
    }
}

impl Drop for AuthOverride {
    fn drop(&mut self) {
        if let Some((sp, saved)) = self.security2.as_mut() {
            let iface: *mut Security2Interface = &mut sp.0;
            unsafe { (*iface).file_authentication = *saved };
        }
        if let Some((sp, saved)) = self.security.as_mut() {
            let iface: *mut SecurityInterface = &mut sp.0;
            unsafe { (*iface).file_authentication_state = *saved };
        }
    }
}

/// Open an architectural protocol non-exclusively (it lives for the life of
/// boot services; we only mutate one function pointer in it).
fn open<P: uefi::proto::ProtocolPointer + 'static>() -> Option<ScopedProtocol<P>> {
    let handle = boot::get_handle_for_protocol::<P>().ok()?;
    unsafe {
        boot::open_protocol::<P>(
            OpenProtocolParams {
                handle,
                agent: boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    }
    .ok()
}

/// `LoadImage` a payload from memory, bypassing the Secure Boot `db` check via a
/// temporary security-arch override. The caller MUST have already verified the
/// buffer (signature or pinned hash) — this only relaxes the firmware gate.
pub fn load_image_verified(buffer: &[u8]) -> Result<Handle, Status> {
    let _guard = AuthOverride::install();
    boot::load_image(
        boot::image_handle(),
        LoadImageSource::FromBuffer {
            buffer,
            file_path: None,
        },
    )
    .map_err(|e| e.status())
    // `_guard` drops here, restoring the original authentication hooks.
}
