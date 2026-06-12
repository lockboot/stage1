// SPDX-License-Identifier: MIT OR Apache-2.0

//! TPM access from UEFI via `EFI_TCG2_PROTOCOL`.
//!
//! `vaportpm-attest` speaks raw TPM 2.0 command/response blocks through its
//! [`TpmTransport`] trait. Here we provide a transport that ships those blocks
//! over the firmware's `EFI_TCG2_PROTOCOL.SubmitCommand`, so the exact same
//! `pcr_extend` logic that `stage1` runs against `/dev/tpmrm0` on Linux runs
//! unchanged here — keeping a single measurement (and verification) model.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use anyhow::{anyhow, bail, Result};
use uefi::boot;
use uefi::boot::ScopedProtocol;
use uefi::proto::tcg::v2::Tcg;
use vaportpm_attest::{Tpm, TpmTransport};

/// A [`TpmTransport`] backed by `EFI_TCG2_PROTOCOL`.
struct Tcg2Transport {
    tcg: ScopedProtocol<Tcg>,
    max_response_size: usize,
}

impl TpmTransport for Tcg2Transport {
    fn transmit_raw(&mut self, command: &[u8]) -> Result<Vec<u8>> {
        // Size the response buffer to the firmware-reported maximum.
        let mut out = vec![0u8; self.max_response_size.max(64)];
        self.tcg
            .submit_command(command, &mut out)
            .map_err(|e| anyhow!("EFI_TCG2 SubmitCommand failed: {:?}", e.status()))?;

        // The actual response length lives in the TPM response header
        // (bytes 2..6, big-endian). Truncate to it.
        if out.len() < 10 {
            bail!("TPM response buffer too small ({} bytes)", out.len());
        }
        let size = u32::from_be_bytes([out[2], out[3], out[4], out[5]]) as usize;
        if size < 10 || size > out.len() {
            bail!("invalid TPM response size {}", size);
        }
        out.truncate(size);
        Ok(out)
    }
}

/// Locate the TPM and return a [`Tpm`] context bound to the TCG2 transport.
///
/// Fails closed: if no TCG2 protocol is present or the TPM is reported absent,
/// returns an error rather than booting an unmeasured payload.
pub fn open_tpm() -> Result<Tpm> {
    let handle = boot::get_handle_for_protocol::<Tcg>()
        .map_err(|e| anyhow!("no EFI_TCG2_PROTOCOL: {:?}", e.status()))?;
    let mut tcg = boot::open_protocol_exclusive::<Tcg>(handle)
        .map_err(|e| anyhow!("open EFI_TCG2_PROTOCOL: {:?}", e.status()))?;

    let cap = tcg
        .get_capability()
        .map_err(|e| anyhow!("TCG2 get_capability: {:?}", e.status()))?;
    if !cap.tpm_present() {
        bail!("TCG2 reports no TPM present");
    }
    let max_response_size = cap.max_response_size as usize;

    Ok(Tpm::with_transport(Box::new(Tcg2Transport {
        tcg,
        max_response_size,
    })))
}
