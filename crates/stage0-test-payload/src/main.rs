// SPDX-License-Identifier: MIT OR Apache-2.0

//! A trivial UEFI payload for exercising the stage0 netboot path end to end.
//!
//! When chain-loaded by stage0 it prints a banner and reads back PCR 14 (the
//! payload measurement) over `EFI_TCG2_PROTOCOL`, proving the
//! measure-then-execute flow worked. PCR 15 is read too and should be all-zero,
//! confirming stage0 measures only the binary. A real payload would instead set
//! up and boot its own OS.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use anyhow::{anyhow, bail, Result};
use uefi::boot::{self, ScopedProtocol};
use uefi::prelude::*;
use uefi::println;
use uefi::proto::tcg::v2::Tcg;
use vaportpm_attest::{PcrOps, TpmAlg, TpmTransport};

struct Tcg2Transport {
    tcg: ScopedProtocol<Tcg>,
    max_response_size: usize,
}

impl TpmTransport for Tcg2Transport {
    fn transmit_raw(&mut self, command: &[u8]) -> Result<Vec<u8>> {
        let mut out = vec![0u8; self.max_response_size.max(64)];
        self.tcg
            .submit_command(command, &mut out)
            .map_err(|e| anyhow!("SubmitCommand failed: {:?}", e.status()))?;
        if out.len() < 10 {
            bail!("short TPM response");
        }
        let size = u32::from_be_bytes([out[2], out[3], out[4], out[5]]) as usize;
        if size < 10 || size > out.len() {
            bail!("bad TPM response size {}", size);
        }
        out.truncate(size);
        Ok(out)
    }
}

#[entry]
fn main() -> Status {
    uefi::helpers::init().unwrap();
    println!("payload: hello from the chain-loaded UEFI payload");

    match print_pcrs() {
        Ok(()) => {}
        Err(e) => println!("payload: could not read PCRs: {e}"),
    }

    // A real payload would ExitBootServices and boot an OS here.
    println!("payload: done");
    boot::stall(5_000_000);
    Status::SUCCESS
}

fn print_pcrs() -> Result<()> {
    let handle = boot::get_handle_for_protocol::<Tcg>()
        .map_err(|e| anyhow!("no EFI_TCG2_PROTOCOL: {:?}", e.status()))?;
    let mut tcg = boot::open_protocol_exclusive::<Tcg>(handle)
        .map_err(|e| anyhow!("open EFI_TCG2_PROTOCOL: {:?}", e.status()))?;
    let max_response_size = tcg
        .get_capability()
        .map_err(|e| anyhow!("get_capability: {:?}", e.status()))?
        .max_response_size as usize;

    let mut tpm = vaportpm_attest::Tpm::with_transport(Box::new(Tcg2Transport {
        tcg,
        max_response_size,
    }));

    for (idx, value) in tpm.pcr_read_bank(&[14, 15], TpmAlg::Sha256)? {
        println!("payload: PCR{idx} (sha256) = {}", hex::encode(value));
    }
    Ok(())
}
