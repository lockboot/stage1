// SPDX-License-Identifier: MIT OR Apache-2.0

use std::env;
use std::fs;
use std::io::Read;
use std::thread;
use std::time::Duration;

fn main() {
    // Echo arguments
    let args: Vec<String> = env::args().collect();
    println!("=== Arguments ===");
    for (i, arg) in args.iter().enumerate() {
        println!("arg[{}]: {}", i, arg);
    }
    println!();

    // stage1 delivers the config (the raw user-data JSON) on stdin.
    println!("=== config (stdin) ===");
    let mut config = String::new();
    match std::io::stdin().read_to_string(&mut config) {
        Ok(_) => println!("{}", config),
        Err(e) => eprintln!("Error reading config from stdin: {}", e),
    }
    println!();

    // Print stage1.attest
    println!("=== /tmp/stage1.attest ===");
    match fs::read_to_string("/tmp/stage1.attest") {
        Ok(contents) => println!("{}", contents),
        Err(e) => eprintln!("Error reading /tmp/stage1.attest: {}", e),
    }
    println!();

    // Opt-in (`--dump-tpm`): the TCG event log (firmware + systemd-stub + kernel events) and every
    // PCR the kernel exposes, so a PCR predictor can be checked event-by-event against this boot.
    if args.iter().any(|a| a == "--dump-tpm") {
        dump_tpm();
    }

    println!("=== Task complete, waiting 60 seconds for console log capture ===");
    thread::sleep(Duration::from_secs(60));
    println!("=== Powering off ===");
    poweroff();
}

/// Mount `fstype` at `target` (best effort: an already-mounted target is fine).
fn mount(fstype: &str, target: &str) {
    let _ = fs::create_dir_all(target);
    let src = std::ffi::CString::new(fstype).unwrap();
    let dst = std::ffi::CString::new(target).unwrap();
    let rc = unsafe {
        libc::mount(
            src.as_ptr(),
            dst.as_ptr(),
            src.as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EBUSY) {
            eprintln!("mount {fstype} on {target}: {e}");
        }
    }
}

/// Print the raw TCG2 event log as `TPMLOG <hex>` lines (<= 64 bytes each, in order) and every
/// PCR as `PCR <bank> <nn> <hex>`, bracketed by stable markers.
fn dump_tpm() {
    mount("sysfs", "/sys");
    mount("securityfs", "/sys/kernel/security");
    println!("=== TPMLOG-BEGIN ===");
    match fs::read("/sys/kernel/security/tpm0/binary_bios_measurements") {
        Ok(log) => {
            for chunk in log.chunks(64) {
                let hex: String = chunk.iter().map(|b| format!("{b:02x}")).collect();
                println!("TPMLOG {hex}");
            }
            println!("=== TPMLOG-END === bytes={}", log.len());
        }
        Err(e) => println!("=== TPMLOG-END === error: {e}"),
    }
    for bank in ["sha1", "sha256", "sha384", "sha512"] {
        for i in 0..24 {
            if let Ok(v) = fs::read_to_string(format!("/sys/class/tpm/tpm0/pcr-{bank}/{i}")) {
                println!("PCR {bank} {i:02} {}", v.trim().to_lowercase());
            }
        }
    }
    println!("=== PCR-DUMP-END ===");
}

fn poweroff() {
    let pid = std::process::id();
    if pid == 1 {
        unsafe {
            libc::sync();
            libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF);
        }
    } else {
        std::process::exit(1);
    }
}
