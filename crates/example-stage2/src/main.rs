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

    println!("=== Task complete, waiting 60 seconds for console log capture ===");
    thread::sleep(Duration::from_secs(60));
    println!("=== Powering off ===");
    poweroff();
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
