// SPDX-License-Identifier: MIT OR Apache-2.0

//! Boot-relative timestamps for stage0's log lines.
//!
//! UEFI boot services expose no monotonic millisecond clock, so we read the CPU's
//! free-running cycle counter directly (x86_64 `rdtsc`, aarch64 `cntvct_el0`) and
//! convert cycles → milliseconds with a frequency calibrated once against
//! `boot::stall`. The result is a coarse "time since [`init`]" that is plenty to
//! see which step in a pasted boot log is eating wall-clock time.
//!
//! Every stage0 log line is emitted through the [`slog!`](crate::slog) macro,
//! which prefixes the [`stamp`] below.

use core::sync::atomic::{AtomicU64, Ordering};

use uefi::boot;

/// Window the counter frequency is averaged over. Long enough that `boot::stall`
/// jitter is a small fraction (timestamps are diagnostic, not load-bearing),
/// short enough to be negligible against the events being timed.
const CALIBRATION_MS: u64 = 50;

/// Raw counter value at [`init`], and the calibrated cycles-per-millisecond.
/// `CYCLES_PER_MS == 0` means [`init`] has not run yet.
static START: AtomicU64 = AtomicU64::new(0);
static CYCLES_PER_MS: AtomicU64 = AtomicU64::new(0);

/// Read the CPU's free-running cycle counter.
#[cfg(target_arch = "x86_64")]
#[inline]
fn raw() -> u64 {
    // SAFETY: `rdtsc` is unprivileged and always present on x86_64 UEFI hosts; it
    // only reads the timestamp counter.
    unsafe { core::arch::x86_64::_rdtsc() }
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn raw() -> u64 {
    let v: u64;
    // SAFETY: CNTVCT_EL0 is the EL0-readable virtual counter; the read is
    // side-effect free.
    unsafe { core::arch::asm!("mrs {}, cntvct_el0", out(reg) v, options(nomem, nostack)) };
    v
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[inline]
fn raw() -> u64 {
    0
}

/// Calibrate the counter frequency against a known stall and mark t = 0. Call once,
/// as early in `main`/`run` as possible. Costs a single `CALIBRATION_MS` stall,
/// which is itself counted (t = 0 is taken before it), so the first log line shows
/// roughly `CALIBRATION_MS`.
pub fn init() {
    let t0 = raw();
    boot::stall((CALIBRATION_MS * 1000) as usize); // stall() takes microseconds
    let t1 = raw();
    let per_ms = (t1.wrapping_sub(t0) / CALIBRATION_MS).max(1);
    CYCLES_PER_MS.store(per_ms, Ordering::Relaxed);
    START.store(t0, Ordering::Relaxed);
}

/// Milliseconds since [`init`]. Returns 0 if [`init`] has not been called.
pub fn since_boot_ms() -> u64 {
    let per_ms = CYCLES_PER_MS.load(Ordering::Relaxed);
    if per_ms == 0 {
        return 0;
    }
    raw().wrapping_sub(START.load(Ordering::Relaxed)) / per_ms
}

/// A `[   S.mmm]`-style stamp (seconds.milliseconds since [`init`]). Returns a
/// `Display` wrapper so the [`slog!`](crate::slog) macro formats without allocating.
pub fn stamp() -> Stamp {
    Stamp(since_boot_ms())
}

pub struct Stamp(u64);

impl core::fmt::Display for Stamp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:>5}.{:03}", self.0 / 1000, self.0 % 1000)
    }
}

/// Milestone log line with a boot-relative timestamp prefix, e.g.
/// `[    1.234] stage0: downloading payload`. Always emitted.
#[macro_export]
macro_rules! slog {
    ($($arg:tt)*) => {
        uefi::println!("[{}] {}", $crate::timing::stamp(), format_args!($($arg)*))
    };
}

/// Verbose trace line, same format as [`slog!`] but compiled in only under the
/// `verbose` feature. Use for per-connection/per-request/per-segment detail that
/// would drown the default boot log. Errors should use `slog!`, not this.
#[cfg(feature = "verbose")]
#[macro_export]
macro_rules! sdbg {
    ($($arg:tt)*) => {
        uefi::println!("[{}] {}", $crate::timing::stamp(), format_args!($($arg)*))
    };
}

/// No-op form when the `verbose` feature is off. Still references the arguments
/// (via `format_args!`) so they don't trip unused-variable warnings.
#[cfg(not(feature = "verbose"))]
#[macro_export]
macro_rules! sdbg {
    ($($arg:tt)*) => {{
        let _ = format_args!($($arg)*);
    }};
}
