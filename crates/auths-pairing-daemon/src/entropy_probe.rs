//! Startup RNG health probe (fn-128.T7).
//!
//! Refuses to run if the kernel CRNG is not initialised or if `OsRng`'s
//! output fails a lightweight NIST SP 800-90B-style health check. Catches
//! the early-boot entropy-starvation window that has historically produced
//! real-world key-collision incidents (Debian BoottimeEntropyStarvation,
//! Cornell "Not-So-Random Numbers in Virtualized Linux").
//!
//! # Design
//!
//! - **Cross-platform baseline (RCT + APT):** read 4 KiB from the RNG,
//!   run NIST SP 800-90B §4 Repetition Count Test (RCT) and Adaptive
//!   Proportion Test (APT). Reject on failure.
//! - **Linux CRNG-init check:** not implemented here — we rely on `OsRng`
//!   reading from `getrandom(2)` in blocking mode via the `getrandom`
//!   crate, which blocks until the pool is initialised on first call.
//!   If the syscall returns bytes, the kernel has seeded.
//!
//! The probe runs BEFORE socket bind. On failure, return a typed error and
//! exit with a non-zero code so service managers surface the issue.
//!
//! Usage:
//! ```ignore
//! use auths_pairing_daemon::entropy_probe::{run_health_check, HealthRng};
//! run_health_check(&mut HealthRng::os_rng())?;
//! ```

use crate::DaemonError;

/// NIST SP 800-90B §4.4.1 RCT: fail if any single value repeats more than
/// `cutoff` times in a row. `cutoff` = 1 + ceil(20 / -log2(p)) with p the
/// most-probable-symbol probability. For `OsRng` output, symbols are bytes,
/// p = 1/256 → cutoff ≈ 3.5 → round up to 4 to keep false-positive rate low.
const RCT_CUTOFF: usize = 4;

/// NIST SP 800-90B §4.4.2 APT: over a window of `APT_WINDOW` samples, the
/// most-probable-symbol appears at most `APT_CUTOFF` times.
const APT_WINDOW: usize = 512;
const APT_CUTOFF: usize = 51;

/// 4 KiB probe: enough samples for the statistical tests to be meaningful
/// without delaying startup noticeably.
const PROBE_SIZE: usize = 4096;

/// Trait for pluggable RNG sources — production uses `OsRng`, tests inject a
/// poisoned RNG via the `test-fake-rng` feature. Avoids dragging `rand_core`
/// generics through the probe's public API.
pub trait HealthRngSource {
    /// Fill `buf` with random bytes.
    fn fill(&mut self, buf: &mut [u8]);
}

/// Wrapper that satisfies [`HealthRngSource`] for real `OsRng`.
pub struct HealthRng<R: rand::RngCore>(pub R);

impl<R: rand::RngCore> HealthRngSource for HealthRng<R> {
    fn fill(&mut self, buf: &mut [u8]) {
        self.0.fill_bytes(buf);
    }
}

impl HealthRng<rand::rngs::OsRng> {
    /// Convenience constructor — production code uses this.
    pub fn os_rng() -> Self {
        Self(rand::rngs::OsRng)
    }
}

/// Run the startup health check. Returns Ok on pass; `DaemonError` on fail.
///
/// Args:
/// * `rng`: An RNG source. Use [`HealthRng::os_rng`] in production; a
///   deterministic crafted source in tests via the `test-fake-rng` feature.
///
/// Usage:
/// ```ignore
/// let mut rng = HealthRng::os_rng();
/// run_health_check(&mut rng).expect("RNG health check failed at startup");
/// ```
pub fn run_health_check<R: HealthRngSource>(rng: &mut R) -> Result<(), DaemonError> {
    let mut buf = vec![0u8; PROBE_SIZE];
    rng.fill(&mut buf);
    rct(&buf)?;
    apt(&buf)?;
    Ok(())
}

/// Repetition Count Test — fails if any byte value repeats more than
/// `RCT_CUTOFF` times consecutively.
fn rct(samples: &[u8]) -> Result<(), DaemonError> {
    if samples.is_empty() {
        return Err(DaemonError::EntropyCheckFailed("empty probe buffer".into()));
    }
    let mut run_value = samples[0];
    let mut run_len = 1usize;
    for &b in &samples[1..] {
        if b == run_value {
            run_len += 1;
            if run_len > RCT_CUTOFF {
                return Err(DaemonError::EntropyCheckFailed(format!(
                    "RCT: byte {b:#x} repeated {run_len} times (cutoff {RCT_CUTOFF})"
                )));
            }
        } else {
            run_value = b;
            run_len = 1;
        }
    }
    Ok(())
}

/// Adaptive Proportion Test — over a window of `APT_WINDOW` samples, no
/// single byte value appears more than `APT_CUTOFF` times.
fn apt(samples: &[u8]) -> Result<(), DaemonError> {
    if samples.len() < APT_WINDOW {
        return Ok(());
    }
    for window_start in (0..=samples.len() - APT_WINDOW).step_by(APT_WINDOW) {
        let window = &samples[window_start..window_start + APT_WINDOW];
        let probe_byte = window[0];
        let count = window.iter().filter(|&&b| b == probe_byte).count();
        if count > APT_CUTOFF {
            return Err(DaemonError::EntropyCheckFailed(format!(
                "APT: byte {probe_byte:#x} appeared {count} times in window (cutoff {APT_CUTOFF})"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic stream source for tests.
    struct CraftedRng {
        pattern: Vec<u8>,
        cursor: usize,
    }

    impl HealthRngSource for CraftedRng {
        fn fill(&mut self, buf: &mut [u8]) {
            for out in buf.iter_mut() {
                *out = self.pattern[self.cursor % self.pattern.len()];
                self.cursor = self.cursor.wrapping_add(1);
            }
        }
    }

    #[test]
    fn real_os_rng_passes_health_check() {
        let mut rng = HealthRng::os_rng();
        run_health_check(&mut rng).expect("OsRng should pass RCT+APT");
    }

    #[test]
    fn all_zero_stream_fails_rct() {
        let mut rng = CraftedRng {
            pattern: vec![0x00],
            cursor: 0,
        };
        let err = run_health_check(&mut rng).expect_err("all-zero stream must fail");
        match err {
            DaemonError::EntropyCheckFailed(msg) => {
                assert!(msg.contains("RCT"), "expected RCT failure, got: {msg}");
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn biased_stream_fails_apt() {
        // Pattern: 0x00 occurs in ~90% of samples, one non-zero byte sprinkled in.
        // Enough to fail APT without triggering RCT first (break the repeated
        // run every few bytes).
        let pattern: Vec<u8> = (0..10)
            .flat_map(|_| vec![0x00, 0x00, 0x00, 0xFF]) // 75% zero, breaks after 3
            .collect();
        let mut rng = CraftedRng { pattern, cursor: 0 };
        let result = run_health_check(&mut rng);
        assert!(
            result.is_err(),
            "biased stream should fail either RCT or APT"
        );
    }

    #[test]
    fn uniform_counter_passes_baseline() {
        // Perfectly uniform-over-one-window byte sequence: 0x00, 0x01, ..., 0xFF, 0x00, ...
        // Should pass both tests (each byte appears exactly 16 times in a 4096-byte probe).
        let pattern: Vec<u8> = (0..=255u8).collect();
        let mut rng = CraftedRng { pattern, cursor: 0 };
        run_health_check(&mut rng).expect("uniform counter should pass");
    }
}
