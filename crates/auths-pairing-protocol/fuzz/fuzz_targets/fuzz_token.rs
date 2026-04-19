#![no_main]
//! Fuzz target for `PairingToken` deserialization (fn-129.T8).
//!
//! Feeds arbitrary bytes to `serde_json::from_slice::<PairingToken>`. The
//! harness never calls methods on parsed tokens that would do crypto —
//! the point is to catch parse-layer panics, memory bloat, or stack
//! overflows in the serde_json + auths-pairing-protocol type definitions.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Ignore Err — that's the expected path for most random inputs.
    // Panic-on-success policy: if this unwraps or panics, it's a defect.
    let _ = serde_json::from_slice::<auths_pairing_protocol::PairingToken>(data);
});
