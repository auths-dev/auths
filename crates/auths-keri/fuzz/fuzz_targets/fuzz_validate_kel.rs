#![no_main]
//! Authenticated KEL-replay fuzz target.
//!
//! Decodes attacker-controlled bytes as a JSON array of signed events and
//! hands them to `validate_signed_kel` — the authenticated replay every
//! stateless verify entrypoint routes through. The byte-level CESR codec
//! parser is fuzzed separately by `fuzz_cesr_import`; this target exercises
//! the validation verdict itself.
//!
//! # Invariants asserted
//!
//! 1. Validation never panics on hostile input: every malformed, forged, or
//!    truncated KEL resolves to a typed error, never a crash.
//! 2. Any `Ok` verdict describes a single-controller chain — the inception's
//!    controller AID is preserved on every following event. The validator
//!    enforces this through chain linkage; re-checking it here turns a silent
//!    linkage regression into a fuzz crash.

use auths_keri::{SignedEvent, validate_signed_kel};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(events) = serde_json::from_slice::<Vec<SignedEvent>>(data) else {
        return;
    };
    let Ok(_key_state) = validate_signed_kel(&events, None) else {
        return;
    };

    // An accepted KEL is non-empty (EmptyKel is an error) and single-controller.
    let controller = events[0].prefix().to_string();
    for (idx, signed) in events.iter().enumerate().skip(1) {
        if signed.prefix().to_string() != controller {
            panic!("validate_signed_kel accepted a mismatched controller AID at event #{idx}");
        }
    }
});
