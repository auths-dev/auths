#![no_main]

//! Fuzz the live presentation request-auth wire (`verify_presentation_json`).
//!
//! Invariants over arbitrary attacker bytes: the entrypoint never panics, always returns a
//! tagged JSON verdict, and — whenever it returns `kind:"valid"` — the holder-binding
//! signature is *load-bearing*: blanking the envelope signature and re-verifying must no
//! longer return valid. A verifier that accepted a request without actually checking the
//! holder signature (the unsigned/wrong-key class) would still return valid with the
//! signature blanked, tripping the assertion. This avoids false positives from benign
//! re-encodings (whitespace, key order, fields the verdict does not depend on) that a
//! byte-identity check would wrongly flag.

use auths_verifier::verify_presentation_json;
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

fuzz_target!(|data: &[u8]| {
    let Ok(request) = std::str::from_utf8(data) else {
        return;
    };
    let verdict = verify_presentation_json(request);
    let parsed: Value =
        serde_json::from_str(&verdict).expect("the verdict surface is always valid JSON");
    if parsed["kind"] != "valid" {
        return;
    }

    // The verifier accepted it; prove the holder signature was necessary.
    let Ok(mut req) = serde_json::from_str::<Value>(request) else {
        return;
    };
    if !req["envelope"]["signatureB64"].is_string() {
        return;
    }
    req["envelope"]["signatureB64"] = Value::String(String::new());
    let reverdict = verify_presentation_json(&req.to_string());
    let reparsed: Value = serde_json::from_str(&reverdict).expect("verdict JSON");
    assert_ne!(
        reparsed["kind"], "valid",
        "blanking the holder signature must break a valid presentation"
    );
});
