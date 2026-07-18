#![no_main]

//! Fuzz the attestation parser.
//!
//! Invariants: parsing arbitrary bytes never panics (both the size-guarded `from_json` and
//! the raw serde path), and a successfully parsed attestation re-emits deterministically —
//! serializing it twice (round-tripping through a re-parse) yields identical bytes. The
//! second invariant matters because attestations are canonicalized before signing, so a
//! non-deterministic emit would be a signing hazard. The "a forged attestation never
//! verifies" invariant lives in the `verify_chain` and `verify_*_json` targets, which drive
//! the verifier rather than the parser.

use auths_verifier::core::Attestation;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Size-guarded pipeline path (enforces the 64 KiB limit).
    let _ = Attestation::from_json(data);

    // Raw serde path, no size guard — catches panics inside hex/chrono serde or deeply
    // nested Option fields that `from_json` would reject early.
    let Ok(att) = serde_json::from_slice::<Attestation>(data) else {
        return;
    };

    // A parsed attestation must re-emit deterministically: serialize, re-parse, serialize
    // again, and the two emissions must be byte-identical.
    let once = serde_json::to_vec(&att).expect("a parsed attestation re-serializes");
    let reparsed: Attestation =
        serde_json::from_slice(&once).expect("re-serialized attestation re-parses");
    let twice = serde_json::to_vec(&reparsed).expect("re-parsed attestation re-serializes");
    assert_eq!(
        once, twice,
        "attestation emit must be deterministic (canonicalization depends on it)"
    );
});
