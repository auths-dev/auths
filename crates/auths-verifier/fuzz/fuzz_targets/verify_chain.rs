#![no_main]

//! Fuzz the attestation-chain verifier.
//!
//! Invariant: over arbitrary bytes the chain verifier never panics and never reports a
//! `Valid` chain — the fuzzer cannot assemble attestations whose signatures verify under a
//! random root key. The verdict future is actually driven here (an earlier revision built
//! it and dropped it, verifying nothing); a tiny current-thread runtime drives it because
//! the crypto provider is async.

use auths_crypto::CurveType;
use auths_verifier::core::{Attestation, DevicePublicKey};
use auths_verifier::verify::verify_chain;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }
    let (root_key, rest) = data.split_at(32);
    let Ok(root_pk) = DevicePublicKey::try_new(CurveType::Ed25519, root_key) else {
        return;
    };

    let attestations: Vec<Attestation> = rest
        .chunks(256)
        .filter_map(|chunk| Attestation::from_json(chunk).ok())
        .collect();
    if attestations.is_empty() {
        return;
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("current-thread runtime");
    if let Ok(report) = runtime.block_on(verify_chain(&attestations, &root_pk)) {
        assert!(
            !report.is_valid(),
            "a fuzzer-assembled chain cannot carry signatures valid under a random root key"
        );
    }
});
