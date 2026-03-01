#![no_main]

use auths_verifier::core::Attestation;
use auths_verifier::verify::verify_chain;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Split input into root key and attestation JSON chunks
    if data.len() < 32 {
        return;
    }
    let (root_key, rest) = data.split_at(32);

    // Try to parse rest as multiple attestations (each chunk is 256 bytes)
    let attestations: Vec<Attestation> = rest
        .chunks(256)
        .filter_map(|chunk| Attestation::from_json(chunk).ok())
        .collect();

    if !attestations.is_empty() {
        // Should never panic, even with malformed data
        let _ = verify_chain(&attestations, root_key);
    }
});
