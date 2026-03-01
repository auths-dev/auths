#![no_main]

use auths_verifier::core::Attestation;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Path 1: full pipeline with size guard (Attestation::from_json enforces 64 KiB limit)
    let _ = Attestation::from_json(data);

    // Path 2: raw serde path, no size guard – catches panics inside hex::serde,
    // chrono::serde, or deeply-nested Option fields that from_json would reject early
    let _ = serde_json::from_slice::<Attestation>(data);
});
