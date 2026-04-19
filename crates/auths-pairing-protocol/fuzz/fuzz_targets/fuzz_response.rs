#![no_main]
//! Fuzz target for `PairingResponse` deserialization (fn-129.T8).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<auths_pairing_protocol::PairingResponse>(data);
});
