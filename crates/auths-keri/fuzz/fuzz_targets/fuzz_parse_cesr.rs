#![no_main]
//! `KeriPublicKey::parse` fuzz harness with a re-encode oracle.
//!
//! When a parse succeeds, the harness synthesizes the CESR prefix form
//! and re-parses it, asserting byte-identical round-trip through the
//! raw-bytes path. Catches round-trip bugs that a single-parse
//! harness would miss (length miscounts, base64 edge cases, mixed
//! prefix ambiguities).

use auths_keri::KeriPublicKey;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use libfuzzer_sys::fuzz_target;

fn re_encode(pk: &KeriPublicKey) -> String {
    let bytes = pk.as_bytes();
    let prefix = pk.cesr_prefix();
    let encoded = URL_SAFE_NO_PAD.encode(bytes);
    format!("{prefix}{encoded}")
}

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    match KeriPublicKey::parse(s) {
        Ok(pk) => {
            let re_encoded = re_encode(&pk);
            match KeriPublicKey::parse(&re_encoded) {
                Ok(pk2) => {
                    if pk.as_bytes() != pk2.as_bytes() {
                        panic!("round-trip produced different bytes");
                    }
                    if pk.curve() != pk2.curve() {
                        panic!("round-trip changed curve");
                    }
                }
                Err(e) => {
                    panic!("re-encoded key failed to parse: {e:?}");
                }
            }
        }
        Err(_) => {
            // Expected for most inputs.
        }
    }
});
