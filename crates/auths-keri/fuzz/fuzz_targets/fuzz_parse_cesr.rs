#![no_main]
//! `KeriPublicKey::parse` fuzz harness with a re-encode oracle.
//!
//! When a parse succeeds, the harness re-encodes the key through the
//! canonical CESR encoder (`to_qb64`) and re-parses it, asserting a
//! byte-identical round-trip. Catches round-trip bugs that a single-parse
//! harness would miss (length miscounts, base64 edge cases, mixed prefix
//! ambiguities, lead-byte misalignment).

use auths_keri::KeriPublicKey;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(pk) = KeriPublicKey::parse(s) else {
        return;
    };

    let re_encoded = match pk.to_qb64() {
        Ok(q) => q,
        Err(e) => panic!("a parsed key must re-encode to canonical qb64: {e:?}"),
    };
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
            panic!("canonical re-encoding failed to parse: {e:?}");
        }
    }
});
