// fn-114: allow during curve-agnostic refactor; removed in fn-114.40.
#![allow(clippy::disallowed_methods)]

#![no_main]

use auths_crypto::did_key_to_ed25519;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Try to parse arbitrary bytes as UTF-8 string, then as DID
    if let Ok(s) = std::str::from_utf8(data) {
        // Should never panic, even with malformed DIDs
        let _ = did_key_to_ed25519(s);
    }
});
