#![no_main]

use auths_crypto::did_key_decode;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = did_key_decode(s);
    }
});
