#![no_main]

use auths_keri::{CesrV1Codec, import_cesr_to_events};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let codec = CesrV1Codec;
    let _ = import_cesr_to_events(&codec, data);
});
