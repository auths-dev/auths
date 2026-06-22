#![no_main]
//! NonTransReceiptCouples parse fuzz target.
//!
//! Feeds attacker-controlled bytes through `parse_nontrans_receipt_couples` — the
//! `-L` witness-receipt attachment reader, which decodes a stream of CESR verkey
//! and signature primitives. The invariant is that no malformed, truncated, or
//! variable-length code ever panics the parser: every input resolves to a typed
//! error or a parsed couple list, never a crash.

use auths_keri::witness::parse_nontrans_receipt_couples;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let _ = parse_nontrans_receipt_couples(s);
});
