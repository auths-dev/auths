#![no_main]
//! CESR attachment parse fuzz target.
//!
//! Feeds attacker-controlled bytes through the `-A` signature and `-A ++ -G` seal
//! attachment readers (`parse_attachment` / `parse_delegated_attachment`) — the
//! parsers the offline verifier runs over a presented bundle's attachments before
//! any signature is checked. The invariant is that no malformed, truncated, or
//! multi-byte input ever panics: every input resolves to a typed error or a parsed
//! result.

use auths_keri::{parse_attachment, parse_delegated_attachment};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_attachment(data);
    let _ = parse_delegated_attachment(data);
});
