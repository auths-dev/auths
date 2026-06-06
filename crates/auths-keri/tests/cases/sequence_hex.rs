//! Sequence-number serialization correctness per KERI spec: `s` is a hex string.
//!
//! Guards the one footgun where decimal-vs-hex confusion is invisible below
//! sequence 10 but diverges at 16 (`"10"` hex vs `"16"` decimal).

use auths_keri::{IxnEvent, KeriSequence, Prefix, Said, Seal, VersionString};
use serde_json::Value;

fn make_ixn_with_seq(seq_u128: u128) -> IxnEvent {
    IxnEvent {
        v: VersionString::placeholder(),
        d: Said::new_unchecked("EPlaceholder0000000000000000000000000000000".to_string()),
        i: Prefix::new_unchecked("EPlaceholderController0000000000000000000000".to_string()),
        s: KeriSequence::new(seq_u128),
        p: Said::new_unchecked("EPlaceholderPrior00000000000000000000000000".to_string()),
        a: vec![Seal::digest("EPlaceholderSeal000000000000000000000000000")],
    }
}

fn s_field(event: &IxnEvent) -> String {
    let v: Value = serde_json::to_value(event).unwrap();
    v.get("s")
        .and_then(|s| s.as_str())
        .map(|s| s.to_string())
        .unwrap_or_default()
}

fn assert_roundtrip(seq: u128, expected_hex: &str) {
    let ev = make_ixn_with_seq(seq);
    let s = s_field(&ev);
    assert_eq!(
        s, expected_hex,
        "sequence {seq} must serialize to {expected_hex:?}, got {s:?}"
    );

    // Round-trip: serialize the event, deserialize back, check the sequence matches.
    let bytes = serde_json::to_vec(&ev).unwrap();
    let back: IxnEvent = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        back.s.value(),
        seq,
        "sequence {seq} must round-trip; got {:?}",
        back.s.value()
    );
}

#[test]
fn sequence_hex_boundary_zero() {
    assert_roundtrip(0, "0");
}

#[test]
fn sequence_hex_single_digit() {
    assert_roundtrip(9, "9");
}

#[test]
fn sequence_hex_ten_is_a() {
    assert_roundtrip(10, "a");
}

#[test]
fn sequence_hex_fifteen_is_f() {
    assert_roundtrip(15, "f");
}

#[test]
fn sequence_hex_sixteen_is_ten() {
    // The canary — decimal 16 looks identical to hex 0x10's value 16 in text
    // form "16" vs "10". This test fails if we ever accidentally serialize
    // decimal.
    assert_roundtrip(16, "10");
}

#[test]
fn sequence_hex_byte_boundary() {
    assert_roundtrip(255, "ff");
    assert_roundtrip(256, "100");
    assert_roundtrip(4095, "fff");
}

#[test]
fn sequence_hex_u64_max() {
    assert_roundtrip(u64::MAX as u128, "ffffffffffffffff");
}

#[test]
fn sequence_hex_beyond_u64() {
    // u64::MAX + 1 — the first value a spec-conforming u128 serializer must
    // handle but a u64-limited impl would overflow.
    assert_roundtrip((u64::MAX as u128) + 1, "10000000000000000");
}

#[test]
fn sequence_hex_u128_max() {
    assert_roundtrip(u128::MAX, "ffffffffffffffffffffffffffffffff");
}
