use auths_id::keri::event::{Event, IcpEvent, IxnEvent, KeriSequence, RotEvent};
use auths_id::keri::seal::Seal;
use auths_id::keri::types::{Prefix, Said};
use auths_keri::{CesrKey, Threshold, VersionString};

fn make_test_icp() -> IcpEvent {
    IcpEvent {
        v: VersionString::placeholder(),
        d: Said::new_unchecked("ETestSaid1234567890123456789012345678901".into()),
        i: Prefix::new_unchecked("ETestPrefix123456789012345678901234567890".into()),
        s: KeriSequence::new(0),
        kt: Threshold::Simple(1),
        k: vec![CesrKey::new_unchecked(
            "DTestKey12345678901234567890123456789012".into(),
        )],
        nt: Threshold::Simple(1),
        n: vec![Said::new_unchecked(
            "ETestNext12345678901234567890123456789012".into(),
        )],
        bt: Threshold::Simple(0),
        b: vec![],
        c: vec![],
        a: vec![],
        x: "".into(),
    }
}

fn make_test_rot() -> RotEvent {
    RotEvent {
        v: VersionString::placeholder(),
        d: Said::new_unchecked("ETestRotSaid23456789012345678901234567890".into()),
        i: Prefix::new_unchecked("ETestPrefix123456789012345678901234567890".into()),
        s: KeriSequence::new(1),
        p: Said::new_unchecked("ETestSaid1234567890123456789012345678901".into()),
        kt: Threshold::Simple(1),
        k: vec![CesrKey::new_unchecked(
            "DNewKey123456789012345678901234567890123".into(),
        )],
        nt: Threshold::Simple(1),
        n: vec![Said::new_unchecked(
            "ENewNext12345678901234567890123456789012".into(),
        )],
        bt: Threshold::Simple(0),
        br: vec![],
        ba: vec![],
        c: vec![],
        a: vec![],
        x: "".into(),
    }
}

fn make_test_ixn() -> IxnEvent {
    IxnEvent {
        v: VersionString::placeholder(),
        d: Said::new_unchecked("ETestIxnSaid23456789012345678901234567890".into()),
        i: Prefix::new_unchecked("ETestPrefix123456789012345678901234567890".into()),
        s: KeriSequence::new(2),
        p: Said::new_unchecked("ETestRotSaid23456789012345678901234567890".into()),
        a: vec![Seal::digest("ESealDigest234567890123456789012345678901")],
        x: "".into(),
    }
}

/// Assert that key positions in the raw JSON string follow the expected order.
fn assert_key_order(json: &str, expected_keys: &[&str]) {
    let mut positions: Vec<(&str, usize)> = Vec::new();
    for key in expected_keys {
        let pattern = format!("\"{}\":", key);
        let pos = json
            .find(&pattern)
            .unwrap_or_else(|| panic!("key \"{}\" not found in JSON: {}", key, json));
        positions.push((key, pos));
    }
    for window in positions.windows(2) {
        assert!(
            window[0].1 < window[1].1,
            "key \"{}\" (pos {}) should come before \"{}\" (pos {}) in: {}",
            window[0].0,
            window[0].1,
            window[1].0,
            window[1].1,
            json
        );
    }
}

#[test]
fn icp_field_order_is_pinned() {
    let icp = make_test_icp();
    let json = serde_json::to_string(&Event::Icp(icp)).unwrap();
    assert_key_order(
        &json,
        &[
            "v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a",
        ],
    );
}

#[test]
fn rot_field_order_is_pinned() {
    let rot = make_test_rot();
    let json = serde_json::to_string(&Event::Rot(rot)).unwrap();
    assert_key_order(
        &json,
        &[
            "v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "br", "ba", "c", "a",
        ],
    );
}

#[test]
fn ixn_field_order_is_pinned() {
    let ixn = make_test_ixn();
    let json = serde_json::to_string(&Event::Ixn(ixn)).unwrap();
    assert_key_order(&json, &["v", "t", "d", "i", "s", "p", "a"]);
}

#[test]
fn icp_with_x_includes_x_last() {
    let mut icp = make_test_icp();
    icp.x = "test_signature".into();
    let json = serde_json::to_string(&Event::Icp(icp)).unwrap();
    assert_key_order(
        &json,
        &[
            "v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a", "x",
        ],
    );
}

#[test]
fn serialization_roundtrip_preserves_data() {
    let icp = make_test_icp();
    let event = Event::Icp(icp);
    let json = serde_json::to_string(&event).unwrap();
    let deserialized: Event = serde_json::from_str(&json).unwrap();
    assert_eq!(event, deserialized);
}

#[test]
fn rot_serialization_roundtrip() {
    let rot = make_test_rot();
    let event = Event::Rot(rot);
    let json = serde_json::to_string(&event).unwrap();
    let deserialized: Event = serde_json::from_str(&json).unwrap();
    assert_eq!(event, deserialized);
}

#[test]
fn ixn_serialization_roundtrip() {
    let ixn = make_test_ixn();
    let event = Event::Ixn(ixn);
    let json = serde_json::to_string(&event).unwrap();
    let deserialized: Event = serde_json::from_str(&json).unwrap();
    assert_eq!(event, deserialized);
}
