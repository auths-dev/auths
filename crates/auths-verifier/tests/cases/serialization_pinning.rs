use auths_verifier::keri::{IcpEvent, IxnEvent, KeriEvent, Prefix, RotEvent, Said, Seal};

fn make_test_icp() -> IcpEvent {
    IcpEvent {
        v: "KERI10JSON000000_".into(),
        d: Said::new_unchecked("ETestSaid1234567890123456789012345678901".into()),
        i: Prefix::new_unchecked("ETestPrefix123456789012345678901234567890".into()),
        s: "0".into(),
        kt: "1".into(),
        k: vec!["DTestKey12345678901234567890123456789012".into()],
        nt: "1".into(),
        n: vec!["ETestNext12345678901234567890123456789012".into()],
        bt: "0".into(),
        b: vec![],
        a: vec![],
        x: "".into(),
    }
}

fn make_test_rot() -> RotEvent {
    RotEvent {
        v: "KERI10JSON000000_".into(),
        d: Said::new_unchecked("ETestRotSaid23456789012345678901234567890".into()),
        i: Prefix::new_unchecked("ETestPrefix123456789012345678901234567890".into()),
        s: "1".into(),
        p: Said::new_unchecked("ETestSaid1234567890123456789012345678901".into()),
        kt: "1".into(),
        k: vec!["DNewKey123456789012345678901234567890123".into()],
        nt: "1".into(),
        n: vec!["ENewNext12345678901234567890123456789012".into()],
        bt: "0".into(),
        b: vec![],
        a: vec![],
        x: "".into(),
    }
}

fn make_test_ixn() -> IxnEvent {
    IxnEvent {
        v: "KERI10JSON000000_".into(),
        d: Said::new_unchecked("ETestIxnSaid23456789012345678901234567890".into()),
        i: Prefix::new_unchecked("ETestPrefix123456789012345678901234567890".into()),
        s: "2".into(),
        p: Said::new_unchecked("ETestRotSaid23456789012345678901234567890".into()),
        a: vec![Seal {
            d: Said::new_unchecked("ESealDigest234567890123456789012345678901".into()),
            seal_type: "device-attestation".into(),
        }],
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
    let json = serde_json::to_string(&KeriEvent::Inception(icp)).unwrap();
    assert_key_order(
        &json,
        &[
            "v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "a",
        ],
    );
}

#[test]
fn rot_field_order_is_pinned() {
    let rot = make_test_rot();
    let json = serde_json::to_string(&KeriEvent::Rotation(rot)).unwrap();
    assert_key_order(
        &json,
        &[
            "v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "b", "a",
        ],
    );
}

#[test]
fn ixn_field_order_is_pinned() {
    let ixn = make_test_ixn();
    let json = serde_json::to_string(&KeriEvent::Interaction(ixn)).unwrap();
    assert_key_order(&json, &["v", "t", "d", "i", "s", "p", "a"]);
}

#[test]
fn icp_with_x_includes_x_last() {
    let mut icp = make_test_icp();
    icp.x = "test_signature".into();
    let json = serde_json::to_string(&KeriEvent::Inception(icp)).unwrap();
    assert_key_order(
        &json,
        &[
            "v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "a", "x",
        ],
    );
}

#[test]
fn icp_without_d_omits_d() {
    let mut icp = make_test_icp();
    icp.d = Said::default();
    let json = serde_json::to_string(&KeriEvent::Inception(icp)).unwrap();
    assert!(
        !json.contains("\"d\":"),
        "d field should be omitted when empty"
    );
    assert_key_order(
        &json,
        &["v", "t", "i", "s", "kt", "k", "nt", "n", "bt", "b", "a"],
    );
}

#[test]
fn serialization_roundtrip_preserves_data() {
    let icp = make_test_icp();
    let event = KeriEvent::Inception(icp);
    let json = serde_json::to_string(&event).unwrap();
    let deserialized: KeriEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, deserialized);
}

#[test]
fn rot_serialization_roundtrip() {
    let rot = make_test_rot();
    let event = KeriEvent::Rotation(rot);
    let json = serde_json::to_string(&event).unwrap();
    let deserialized: KeriEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, deserialized);
}

#[test]
fn ixn_serialization_roundtrip() {
    let ixn = make_test_ixn();
    let event = KeriEvent::Interaction(ixn);
    let json = serde_json::to_string(&event).unwrap();
    let deserialized: KeriEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, deserialized);
}

#[test]
fn json_canon_golden_output() {
    let input = serde_json::json!({
        "z": "last",
        "a": "first",
        "m": [3, 1, 2],
        "nested": {"b": 2, "a": 1}
    });

    let canonical = json_canon::to_string(&input).unwrap();

    // RFC 8785 (JCS): keys sorted lexicographically, no whitespace, arrays preserve order
    assert_eq!(
        canonical,
        r#"{"a":"first","m":[3,1,2],"nested":{"a":1,"b":2},"z":"last"}"#
    );
}
