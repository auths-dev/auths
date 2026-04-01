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

#[test]
fn environment_claim_excluded_from_canonical_form() {
    use auths_verifier::core::{
        Attestation, CanonicalAttestationData, Ed25519PublicKey, Ed25519Signature, ResourceId,
        canonicalize_attestation_data,
    };
    use auths_verifier::types::CanonicalDid;

    let att = Attestation {
        version: 1,
        rid: ResourceId::new("test-rid"),
        issuer: CanonicalDid::new_unchecked("did:keri:ETest"),
        subject: CanonicalDid::new_unchecked("did:key:z6Mk..."),
        device_public_key: Ed25519PublicKey::from_bytes([0u8; 32]),
        identity_signature: Ed25519Signature::empty(),
        device_signature: Ed25519Signature::empty(),
        revoked_at: None,
        expires_at: None,
        timestamp: None,
        note: None,
        payload: None,
        role: None,
        capabilities: vec![],
        delegated_by: None,
        signer_type: None,
        environment_claim: Some(serde_json::json!({"provider": "aws", "region": "us-east-1"})),
        commit_sha: None,
        commit_message: None,
        author: None,
        oidc_binding: None,
    };

    let data = CanonicalAttestationData {
        version: att.version,
        rid: &att.rid,
        issuer: &att.issuer,
        subject: &att.subject,
        device_public_key: att.device_public_key.as_bytes(),
        payload: &att.payload,
        timestamp: &att.timestamp,
        expires_at: &att.expires_at,
        revoked_at: &att.revoked_at,
        note: &att.note,
        role: None,
        capabilities: None,
        delegated_by: None,
        signer_type: None,
    };

    let canonical_with_env = canonicalize_attestation_data(&data).unwrap();

    let att_without = Attestation {
        environment_claim: None,
        ..att.clone()
    };

    let data_without = CanonicalAttestationData {
        version: att_without.version,
        rid: &att_without.rid,
        issuer: &att_without.issuer,
        subject: &att_without.subject,
        device_public_key: att_without.device_public_key.as_bytes(),
        payload: &att_without.payload,
        timestamp: &att_without.timestamp,
        expires_at: &att_without.expires_at,
        revoked_at: &att_without.revoked_at,
        note: &att_without.note,
        role: None,
        capabilities: None,
        delegated_by: None,
        signer_type: None,
    };

    let canonical_without_env = canonicalize_attestation_data(&data_without).unwrap();

    assert_eq!(
        canonical_with_env, canonical_without_env,
        "environment_claim must not affect canonical form"
    );
}

#[test]
fn environment_claim_roundtrips_through_json() {
    use auths_verifier::core::{Attestation, Ed25519PublicKey, Ed25519Signature, ResourceId};
    use auths_verifier::types::CanonicalDid;

    let att = Attestation {
        version: 1,
        rid: ResourceId::new("test-rid"),
        issuer: CanonicalDid::new_unchecked("did:keri:ETest"),
        subject: CanonicalDid::new_unchecked("did:key:z6Mk..."),
        device_public_key: Ed25519PublicKey::from_bytes([0u8; 32]),
        identity_signature: Ed25519Signature::empty(),
        device_signature: Ed25519Signature::empty(),
        revoked_at: None,
        expires_at: None,
        timestamp: None,
        note: None,
        payload: None,
        role: None,
        capabilities: vec![],
        delegated_by: None,
        signer_type: None,
        environment_claim: Some(serde_json::json!({"provider": "aws"})),
        commit_sha: None,
        commit_message: None,
        author: None,
        oidc_binding: None,
    };

    let json = serde_json::to_string(&att).unwrap();
    assert!(json.contains("\"environment_claim\""));

    let parsed: Attestation = serde_json::from_str(&json).unwrap();
    assert_eq!(att.environment_claim, parsed.environment_claim);

    let att_none = Attestation {
        environment_claim: None,
        ..att.clone()
    };
    let json_none = serde_json::to_string(&att_none).unwrap();
    assert!(!json_none.contains("environment_claim"));

    let parsed_none: Attestation = serde_json::from_str(&json_none).unwrap();
    assert_eq!(parsed_none.environment_claim, None);
}
