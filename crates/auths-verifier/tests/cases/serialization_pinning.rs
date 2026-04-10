use auths_keri::{
    CesrKey, Event as KeriEvent, IcpEvent, IxnEvent, KeriSequence, Prefix, RotEvent, Said, Seal,
    Threshold, VersionString,
};

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
    let json = serde_json::to_string(&KeriEvent::Icp(icp)).unwrap();
    assert_key_order(
        &json,
        &[
            "v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c",
        ],
    );
}

#[test]
fn rot_field_order_is_pinned() {
    let rot = make_test_rot();
    let json = serde_json::to_string(&KeriEvent::Rot(rot)).unwrap();
    // `a` is omitted when empty (canonical auths-keri format)
    assert_key_order(
        &json,
        &[
            "v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "br", "ba", "c",
        ],
    );
}

#[test]
fn ixn_field_order_is_pinned() {
    let ixn = make_test_ixn();
    let json = serde_json::to_string(&KeriEvent::Ixn(ixn)).unwrap();
    assert_key_order(&json, &["v", "t", "d", "i", "s", "p", "a"]);
}

#[test]
fn icp_with_x_includes_x_last() {
    let mut icp = make_test_icp();
    icp.x = "test_signature".into();
    let json = serde_json::to_string(&KeriEvent::Icp(icp)).unwrap();
    assert_key_order(
        &json,
        &[
            "v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "x",
        ],
    );
}

#[test]
fn icp_with_empty_d_still_includes_d() {
    let mut icp = make_test_icp();
    icp.d = Said::default();
    let json = serde_json::to_string(&KeriEvent::Icp(icp)).unwrap();
    // Per spec, all fields are always present (even with empty d)
    assert!(
        json.contains("\"d\":"),
        "d field must always be present per spec"
    );
    assert_key_order(
        &json,
        &[
            "v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a",
        ],
    );
}

#[test]
fn serialization_roundtrip_preserves_data() {
    let icp = make_test_icp();
    let event = KeriEvent::Icp(icp);
    let json = serde_json::to_string(&event).unwrap();
    let deserialized: KeriEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, deserialized);
}

#[test]
fn rot_serialization_roundtrip() {
    let rot = make_test_rot();
    let event = KeriEvent::Rot(rot);
    let json = serde_json::to_string(&event).unwrap();
    let deserialized: KeriEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, deserialized);
}

#[test]
fn ixn_serialization_roundtrip() {
    let ixn = make_test_ixn();
    let event = KeriEvent::Ixn(ixn);
    let json = serde_json::to_string(&event).unwrap();
    let deserialized: KeriEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, deserialized);
}

#[test]
fn seal_type_is_kebab_case_string() {
    let seal = Seal::digest("ETest");
    let json = serde_json::to_string(&seal).unwrap();
    assert!(json.contains(r#""d":"ETest""#));
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
        Attestation, Ed25519PublicKey, Ed25519Signature, ResourceId, canonicalize_attestation_data,
    };
    use auths_verifier::types::CanonicalDid;

    let att = Attestation {
        version: 1,
        rid: ResourceId::new("test-rid"),
        issuer: CanonicalDid::new_unchecked("did:keri:ETest"),
        subject: CanonicalDid::new_unchecked("did:key:z6Mk..."),
        device_public_key: Ed25519PublicKey::from_bytes([0u8; 32]).into(),
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

    let canonical_with_env = canonicalize_attestation_data(&att.canonical_data()).unwrap();

    let att_without = Attestation {
        environment_claim: None,
        ..att.clone()
    };

    let canonical_without_env =
        canonicalize_attestation_data(&att_without.canonical_data()).unwrap();

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
        device_public_key: Ed25519PublicKey::from_bytes([0u8; 32]).into(),
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
