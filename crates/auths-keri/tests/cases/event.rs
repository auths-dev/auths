use auths_keri::{CesrV1Codec, serialize_for_cesr};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

fn make_test_icp(sig: Option<&[u8; 64]>) -> serde_json::Value {
    let x = sig.map(|s| URL_SAFE_NO_PAD.encode(s)).unwrap_or_default();
    serde_json::json!({
        "v": "KERI10JSON000000_",
        "t": "icp",
        "d": "ETestSaid1234567890123456789012345678901",
        "i": "ETestPrefix123456789012345678901234567890",
        "s": "0",
        "kt": "1",
        "k": ["DTestKey12345678901234567890123456789012"],
        "nt": "1",
        "n": ["ETestNext12345678901234567890123456789012"],
        "bt": "0",
        "b": [],
        "a": [],
        "x": x
    })
}

fn make_test_rot(sig: Option<&[u8; 64]>) -> serde_json::Value {
    let x = sig.map(|s| URL_SAFE_NO_PAD.encode(s)).unwrap_or_default();
    serde_json::json!({
        "v": "KERI10JSON000000_",
        "t": "rot",
        "d": "ETestRotSaid23456789012345678901234567890",
        "i": "ETestPrefix123456789012345678901234567890",
        "s": "1",
        "p": "ETestSaid1234567890123456789012345678901",
        "kt": "1",
        "k": ["DNewKey123456789012345678901234567890123"],
        "nt": "1",
        "n": ["ENewNext12345678901234567890123456789012"],
        "bt": "0",
        "b": [],
        "a": [],
        "x": x
    })
}

fn make_test_ixn(sig: Option<&[u8; 64]>) -> serde_json::Value {
    let x = sig.map(|s| URL_SAFE_NO_PAD.encode(s)).unwrap_or_default();
    serde_json::json!({
        "v": "KERI10JSON000000_",
        "t": "ixn",
        "d": "ETestIxnSaid23456789012345678901234567890",
        "i": "ETestPrefix123456789012345678901234567890",
        "s": "2",
        "p": "ETestRotSaid23456789012345678901234567890",
        "a": [{"d": "ESealDigest234567890123456789012345678901", "type": "device-attestation"}],
        "x": x
    })
}

#[test]
fn icp_output_has_no_x_field() {
    let codec = CesrV1Codec::new();
    let sig = [42u8; 64];
    let event = make_test_icp(Some(&sig));
    let result = serialize_for_cesr(&codec, &event).unwrap();

    let body: serde_json::Value = serde_json::from_slice(&result.body_bytes).unwrap();
    assert!(
        body.get("x").is_none(),
        "x field must not appear in CESR output"
    );
}

#[test]
fn icp_said_is_44_chars_starting_with_e() {
    let codec = CesrV1Codec::new();
    let event = make_test_icp(None);
    let result = serialize_for_cesr(&codec, &event).unwrap();

    assert_eq!(result.said.len(), 44);
    assert!(
        result.said.starts_with('E'),
        "SAID must start with 'E' (Blake3 derivation code)"
    );
}

#[test]
fn icp_body_has_d_equals_said_and_i_equals_said() {
    let codec = CesrV1Codec::new();
    let event = make_test_icp(None);
    let result = serialize_for_cesr(&codec, &event).unwrap();

    let body: serde_json::Value = serde_json::from_slice(&result.body_bytes).unwrap();
    let d = body.get("d").and_then(|v| v.as_str()).unwrap();
    let i = body.get("i").and_then(|v| v.as_str()).unwrap();
    assert_eq!(d, result.said, "d must equal computed SAID");
    assert_eq!(
        i, result.said,
        "i must equal d for inception (self-certifying)"
    );
}

#[test]
fn icp_version_string_has_correct_hex_count() {
    let codec = CesrV1Codec::new();
    let event = make_test_icp(None);
    let result = serialize_for_cesr(&codec, &event).unwrap();

    let body: serde_json::Value = serde_json::from_slice(&result.body_bytes).unwrap();
    let v = body.get("v").and_then(|v| v.as_str()).unwrap();
    assert!(v.starts_with("KERI10JSON"));
    assert!(v.ends_with('_'));

    let hex_part = &v[10..16];
    let declared_size = usize::from_str_radix(hex_part, 16).unwrap();
    assert_eq!(
        declared_size,
        result.body_bytes.len(),
        "version string hex must match body byte count"
    );
}

#[test]
fn icp_keys_are_cesr_qualified() {
    let codec = CesrV1Codec::new();
    let event = make_test_icp(None);
    let result = serialize_for_cesr(&codec, &event).unwrap();

    let body: serde_json::Value = serde_json::from_slice(&result.body_bytes).unwrap();
    let keys = body.get("k").and_then(|v| v.as_array()).unwrap();
    for key in keys {
        let k = key.as_str().unwrap();
        assert!(
            k.starts_with('D'),
            "key must be CESR-qualified (D prefix): {k}"
        );
    }
}

#[test]
fn icp_signature_bytes_extracted_from_x() {
    let codec = CesrV1Codec::new();
    let sig = [42u8; 64];
    let event = make_test_icp(Some(&sig));
    let result = serialize_for_cesr(&codec, &event).unwrap();

    let sig_bytes = result.signature_bytes.expect("should have signature");
    assert_eq!(sig_bytes.len(), 64);
    assert_eq!(sig_bytes, sig.to_vec());
}

#[test]
fn no_signature_when_x_empty() {
    let codec = CesrV1Codec::new();
    let event = make_test_icp(None);
    let result = serialize_for_cesr(&codec, &event).unwrap();
    assert!(result.signature_bytes.is_none());
}

#[test]
fn rot_serialization_produces_valid_output() {
    let codec = CesrV1Codec::new();
    let sig = [99u8; 64];
    let event = make_test_rot(Some(&sig));
    let result = serialize_for_cesr(&codec, &event).unwrap();

    let body: serde_json::Value = serde_json::from_slice(&result.body_bytes).unwrap();
    assert!(body.get("x").is_none());
    assert_eq!(result.said.len(), 44);

    let d = body.get("d").and_then(|v| v.as_str()).unwrap();
    assert_eq!(d, result.said);

    let i = body.get("i").and_then(|v| v.as_str()).unwrap();
    assert_ne!(i, result.said, "rotation i should keep original prefix");

    let sig_bytes = result.signature_bytes.unwrap();
    assert_eq!(sig_bytes, [99u8; 64].to_vec());
}

#[test]
fn ixn_serialization_produces_valid_output() {
    let codec = CesrV1Codec::new();
    let event = make_test_ixn(None);
    let result = serialize_for_cesr(&codec, &event).unwrap();

    let body: serde_json::Value = serde_json::from_slice(&result.body_bytes).unwrap();
    assert!(body.get("x").is_none());
    assert_eq!(result.said.len(), 44);

    let d = body.get("d").and_then(|v| v.as_str()).unwrap();
    assert_eq!(d, result.said);

    let a = body.get("a").and_then(|v| v.as_array()).unwrap();
    assert_eq!(a.len(), 1, "seals must be preserved");
}

#[test]
fn said_is_deterministic_across_calls() {
    let codec = CesrV1Codec::new();
    let event = make_test_icp(None);
    let result1 = serialize_for_cesr(&codec, &event).unwrap();
    let result2 = serialize_for_cesr(&codec, &event).unwrap();
    assert_eq!(result1.said, result2.said);
    assert_eq!(result1.body_bytes, result2.body_bytes);
}
