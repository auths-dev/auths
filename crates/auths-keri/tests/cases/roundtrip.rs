use auths_keri::{CesrV1Codec, export_kel_as_cesr, import_cesr_to_events};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

fn make_signed_icp() -> serde_json::Value {
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
        "x": URL_SAFE_NO_PAD.encode([10u8; 64])
    })
}

fn make_signed_rot() -> serde_json::Value {
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
        "x": URL_SAFE_NO_PAD.encode([20u8; 64])
    })
}

fn make_signed_ixn() -> serde_json::Value {
    serde_json::json!({
        "v": "KERI10JSON000000_",
        "t": "ixn",
        "d": "ETestIxnSaid23456789012345678901234567890",
        "i": "ETestPrefix123456789012345678901234567890",
        "s": "2",
        "p": "ETestRotSaid23456789012345678901234567890",
        "a": [{"d": "ESealDigest234567890123456789012345678901", "type": "device-attestation"}],
        "x": URL_SAFE_NO_PAD.encode([30u8; 64])
    })
}

#[test]
fn export_produces_nonempty_stream_with_correct_count() {
    let codec = CesrV1Codec::new();
    let events = [make_signed_icp(), make_signed_rot(), make_signed_ixn()];
    let stream = export_kel_as_cesr(&codec, &events).unwrap();

    assert!(!stream.bytes.is_empty());
    assert_eq!(stream.event_count, 3);
}

#[test]
fn import_parses_back_correct_event_count() {
    let codec = CesrV1Codec::new();
    let events = [make_signed_icp(), make_signed_rot(), make_signed_ixn()];
    let stream = export_kel_as_cesr(&codec, &events).unwrap();

    let reimported = import_cesr_to_events(&codec, &stream.bytes).unwrap();
    assert_eq!(reimported.len(), 3);
}

#[test]
fn roundtrip_preserves_event_types() {
    let codec = CesrV1Codec::new();
    let events = [make_signed_icp(), make_signed_rot(), make_signed_ixn()];
    let stream = export_kel_as_cesr(&codec, &events).unwrap();
    let reimported = import_cesr_to_events(&codec, &stream.bytes).unwrap();

    assert_eq!(reimported[0].get("t").and_then(|v| v.as_str()), Some("icp"));
    assert_eq!(reimported[1].get("t").and_then(|v| v.as_str()), Some("rot"));
    assert_eq!(reimported[2].get("t").and_then(|v| v.as_str()), Some("ixn"));
}

#[test]
fn roundtrip_preserves_keys_and_commitments() {
    let codec = CesrV1Codec::new();
    let events = [make_signed_icp()];
    let stream = export_kel_as_cesr(&codec, &events).unwrap();
    let reimported = import_cesr_to_events(&codec, &stream.bytes).unwrap();

    let original = &events[0];
    let reimported = &reimported[0];

    assert_eq!(
        reimported["k"], original["k"],
        "keys must survive round-trip"
    );
    assert_eq!(
        reimported["n"], original["n"],
        "commitments must survive round-trip"
    );
    assert_eq!(reimported["kt"], original["kt"]);
    assert_eq!(reimported["nt"], original["nt"]);
    assert_eq!(reimported["s"], "0");
}

#[test]
fn roundtrip_reimported_events_have_x_field() {
    let codec = CesrV1Codec::new();
    let events = [make_signed_icp()];
    let stream = export_kel_as_cesr(&codec, &events).unwrap();
    let reimported = import_cesr_to_events(&codec, &stream.bytes).unwrap();

    let x = reimported[0]["x"]
        .as_str()
        .expect("x field must be present");
    assert!(!x.is_empty(), "reimported event must have x field");

    let sig_bytes = URL_SAFE_NO_PAD.decode(x).unwrap();
    assert_eq!(sig_bytes.len(), 64, "signature must be 64 bytes");
    assert_eq!(
        sig_bytes,
        [10u8; 64].to_vec(),
        "signature content must match"
    );
}

#[test]
fn roundtrip_preserves_seals() {
    let codec = CesrV1Codec::new();
    let events = [make_signed_ixn()];
    let stream = export_kel_as_cesr(&codec, &events).unwrap();
    let reimported = import_cesr_to_events(&codec, &stream.bytes).unwrap();

    let a = reimported[0]["a"].as_array().expect("a must be array");
    assert_eq!(a.len(), 1);
    assert_eq!(a[0]["type"], "device-attestation");
}

#[test]
fn roundtrip_multi_event_preserves_chain_links() {
    let codec = CesrV1Codec::new();
    let events = [make_signed_icp(), make_signed_rot(), make_signed_ixn()];
    let stream = export_kel_as_cesr(&codec, &events).unwrap();
    let reimported = import_cesr_to_events(&codec, &stream.bytes).unwrap();

    let rot_p = reimported[1]["p"].as_str().expect("rot must have p field");
    let ixn_p = reimported[2]["p"].as_str().expect("ixn must have p field");

    assert!(!rot_p.is_empty(), "rotation must have p field");
    assert!(!ixn_p.is_empty(), "interaction must have p field");
}

#[test]
fn import_empty_stream_returns_empty() {
    let codec = CesrV1Codec::new();
    let events = import_cesr_to_events(&codec, &[]).unwrap();
    assert!(events.is_empty());
}

#[test]
fn export_single_event_roundtrip() {
    let codec = CesrV1Codec::new();
    let events = [make_signed_rot()];
    let stream = export_kel_as_cesr(&codec, &events).unwrap();
    let reimported = import_cesr_to_events(&codec, &stream.bytes).unwrap();
    assert_eq!(reimported.len(), 1);
    assert_eq!(reimported[0].get("t").and_then(|v| v.as_str()), Some("rot"));
}
