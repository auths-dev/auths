use auths_keri::{CesrV1Codec, assemble_cesr_stream, serialize_for_cesr};
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
        "x": URL_SAFE_NO_PAD.encode([1u8; 64])
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
        "x": URL_SAFE_NO_PAD.encode([2u8; 64])
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
        "x": URL_SAFE_NO_PAD.encode([3u8; 64])
    })
}

#[test]
fn single_event_stream_starts_with_json_followed_by_attachment() {
    let codec = CesrV1Codec::new();
    let event = make_signed_icp();
    let serialized = serialize_for_cesr(&codec, &event).unwrap();
    let stream = assemble_cesr_stream(&codec, &[serialized]).unwrap();

    assert_eq!(stream.event_count, 1);
    assert_eq!(stream.bytes[0], b'{', "stream must start with JSON body");

    let stream_str = std::str::from_utf8(&stream.bytes).unwrap();
    assert!(
        stream_str.contains("-AAB"),
        "stream must contain counter code for 1 sig"
    );
}

#[test]
fn three_event_stream_contains_three_bodies_with_attachments() {
    let codec = CesrV1Codec::new();
    let events = [make_signed_icp(), make_signed_rot(), make_signed_ixn()];
    let serialized: Vec<_> = events
        .iter()
        .map(|e| serialize_for_cesr(&codec, e).unwrap())
        .collect();
    let stream = assemble_cesr_stream(&codec, &serialized).unwrap();

    assert_eq!(stream.event_count, 3);

    let stream_str = std::str::from_utf8(&stream.bytes).unwrap();
    let counter_count = stream_str.matches("-AAB").count();
    assert_eq!(counter_count, 3, "3 events = 3 counter codes");
}

#[test]
fn stream_byte_count_matches_sum_of_parts() {
    let codec = CesrV1Codec::new();
    let events = [make_signed_icp(), make_signed_rot()];
    let serialized: Vec<_> = events
        .iter()
        .map(|e| serialize_for_cesr(&codec, e).unwrap())
        .collect();

    let expected: usize = serialized
        .iter()
        .map(|s| {
            let attachment_size = if s.signature_bytes.is_some() {
                4 + 88
            } else {
                0
            };
            s.body_bytes.len() + attachment_size
        })
        .sum();

    let stream = assemble_cesr_stream(&codec, &serialized).unwrap();
    assert_eq!(stream.bytes.len(), expected);
}

#[test]
fn event_without_signature_omits_attachment() {
    let codec = CesrV1Codec::new();
    let event = serde_json::json!({
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
        "x": ""
    });
    let serialized = serialize_for_cesr(&codec, &event).unwrap();
    let stream = assemble_cesr_stream(&codec, std::slice::from_ref(&serialized)).unwrap();

    assert_eq!(
        stream.bytes.len(),
        serialized.body_bytes.len(),
        "no signature = no attachment bytes"
    );
    let stream_str = std::str::from_utf8(&stream.bytes).unwrap();
    assert!(
        !stream_str.contains("-AA"),
        "no counter code when no signature"
    );
}
