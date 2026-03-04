use auths_keri::{CesrV1Codec, assemble_cesr_stream, serialize_for_cesr};
use auths_verifier::keri::{IcpEvent, IxnEvent, KeriEvent, Prefix, RotEvent, Said, Seal};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

fn make_signed_icp() -> KeriEvent {
    KeriEvent::Inception(IcpEvent {
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
        x: URL_SAFE_NO_PAD.encode([1u8; 64]),
    })
}

fn make_signed_rot() -> KeriEvent {
    KeriEvent::Rotation(RotEvent {
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
        x: URL_SAFE_NO_PAD.encode([2u8; 64]),
    })
}

fn make_signed_ixn() -> KeriEvent {
    KeriEvent::Interaction(IxnEvent {
        v: "KERI10JSON000000_".into(),
        d: Said::new_unchecked("ETestIxnSaid23456789012345678901234567890".into()),
        i: Prefix::new_unchecked("ETestPrefix123456789012345678901234567890".into()),
        s: "2".into(),
        p: Said::new_unchecked("ETestRotSaid23456789012345678901234567890".into()),
        a: vec![Seal {
            d: Said::new_unchecked("ESealDigest234567890123456789012345678901".into()),
            seal_type: "device-attestation".into(),
        }],
        x: URL_SAFE_NO_PAD.encode([3u8; 64]),
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

    // Compute expected size: body + counter code (4 bytes) + signature (88 bytes) per event.
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
    let event = KeriEvent::Inception(IcpEvent {
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
        x: String::new(),
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
