use auths_keri::{CesrV1Codec, export_kel_as_cesr, import_cesr_to_events};
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
        x: URL_SAFE_NO_PAD.encode([10u8; 64]),
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
        x: URL_SAFE_NO_PAD.encode([20u8; 64]),
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
        x: URL_SAFE_NO_PAD.encode([30u8; 64]),
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

    assert!(matches!(reimported[0], KeriEvent::Inception(_)));
    assert!(matches!(reimported[1], KeriEvent::Rotation(_)));
    assert!(matches!(reimported[2], KeriEvent::Interaction(_)));
}

#[test]
fn roundtrip_preserves_keys_and_commitments() {
    let codec = CesrV1Codec::new();
    let events = [make_signed_icp()];
    let stream = export_kel_as_cesr(&codec, &events).unwrap();
    let reimported = import_cesr_to_events(&codec, &stream.bytes).unwrap();

    let KeriEvent::Inception(original) = &events[0] else {
        panic!()
    };
    let KeriEvent::Inception(reimported) = &reimported[0] else {
        panic!()
    };

    assert_eq!(reimported.k, original.k, "keys must survive round-trip");
    assert_eq!(
        reimported.n, original.n,
        "commitments must survive round-trip"
    );
    assert_eq!(reimported.kt, original.kt);
    assert_eq!(reimported.nt, original.nt);
    assert_eq!(reimported.s, "0");
}

#[test]
fn roundtrip_reimported_events_have_x_field() {
    let codec = CesrV1Codec::new();
    let events = [make_signed_icp()];
    let stream = export_kel_as_cesr(&codec, &events).unwrap();
    let reimported = import_cesr_to_events(&codec, &stream.bytes).unwrap();

    let KeriEvent::Inception(icp) = &reimported[0] else {
        panic!()
    };
    assert!(!icp.x.is_empty(), "reimported event must have x field");

    let sig_bytes = URL_SAFE_NO_PAD.decode(&icp.x).unwrap();
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

    let KeriEvent::Interaction(ixn) = &reimported[0] else {
        panic!()
    };
    assert_eq!(ixn.a.len(), 1);
    assert_eq!(ixn.a[0].seal_type, "device-attestation");
}

#[test]
fn roundtrip_multi_event_preserves_chain_links() {
    let codec = CesrV1Codec::new();
    let events = [make_signed_icp(), make_signed_rot(), make_signed_ixn()];
    let stream = export_kel_as_cesr(&codec, &events).unwrap();
    let reimported = import_cesr_to_events(&codec, &stream.bytes).unwrap();

    let KeriEvent::Rotation(rot) = &reimported[1] else {
        panic!()
    };
    let KeriEvent::Interaction(ixn) = &reimported[2] else {
        panic!()
    };

    // Chain links (p fields) should be populated with spec SAIDs, not original SAIDs.
    assert!(!rot.p.is_empty(), "rotation must have p field");
    assert!(!ixn.p.is_empty(), "interaction must have p field");
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
    assert!(matches!(reimported[0], KeriEvent::Rotation(_)));
}
