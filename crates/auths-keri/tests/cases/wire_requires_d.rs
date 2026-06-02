//! A.3 — a KERI event must carry a non-empty SAID `d` on the wire.
//!
//! An event JSON with the `d` key **omitted**, or present but **empty**
//! (`"d":""`), must fail to deserialize. A finalized event (real SAID)
//! must still round-trip unchanged.

use auths_keri::{
    CesrKey, Event, IcpEvent, KeriPublicKey, KeriSequence, Prefix, Said, Threshold, VersionString,
    finalize_icp_event,
};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::Value;

fn cesr_pub() -> String {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    KeriPublicKey::ed25519(kp.public_key().as_ref())
        .unwrap()
        .to_qb64()
        .unwrap()
}

fn finalized_icp() -> IcpEvent {
    let icp = IcpEvent {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: Prefix::default(),
        s: KeriSequence::new(0),
        kt: Threshold::Simple(1),
        k: vec![CesrKey::new_unchecked(cesr_pub())],
        nt: Threshold::Simple(1),
        n: vec![Said::new_unchecked(
            "EFakeNextCommitment0000000000000000000000000".to_string(),
        )],
        bt: Threshold::Simple(0),
        b: vec![],
        c: vec![],
        a: vec![],
    };
    finalize_icp_event(icp).unwrap()
}

#[test]
fn event_without_d_is_rejected() {
    let mut v = serde_json::to_value(Event::Icp(finalized_icp())).unwrap();
    v.as_object_mut().unwrap().remove("d");
    let json = serde_json::to_string(&v).unwrap();
    assert!(
        serde_json::from_str::<Event>(&json).is_err(),
        "an event JSON with `d` omitted must fail to parse: {json}"
    );
}

#[test]
fn event_with_empty_d_is_rejected() {
    let mut v = serde_json::to_value(Event::Icp(finalized_icp())).unwrap();
    v.as_object_mut()
        .unwrap()
        .insert("d".to_string(), Value::String(String::new()));
    let json = serde_json::to_string(&v).unwrap();
    assert!(
        serde_json::from_str::<Event>(&json).is_err(),
        "an event JSON with `d:\"\"` must fail to parse: {json}"
    );
}

#[test]
fn finalized_icp_round_trips() {
    let icp = finalized_icp();
    let json = serde_json::to_string(&Event::Icp(icp.clone())).unwrap();
    match serde_json::from_str::<Event>(&json).expect("finalized icp must parse") {
        Event::Icp(parsed) => assert_eq!(parsed, icp, "finalized icp must round-trip unchanged"),
        other => panic!("expected icp, got {other:?}"),
    }
}
