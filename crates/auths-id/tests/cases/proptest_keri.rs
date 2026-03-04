use auths_core::crypto::said::{compute_next_commitment, compute_said};
use auths_id::keri::{
    Event, IcpEvent, IxnEvent, KERI_VERSION, KeriSequence, Prefix, RotEvent, Said, Seal,
    ValidationError, finalize_icp_event, serialize_for_signing, validate_kel, verify_event_said,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use proptest::prelude::*;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

fn gen_keypair() -> Ed25519KeyPair {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
}

fn encode_pubkey(kp: &Ed25519KeyPair) -> String {
    format!("D{}", URL_SAFE_NO_PAD.encode(kp.public_key().as_ref()))
}

fn sign_event(event: &Event, kp: &Ed25519KeyPair) -> String {
    let canonical = serialize_for_signing(event).unwrap();
    URL_SAFE_NO_PAD.encode(kp.sign(&canonical).as_ref())
}

fn make_signed_icp(kp: &Ed25519KeyPair, next_commitment: &str) -> IcpEvent {
    let icp = IcpEvent {
        v: KERI_VERSION.to_string(),
        d: Said::default(),
        i: Prefix::default(),
        s: KeriSequence::new(0),
        kt: "1".to_string(),
        k: vec![encode_pubkey(kp)],
        nt: "1".to_string(),
        n: vec![next_commitment.to_string()],
        bt: "0".to_string(),
        b: vec![],
        a: vec![],
        x: String::new(),
    };

    let mut finalized = finalize_icp_event(icp).unwrap();
    finalized.x = sign_event(&Event::Icp(finalized.clone()), kp);
    finalized
}

fn make_signed_ixn(
    prefix: &Prefix,
    prev_said: &Said,
    seq: u64,
    kp: &Ed25519KeyPair,
    seals: Vec<Seal>,
) -> IxnEvent {
    let mut ixn = IxnEvent {
        v: KERI_VERSION.to_string(),
        d: Said::default(),
        i: prefix.clone(),
        s: KeriSequence::new(seq),
        p: prev_said.clone(),
        a: seals,
        x: String::new(),
    };

    let json = serde_json::to_vec(&Event::Ixn(ixn.clone())).unwrap();
    ixn.d = compute_said(&json);
    ixn.x = sign_event(&Event::Ixn(ixn.clone()), kp);
    ixn
}

fn make_signed_rot(
    prefix: &Prefix,
    prev_said: &Said,
    seq: u64,
    new_kp: &Ed25519KeyPair,
    next_commitment: &str,
) -> RotEvent {
    let mut rot = RotEvent {
        v: KERI_VERSION.to_string(),
        d: Said::default(),
        i: prefix.clone(),
        s: KeriSequence::new(seq),
        p: prev_said.clone(),
        kt: "1".to_string(),
        k: vec![encode_pubkey(new_kp)],
        nt: "1".to_string(),
        n: vec![next_commitment.to_string()],
        bt: "0".to_string(),
        b: vec![],
        a: vec![],
        x: String::new(),
    };

    let json = serde_json::to_vec(&Event::Rot(rot.clone())).unwrap();
    rot.d = compute_said(&json);
    rot.x = sign_event(&Event::Rot(rot.clone()), new_kp);
    rot
}

fn build_valid_kel(ixn_count: usize) -> Vec<Event> {
    let kp = gen_keypair();
    let next_kp = gen_keypair();
    let next_commitment = compute_next_commitment(next_kp.public_key().as_ref());

    let icp = make_signed_icp(&kp, &next_commitment);
    let prefix = icp.i.clone();
    let mut events: Vec<Event> = vec![Event::Icp(icp.clone())];
    let mut prev_said = icp.d.clone();

    for i in 0..ixn_count {
        let ixn = make_signed_ixn(
            &prefix,
            &prev_said,
            (i + 1) as u64,
            &kp,
            vec![Seal::device_attestation(format!("EAttest{i}"))],
        );
        prev_said = ixn.d.clone();
        events.push(Event::Ixn(ixn));
    }

    events
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]

    #[test]
    fn said_integrity_recompute_matches(ixn_count in 0..5usize) {
        let events = build_valid_kel(ixn_count);
        for event in &events {
            prop_assert!(verify_event_said(event).is_ok(), "SAID verification failed for event s={}", event.sequence().value());
        }
    }

    #[test]
    fn duplicate_sequence_rejected(ixn_count in 1..4usize) {
        let events = build_valid_kel(ixn_count);
        // Duplicate the last event
        let mut bad_events = events.clone();
        bad_events.push(events.last().unwrap().clone());

        let result = validate_kel(&bad_events);
        prop_assert!(result.is_err());
        match result.unwrap_err() {
            ValidationError::InvalidSequence { .. }
            | ValidationError::BrokenChain { .. }
            | ValidationError::SignatureFailed { .. } => {}
            e => prop_assert!(false, "Expected sequence/chain/sig error, got: {:?}", e),
        }
    }

    #[test]
    fn broken_chain_rejected(ixn_count in 1..4usize) {
        let mut events = build_valid_kel(ixn_count);
        // Corrupt the `p` field of the last event
        if let Some(Event::Ixn(ixn)) = events.last_mut() {
            ixn.p = Said::new_unchecked("ECorruptedPreviousSaidThatDoesNotMatch00000000".to_string());
        }

        let result = validate_kel(&events);
        prop_assert!(result.is_err());
        match result.unwrap_err() {
            // Corrupting `p` changes serialization, so SAID check fails first
            ValidationError::InvalidSaid { .. }
            | ValidationError::BrokenChain { .. }
            | ValidationError::SignatureFailed { .. } => {}
            e => prop_assert!(false, "Expected InvalidSaid, BrokenChain, or SignatureFailed, got: {:?}", e),
        }
    }

    #[test]
    fn multiple_inception_rejected(ixn_count in 0..3usize) {
        let events = build_valid_kel(ixn_count);
        // Append another inception
        let extra_kp = gen_keypair();
        let extra_next = gen_keypair();
        let extra_icp = make_signed_icp(&extra_kp, &compute_next_commitment(extra_next.public_key().as_ref()));
        let mut bad_events = events;
        bad_events.push(Event::Icp(extra_icp));

        let result = validate_kel(&bad_events);
        prop_assert!(result.is_err());
        match result.unwrap_err() {
            ValidationError::MultipleInceptions
            | ValidationError::InvalidSequence { .. } => {}
            e => prop_assert!(false, "Expected MultipleInceptions or InvalidSequence, got: {:?}", e),
        }
    }

    #[test]
    fn wrong_rotation_key_rejected(_dummy in 0..5u8) {
        let kp = gen_keypair();
        let next_kp = gen_keypair();
        let wrong_kp = gen_keypair();
        let next_commitment = compute_next_commitment(next_kp.public_key().as_ref());

        let icp = make_signed_icp(&kp, &next_commitment);
        let prefix = icp.i.clone();
        let prev_said = icp.d.clone();
        let mut events: Vec<Event> = vec![Event::Icp(icp)];

        // Rotate with the WRONG key (not the pre-committed one)
        let future_kp = gen_keypair();
        let rot = make_signed_rot(
            &prefix,
            &prev_said,
            1,
            &wrong_kp,
            &compute_next_commitment(future_kp.public_key().as_ref()),
        );
        events.push(Event::Rot(rot));

        let result = validate_kel(&events);
        prop_assert!(result.is_err());
        match result.unwrap_err() {
            ValidationError::CommitmentMismatch { .. }
            | ValidationError::SignatureFailed { .. } => {}
            e => prop_assert!(false, "Expected CommitmentMismatch or SignatureFailed, got: {:?}", e),
        }
    }

    #[test]
    fn valid_kel_replay_idempotent(ixn_count in 0..5usize) {
        let events = build_valid_kel(ixn_count);
        let state1 = validate_kel(&events).expect("first validation should succeed");
        let state2 = validate_kel(&events).expect("second validation should succeed");
        prop_assert_eq!(state1, state2);
    }

    #[test]
    fn valid_kel_with_rotation_replays_correctly(_dummy in 0..5u8) {
        let kp1 = gen_keypair();
        let kp2 = gen_keypair();
        let kp3 = gen_keypair();
        let commitment2 = compute_next_commitment(kp2.public_key().as_ref());
        let commitment3 = compute_next_commitment(kp3.public_key().as_ref());

        let icp = make_signed_icp(&kp1, &commitment2);
        let prefix = icp.i.clone();
        let prev_said = icp.d.clone();

        let rot = make_signed_rot(&prefix, &prev_said, 1, &kp2, &commitment3);
        let rot_said = rot.d.clone();

        let ixn = make_signed_ixn(
            &prefix,
            &rot_said,
            2,
            &kp2,
            vec![Seal::device_attestation("EPostRotAttest")],
        );

        let events = vec![Event::Icp(icp), Event::Rot(rot), Event::Ixn(ixn)];
        let state = validate_kel(&events).expect("valid KEL should validate");

        prop_assert_eq!(state.sequence, 2);
        prop_assert_eq!(state.current_keys, vec![encode_pubkey(&kp2)]);
        prop_assert_eq!(state.next_commitment, vec![commitment3]);
    }
}
