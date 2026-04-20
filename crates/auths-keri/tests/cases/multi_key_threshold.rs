//! Readiness tests for `Threshold::Weighted` + multi-sig validator.
//!
//! Confirms that:
//!   (1) `Threshold::Weighted(vec![vec![1/2, 1/2, 1/2]])` serializes to
//!       `"kt": [["1/2","1/2","1/2"]]` inside an `IcpEvent` and round-trips
//!       back unchanged (plus scalar `Simple(2)` → `"2"` control).
//!   (2) `validate_signed_event` against a 3-key inception with a weighted
//!       threshold accepts any 2-of-3 signatures and rejects 1-of-3 and 0-of-3.

use auths_keri::{
    CesrKey, Event, Fraction, IcpEvent, IndexedSignature, KeriSequence, Prefix, Said, SignedEvent,
    Threshold, ValidationError, VersionString, finalize_icp_event, serialize_for_signing,
    validate_signed_event,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

fn gen_keypair() -> Ed25519KeyPair {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
}

fn cesr_pub(kp: &Ed25519KeyPair) -> String {
    format!("D{}", URL_SAFE_NO_PAD.encode(kp.public_key().as_ref()))
}

fn half() -> Fraction {
    Fraction {
        numerator: 1,
        denominator: 2,
    }
}

fn weighted_halves_3() -> Threshold {
    Threshold::Weighted(vec![vec![half(), half(), half()]])
}

/// Build a finalized 3-key inception event with weighted `["1/2","1/2","1/2"]`
/// thresholds for both signing and rotation. Returns the event + the three
/// keypairs in the same order as `k`.
fn make_three_key_icp() -> (IcpEvent, [Ed25519KeyPair; 3]) {
    let kps = [gen_keypair(), gen_keypair(), gen_keypair()];
    let k = vec![
        CesrKey::new_unchecked(cesr_pub(&kps[0])),
        CesrKey::new_unchecked(cesr_pub(&kps[1])),
        CesrKey::new_unchecked(cesr_pub(&kps[2])),
    ];
    let n = vec![
        Said::new_unchecked("EFakeNextCommitment000000000000000000000000".to_string()),
        Said::new_unchecked("EFakeNextCommitment000000000000000000000001".to_string()),
        Said::new_unchecked("EFakeNextCommitment000000000000000000000002".to_string()),
    ];

    let icp = IcpEvent {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: Prefix::default(),
        s: KeriSequence::new(0),
        kt: weighted_halves_3(),
        k,
        nt: weighted_halves_3(),
        n,
        bt: Threshold::Simple(0),
        b: vec![],
        c: vec![],
        a: vec![],
        dt: None,
    };

    let finalized = finalize_icp_event(icp).unwrap();
    (finalized, kps)
}

fn sign_icp(icp: &IcpEvent, kp: &Ed25519KeyPair, index: u32) -> IndexedSignature {
    let canonical = serialize_for_signing(&Event::Icp(icp.clone())).unwrap();
    IndexedSignature {
        index,
        sig: kp.sign(&canonical).as_ref().to_vec(),
    }
}

/// Serialization round-trip: `Threshold::Weighted(vec![vec![1/2,1/2,1/2]])`
/// embedded in an `IcpEvent` must emit `"kt": [["1/2","1/2","1/2"]]`, and
/// `Threshold::Simple(2)` must emit `"kt": "2"` (hex).
#[test]
fn threshold_weighted_roundtrip_serialization() {
    let (icp, _kps) = make_three_key_icp();
    let event = Event::Icp(icp.clone());

    // Serialize the event and inspect the `kt`/`nt` shape.
    let json = serde_json::to_value(&event).unwrap();
    let body = json.as_object().unwrap();

    let kt = body.get("kt").unwrap();
    let expected_kt: serde_json::Value = serde_json::json!([["1/2", "1/2", "1/2"]]);
    assert_eq!(kt, &expected_kt, "kt must serialize as [[\"1/2\",...]]");

    let nt = body.get("nt").unwrap();
    assert_eq!(nt, &expected_kt, "nt must serialize as [[\"1/2\",...]]");

    // Round-trip back and confirm the threshold survives unchanged.
    let s = serde_json::to_string(&event).unwrap();
    let decoded: Event = serde_json::from_str(&s).unwrap();
    match decoded {
        Event::Icp(round) => {
            assert_eq!(round.kt, weighted_halves_3());
            assert_eq!(round.nt, weighted_halves_3());
        }
        _ => panic!("expected Icp after round-trip"),
    }

    // Scalar control: Threshold::Simple(2) serializes as the hex string "2".
    let scalar = Threshold::Simple(2);
    let s2 = serde_json::to_string(&scalar).unwrap();
    assert_eq!(s2, "\"2\"", "Simple(2) must serialize as hex \"2\"");
    let back: Threshold = serde_json::from_str(&s2).unwrap();
    assert_eq!(back, Threshold::Simple(2));
}

/// With `kt: ["1/2","1/2","1/2"]`, any 2-of-3 valid signatures satisfy the
/// threshold (1/2 + 1/2 = 1); 1-of-3 and 0-of-3 must be rejected.
#[test]
fn validator_weighted_two_of_three() {
    let (icp, kps) = make_three_key_icp();
    let sig0 = sign_icp(&icp, &kps[0], 0);
    let sig1 = sign_icp(&icp, &kps[1], 1);
    let sig2 = sign_icp(&icp, &kps[2], 2);

    // 0-of-3: empty signatures must fail.
    let empty = SignedEvent::new(Event::Icp(icp.clone()), vec![]);
    assert!(matches!(
        validate_signed_event(&empty, None),
        Err(ValidationError::SignatureFailed { .. })
    ));

    // 1-of-3: single signature cannot meet 1/2 + 1/2 >= 1.
    for single in [&sig0, &sig1, &sig2] {
        let signed = SignedEvent::new(Event::Icp(icp.clone()), vec![single.clone()]);
        assert!(
            matches!(
                validate_signed_event(&signed, None),
                Err(ValidationError::SignatureFailed { .. })
            ),
            "single signature at index {} must not satisfy 1/2,1/2,1/2",
            single.index
        );
    }

    // 2-of-3: every pair sums to exactly 1 and must be accepted.
    for pair in [
        vec![sig0.clone(), sig1.clone()],
        vec![sig0.clone(), sig2.clone()],
        vec![sig1.clone(), sig2.clone()],
    ] {
        let indices: Vec<u32> = pair.iter().map(|s| s.index).collect();
        let signed = SignedEvent::new(Event::Icp(icp.clone()), pair);
        validate_signed_event(&signed, None).unwrap_or_else(|e| {
            panic!(
                "pair {:?} must satisfy weighted threshold but got {:?}",
                indices, e
            )
        });
    }

    // 3-of-3 also passes (sanity check).
    let all = SignedEvent::new(Event::Icp(icp.clone()), vec![sig0, sig1, sig2]);
    validate_signed_event(&all, None).unwrap();
}

/// Out-of-range index in a signature list is silently skipped by the
/// validator, so a lone out-of-range signature must fail the threshold.
#[test]
fn validator_out_of_range_index_rejected() {
    let (icp, kps) = make_three_key_icp();
    let mut sig = sign_icp(&icp, &kps[0], 99);
    // Force an index past the key list.
    sig.index = 99;

    let signed = SignedEvent::new(Event::Icp(icp), vec![sig]);
    assert!(matches!(
        validate_signed_event(&signed, None),
        Err(ValidationError::SignatureFailed { .. })
    ));
}
