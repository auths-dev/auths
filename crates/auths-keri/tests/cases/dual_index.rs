//! Epic B — dual-index CESR signature attachment parsing & emission.
//!
//! Oracle: `tests/fixtures/keripy/rot_remove.rot.att` — keripy 1.3.4's `-AAC`
//! group of two `2A` (Ed25519_Big) sigers for a 3→2 key removal: new `k[0]`
//! reveals prior `n[1]`, new `k[1]` reveals prior `n[2]`.

use auths_keri::{
    Event, IndexedSignature, SignedEvent, ValidationError, parse_attachment, replay_kel,
    serialize_attachment, validate_signed_event,
};
use std::path::Path;

fn fixture(name: &str) -> Vec<u8> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/keripy")
        .join(name);
    std::fs::read(&p).unwrap_or_else(|_| panic!("fixture missing: {}", p.display()))
}

fn load_event(name: &str) -> Event {
    serde_json::from_slice(&fixture(name)).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

/// Our code-directed parser must read keripy's dual-index attachment with the
/// correct `(index, prior_index)` pairs.
#[test]
fn parses_keripy_rot_remove_attachment() {
    let att = fixture("rot_remove.rot.att");
    let sigs = parse_attachment(&att).expect("keripy dual-index attachment must parse");
    assert_eq!(sigs.len(), 2, "expected two sigers");
    assert_eq!((sigs[0].index, sigs[0].prior_index), (0, Some(1)));
    assert_eq!((sigs[1].index, sigs[1].prior_index), (1, Some(2)));
}

/// A heterogeneous group — single-index `A` (88 ch) followed by dual-index `2A`
/// (92 ch) — must parse at code-directed boundaries; `prior_index` is `Some`
/// only for the dual-index siger.
#[test]
fn mixed_curve_attachment_parses() {
    // One single-index `A` siger via our emitter (88 chars after the -AAB header).
    let a = serialize_attachment(&[IndexedSignature {
        index: 5,
        prior_index: None,
        sig: vec![7u8; 64],
    }])
    .unwrap();
    let a_siger = &a[4..];
    assert_eq!(a_siger.len(), 88, "single-index Ed25519 siger is 88 chars");

    // One dual-index `2A` siger from the keripy fixture (92 chars after -AAC).
    let rot = fixture("rot_remove.rot.att");
    let twoa_siger = &rot[4..4 + 92];

    // Hand-assemble a count-2 group: -AAC + A(88) + 2A(92).
    let mut group = b"-AAC".to_vec();
    group.extend_from_slice(a_siger);
    group.extend_from_slice(twoa_siger);

    let sigs = parse_attachment(&group).expect("mixed-width group must parse");
    assert_eq!(sigs.len(), 2);
    assert_eq!((sigs[0].index, sigs[0].prior_index), (5, None));
    assert_eq!((sigs[1].index, sigs[1].prior_index), (0, Some(1)));
}

/// A signature with `prior_index = Some(j)` (and j != index) must emit a 92-char
/// dual-index `2A` siger and round-trip.
#[test]
fn dual_index_attachment_roundtrips() {
    let sig = IndexedSignature {
        index: 0,
        prior_index: Some(1),
        sig: vec![9u8; 64],
    };
    let att = serialize_attachment(std::slice::from_ref(&sig)).unwrap();
    let s = std::str::from_utf8(&att).unwrap();
    assert!(
        s.starts_with("-AAB2A"),
        "dual-index siger must use the 2A code: {s}"
    );
    assert_eq!(att.len(), 4 + 92, "counter (4) + one 2A siger (92)");
    let back = parse_attachment(&att).unwrap();
    assert_eq!(back.len(), 1);
    assert_eq!((back[0].index, back[0].prior_index), (0, Some(1)));
    assert_eq!(back[0].sig, vec![9u8; 64]);
}

/// Strongest §1.5 check: parse keripy's dual-index attachment, then re-emit it
/// through our serializer — the bytes must be byte-for-byte identical to keripy.
#[test]
fn reemits_keripy_rot_remove_attachment_byte_for_byte() {
    let att = fixture("rot_remove.rot.att");
    let sigs = parse_attachment(&att).unwrap();
    let reemitted = serialize_attachment(&sigs).unwrap();
    assert_eq!(
        reemitted, att,
        "our dual-index emission must equal keripy's bytes exactly"
    );
}

/// End-to-end §1.5: auths must ACCEPT keripy's 3→2 dual-index removal rotation
/// (rejected as AsymmetricKeyRotation before B.4). Replays the keripy icp to the
/// prior key state, then validates the keripy rot + its dual-index attachment.
#[test]
fn asymmetric_rotation_kt2_now_accepted() {
    let icp = load_event("rot_remove.icp.json");
    let prior = replay_kel(std::slice::from_ref(&icp)).expect("icp replays to a key state");
    let rot = load_event("rot_remove.rot.json");
    let sigs = parse_attachment(&fixture("rot_remove.rot.att")).unwrap();
    validate_signed_event(&SignedEvent::new(rot, sigs), Some(&prior))
        .expect("keripy dual-index removal rotation must validate");
}

/// Each rotation signature binds to the specific prior commitment it reveals.
#[test]
fn dual_index_rotation_binds_prior_commitment() {
    let icp = load_event("rot_remove.icp.json");
    let prior = replay_kel(std::slice::from_ref(&icp)).unwrap();
    let rot = load_event("rot_remove.rot.json");
    let good = parse_attachment(&fixture("rot_remove.rot.att")).unwrap();

    // Genuine binding validates.
    validate_signed_event(&SignedEvent::new(rot.clone(), good.clone()), Some(&prior))
        .expect("genuine dual-index binding must validate");

    // A wrong prior_index (revealing a commitment the key does not satisfy) drops
    // that signature; the prior nt=2 is no longer met.
    let mut wrong = good.clone();
    wrong[0].prior_index = Some(2); // k[0]=s3 was committed at n[1], not n[2]
    assert!(matches!(
        validate_signed_event(&SignedEvent::new(rot.clone(), wrong), Some(&prior)),
        Err(ValidationError::SignatureFailed { .. })
    ));

    // Two signatures naming the SAME prior commitment count once → nt=2 unmet.
    let mut dup = good.clone();
    dup[1] = good[0].clone();
    assert!(
        validate_signed_event(&SignedEvent::new(rot, dup), Some(&prior)).is_err(),
        "two sigs revealing the same prior commitment must not satisfy nt=2"
    );
}
