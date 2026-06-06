//! Epic E.1 — reciprocal source seal (`-G` `SealSourceCouple`) on delegated events
//! and the bilateral `validate_delegation` binding.
//!
//! Proves: (1) auths' `-G` encoding is byte-identical to keripy 1.3.4; (2) a
//! delegated event that points back at its anchoring event validates; (3) a
//! one-directional delegation (no `-G`) or one whose `-G` points elsewhere is
//! rejected.

use auths_keri::{
    CesrKey, DipEvent, DipEventInit, Event, IcpEvent, IcpEventInit, IxnEvent, KeriPublicKey,
    KeriSequence, Prefix, Said, Seal, SourceSeal, Threshold, ValidationError, VersionString,
    compute_next_commitment, finalize_dip_event, finalize_icp_event, finalize_ixn_event,
    parse_delegated_attachment, parse_source_seal_couples, serialize_source_seal_couples,
    validate_delegation,
};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::Value;

const GSRC_ATT: &[u8] = include_bytes!("../fixtures/keripy/delegation.gsrc.att");
const DIP_ATT: &[u8] = include_bytes!("../fixtures/keripy/delegation.dip.att");
const META: &str = include_str!("../fixtures/keripy/delegation.meta.json");

fn gen_cesr_key() -> CesrKey {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let pk = KeriPublicKey::ed25519(kp.public_key().as_ref()).unwrap();
    CesrKey::new_unchecked(pk.to_qb64().unwrap())
}

fn dummy_key(seed: u8) -> KeriPublicKey {
    KeriPublicKey::ed25519(&[seed; 32]).unwrap()
}

/// Build a delegator `icp` + a device `dip` it anchors at sequence 1, returning the
/// dip (with `source_seal` left `None`) and the delegator KEL `[icp, anchor_ixn]`.
fn delegated_fixture() -> (DipEvent, Vec<Event>) {
    let root_icp = finalize_icp_event(IcpEvent::new(IcpEventInit {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: Prefix::default(),
        s: KeriSequence::new(0),
        kt: Threshold::Simple(1),
        k: vec![CesrKey::new_unchecked(dummy_key(1).to_qb64().unwrap())],
        nt: Threshold::Simple(1),
        n: vec![compute_next_commitment(&dummy_key(2))],
        bt: Threshold::Simple(0),
        b: vec![],
        c: vec![],
        a: vec![],
    }))
    .unwrap();
    let root_prefix = root_icp.i.clone();

    let dip = finalize_dip_event(DipEvent::new(DipEventInit {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: Prefix::default(),
        s: KeriSequence::new(0),
        kt: Threshold::Simple(1),
        k: vec![gen_cesr_key()],
        nt: Threshold::Simple(1),
        n: vec![compute_next_commitment(&dummy_key(3))],
        bt: Threshold::Simple(0),
        b: vec![],
        c: vec![],
        a: vec![],
        di: root_prefix.clone(),
    }))
    .unwrap();

    let anchor = finalize_ixn_event(IxnEvent {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: root_prefix.clone(),
        s: KeriSequence::new(1),
        p: root_icp.d.clone(),
        a: vec![Seal::KeyEvent {
            i: dip.i.clone(),
            s: KeriSequence::new(0),
            d: dip.d.clone(),
        }],
    })
    .unwrap();

    let root_kel = vec![Event::Icp(root_icp), Event::Ixn(anchor)];
    (dip, root_kel)
}

/// The source seal that correctly references the anchoring ixn (sequence 1).
fn anchor_seal(root_kel: &[Event]) -> SourceSeal {
    let anchor = &root_kel[1];
    SourceSeal {
        s: anchor.sequence(),
        d: anchor.said().clone(),
    }
}

#[test]
fn delegation_roundtrips_keripy_134_fixture() {
    let meta: Value = serde_json::from_str(META).unwrap();
    let anchor_sn = meta["anchor_sn"].as_u64().unwrap() as u128;
    let anchor_said = meta["anchor_said"].as_str().unwrap().to_string();
    let couple = SourceSeal {
        s: KeriSequence::new(anchor_sn),
        d: Said::new_unchecked(anchor_said),
    };

    // Our `-G` encoder is byte-identical to keripy 1.3.4.
    let encoded = serialize_source_seal_couples(std::slice::from_ref(&couple)).unwrap();
    assert_eq!(encoded, GSRC_ATT, "auths -G bytes must match keripy 1.3.4");

    // And we parse keripy's `-G` group back to the same couple.
    let parsed = parse_source_seal_couples(GSRC_ATT).unwrap();
    assert_eq!(parsed, vec![couple.clone()]);

    // The full keripy dip attachment splits into one controller sig + the couple.
    let (sigs, couples) = parse_delegated_attachment(DIP_ATT).unwrap();
    assert_eq!(sigs.len(), 1, "keripy dip carries one controller signature");
    assert_eq!(
        couples,
        vec![couple],
        "and one -G source seal back-reference"
    );
}

#[test]
fn validate_delegation_accepts_bilateral() {
    let (mut dip, root_kel) = delegated_fixture();
    dip.source_seal = Some(anchor_seal(&root_kel));
    validate_delegation(&Event::Dip(dip), &root_kel)
        .expect("a dip whose -G points at its anchoring event validates");
}

#[test]
fn validate_delegation_rejects_one_directional() {
    let (dip, root_kel) = delegated_fixture();
    // The delegator anchored the dip, but the dip carries no -G back-reference.
    assert!(dip.source_seal.is_none());
    let err = validate_delegation(&Event::Dip(dip), &root_kel)
        .expect_err("a one-directional delegation must be rejected");
    assert!(
        matches!(err, ValidationError::DelegateSourceSealMissing { .. }),
        "expected DelegateSourceSealMissing, got {err:?}"
    );
}

#[test]
fn seal_back_ref_mismatch_rejected() {
    let (mut dip, root_kel) = delegated_fixture();
    // The dip's -G points at the right sequence but the wrong SAID (L′ ≠ L).
    dip.source_seal = Some(SourceSeal {
        s: root_kel[1].sequence(),
        d: Said::new_unchecked("EWrongAnchorSaid00000000000000000000000000000".to_string()),
    });
    let err = validate_delegation(&Event::Dip(dip), &root_kel)
        .expect_err("a mismatched -G back-reference must be rejected");
    assert!(
        matches!(err, ValidationError::SealBackRefMismatch { .. }),
        "expected SealBackRefMismatch, got {err:?}"
    );
}
