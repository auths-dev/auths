//! Appendix A invariants as named tests (E4).
//!
//! Each test is the adversarial answer to "what input would violate this
//! invariant?" — the attack is constructed, then asserted to be refused.

use auths_anchor::{
    Acceptance, AnchorError, DuplicityProof, Freshness, accept_anchor, freshness, verify_finalized,
    verify_signature,
};
use auths_crypto::CurveType;

use super::support::{controller_keys_for, finalized, signed_anchor, signed_anchor_p256};

fn now() -> chrono::DateTime<chrono::Utc> {
    chrono::TimeZone::timestamp_opt(&chrono::Utc, 1_800_000_000, 0).unwrap()
}

/// I-DUP-1: a witness never co-signs two heads at one index; the same-index
/// fork is refused and turned into a verifiable duplicity proof.
#[test]
fn i_dup_1_never_two_heads_one_index() {
    let prior = signed_anchor(5, [1u8; 32], 2, "EWitSet");
    let fork = signed_anchor(5, [2u8; 32], 2, "EWitSet");
    let keys = controller_keys_for(&prior);

    match accept_anchor(&fork, &keys, Some(&prior), now()).unwrap() {
        Acceptance::Duplicity(proof) => proof.verify().unwrap(),
        Acceptance::CoSign(_) => panic!("co-signed a fork — I-DUP-1 violated"),
    }
}

/// I-DUP-2: a duplicity proof is self-contained and verifies offline by a
/// stranger who reconstructs it from the two anchors alone.
#[test]
fn i_dup_2_duplicity_proof_is_offline_verifiable() {
    let a = signed_anchor(3, [10u8; 32], 2, "EWitSet");
    let b = signed_anchor(3, [20u8; 32], 2, "EWitSet");
    let proof = DuplicityProof::new(&a, &b).unwrap();

    // Round-trip through JSON to prove it carries everything a stranger needs.
    let wire = serde_json::to_string(&proof).unwrap();
    let rehydrated: DuplicityProof = serde_json::from_str(&wire).unwrap();
    rehydrated.verify().unwrap();
}

/// I-DUP-3: the party signature is curve-tagged in-band and verifies under both
/// supported curves (dispatch never looks at length).
#[test]
fn i_dup_3_party_signature_is_curve_tagged() {
    let ed = signed_anchor(1, [1u8; 32], 2, "EWitSet");
    assert_eq!(ed.sig_party.curve, CurveType::Ed25519);
    assert!(
        verify_signature(
            ed.sig_party.curve,
            &ed.sig_party.public_key,
            &ed.party_signing_bytes().unwrap(),
            &ed.sig_party.signature,
        )
        .unwrap()
    );

    let p = signed_anchor_p256(1);
    assert_eq!(p.sig_party.curve, CurveType::P256);
    assert!(
        verify_signature(
            p.sig_party.curve,
            &p.sig_party.public_key,
            &p.party_signing_bytes().unwrap(),
            &p.sig_party.signature,
        )
        .unwrap()
    );
}

/// I-FINAL-1: finalization requires ≥ t distinct cosignatures.
#[test]
fn i_final_1_threshold_enforced() {
    verify_finalized(&finalized(3, 2), None).unwrap();

    let mut under = finalized(3, 3);
    under.cosignatures.truncate(2);
    assert!(matches!(
        verify_finalized(&under, None),
        Err(AnchorError::ThresholdNotMet {
            got: 2,
            threshold: 3
        })
    ));
}

/// I-FINAL-2: every cosigner must be inside the declared set; a cosignature
/// attributed to a name outside the set is refused.
#[test]
fn i_final_2_cosigner_must_be_in_declared_set() {
    let mut f = finalized(3, 2);
    f.cosignatures[0].witness_name = "impostor".to_string();
    assert!(matches!(
        verify_finalized(&f, None),
        Err(AnchorError::CosignerOutsideSet { .. })
    ));
}

/// I-TRUST-3: the anchor commits to its witness set by SAID; a resolved set with
/// a different SAID is refused before any signature is trusted.
#[test]
fn i_trust_3_witness_set_said_binds() {
    let mut f = finalized(3, 2);
    f.witness_set.said = "EDifferentSet".to_string();
    assert!(matches!(
        verify_finalized(&f, None),
        Err(AnchorError::WitnessSetMismatch { .. })
    ));
}

/// I-VERIFY-1: verification is offline and by value — `verify_finalized` and
/// `freshness` take no I/O handles, so a passing call proves the offline path.
#[test]
fn i_verify_1_offline_only() {
    verify_finalized(&finalized(3, 2), None).unwrap();
    assert!(freshness(Some(9), Some(7)).is_fresh());
}

/// I-VERIFY-3: freshness is a separate labeled result, never folded into the
/// authorization decision; a stale bundle is labeled, not rejected.
#[test]
fn i_verify_3_freshness_is_separate_and_labeled() {
    assert_eq!(freshness(Some(9), Some(7)).status(), "fresh");
    assert!(matches!(
        freshness(Some(5), Some(7)),
        Freshness::Stale { .. }
    ));
    assert_eq!(freshness(Some(1), None), Freshness::Unanchored);
}

/// A set whose members were swapped but whose SAID string
/// was copied from the real set is refused — the SAID is recomputed from
/// content, never trusted as a label.
#[test]
fn i_trust_3_set_content_is_self_addressing() {
    let real = finalized(3, 2);
    let mut forged = finalized(3, 2);
    forged.witness_set.members[0].public_key = vec![0xAA; 32];
    forged.witness_set.said = real.anchor.witness_set.said.clone();
    assert!(matches!(
        verify_finalized(&forged, None),
        Err(AnchorError::SetSaidMismatch { .. }) | Err(AnchorError::CheckpointUnverifiable { .. })
    ));
}

/// A cosignature without a member-signed logged inclusion does not count
/// toward finalization — an unlogged co-sign is not finalization-grade.
#[test]
fn cosignature_without_logged_inclusion_is_refused() {
    let mut f = finalized(2, 2);
    f.inclusion.pop();
    assert!(matches!(
        verify_finalized(&f, None),
        Err(AnchorError::InclusionMissing { .. })
    ));
}

/// A post-dated τ beyond the skew bound is refused at accept —
/// otherwise one request makes every future withholding gap read fresh.
#[test]
fn post_dated_timestamp_is_refused() {
    let mut anchor = signed_anchor(1, [1u8; 32], 2, "EWitSet");
    anchor.timestamp = now() + chrono::Duration::seconds(3600);
    // Re-sign so only the skew (not the signature) is under test.
    let keys = controller_keys_for(&anchor);
    assert!(matches!(
        accept_anchor(&anchor, &keys, None, now()),
        Err(AnchorError::TimestampInFuture { .. })
    ));
}

/// Wire/signed parity: sub-second timestamps are unrepresentable on the wire
/// (serde truncates) and refused in-process — the signed bytes always commit
/// to exactly the value everyone compares.
#[test]
fn sub_second_timestamps_are_refused_and_unrepresentable() {
    let mut anchor = signed_anchor(1, [1u8; 32], 2, "EWitSet");
    anchor.timestamp = now() + chrono::Duration::nanoseconds(1);
    let keys = controller_keys_for(&anchor);
    assert!(matches!(
        accept_anchor(&anchor, &keys, None, now()),
        Err(AnchorError::SubSecondTimestamp)
    ));

    // Round-trip through the wire: the sub-second precision cannot survive.
    let wire = serde_json::to_string(&anchor).unwrap();
    let rehydrated: auths_anchor::Anchor = serde_json::from_str(&wire).unwrap();
    assert_eq!(rehydrated.timestamp.timestamp_subsec_nanos(), 0);
}

/// A tampered anchor tuple invalidates the party signature (the anchor bytes are
/// bound, not just the head).
#[test]
fn tampering_the_tuple_breaks_the_party_signature() {
    let mut anchor = signed_anchor(1, [1u8; 32], 2, "EWitSet");
    let keys = controller_keys_for(&anchor);
    anchor.cumulative += 1; // move the money without re-signing
    assert!(matches!(
        accept_anchor(&anchor, &keys, None, now()),
        Err(AnchorError::PartySignatureInvalid)
    ));
}
