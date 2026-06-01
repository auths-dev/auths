//! Witness-flow integration tests (D.6): receipt ingestion, first-seen
//! superseding under a simulated witness, and convergence of two diverging
//! local views onto the same recovery rotation.
//!
//! The first-seen *rules* are unit-tested in `witness::first_seen`; these wire
//! the pieces together the way a validator would — quorum acceptance via
//! `WitnessAgreement`, recovery superseding via `InMemoryFirstSeen`, and a
//! round-trip of the receipt encoding a verifier ingests.

use auths_keri::witness::agreement::WitnessAgreement;
use auths_keri::witness::{FirstSeenPolicy, InMemoryFirstSeen, Receipt, SignedReceipt};
use auths_keri::{Prefix, Said, Threshold};

fn prefix() -> Prefix {
    Prefix::new_unchecked("EControllerAid".to_string())
}

fn backers(n: usize) -> Vec<Prefix> {
    (1..=n)
        .map(|i| Prefix::new_unchecked(format!("BWitness{i}")))
        .collect()
}

/// A 2-of-3 witness quorum accepts an event once two designated backers
/// receipt it; the accepted event then passes the first-seen gate.
#[test]
fn receipt_quorum_then_first_seen_accept() {
    let agreement = WitnessAgreement::new(100);
    let p = prefix();
    let said = Said::new_unchecked("EEvent0".to_string());
    let bt = Threshold::Simple(2);

    agreement.submit_event(&p, 0, &said, &bt, &backers(3));
    assert!(!agreement.is_accepted(&p, 0, &said));

    agreement.add_receipt(&p, 0, &said, "BWitness1");
    assert!(!agreement.is_accepted(&p, 0, &said), "one receipt < quorum");

    agreement.add_receipt(&p, 0, &said, "BWitness2");
    assert!(
        agreement.is_accepted(&p, 0, &said),
        "two receipts meet 2-of-3"
    );

    // A receipt from a non-designated backer must not push quorum further.
    let fs = InMemoryFirstSeen::new();
    assert!(fs.try_accept(&p, 0, &said).is_ok());
}

/// Recovery flow: an interaction is first-seen at seq 1, then a recovery
/// rotation (establishment) supersedes it, and a later interaction cannot
/// displace the rotation.
#[test]
fn recovery_rotation_supersedes_interaction_flow() {
    let fs = InMemoryFirstSeen::new();
    let p = prefix();
    let ixn = Said::new_unchecked("EIxn1".to_string());
    let rot = Said::new_unchecked("ERot1".to_string());

    fs.try_accept(&p, 1, &ixn).unwrap();
    assert_eq!(fs.was_seen(&p, 1), Some(ixn));

    fs.try_supersede(&p, 1, &rot, true).unwrap();
    assert_eq!(fs.was_seen(&p, 1), Some(rot));

    let late_ixn = Said::new_unchecked("EIxn1b".to_string());
    assert!(
        fs.try_supersede(&p, 1, &late_ixn, false).is_err(),
        "an interaction cannot supersede a recovery rotation"
    );
}

/// Two validators with diverging seq-1 views converge once both apply the
/// recovery rotation: A saw the interaction first then superseded; B saw the
/// rotation first. Both end on the rotation SAID.
#[test]
fn two_views_converge_on_recovery_rotation() {
    let p = prefix();
    let ixn = Said::new_unchecked("EIxn1".to_string());
    let rot = Said::new_unchecked("ERot1".to_string());

    let view_a = InMemoryFirstSeen::new();
    view_a.try_accept(&p, 1, &ixn).unwrap();
    view_a.try_supersede(&p, 1, &rot, true).unwrap();

    let view_b = InMemoryFirstSeen::new();
    view_b.try_supersede(&p, 1, &rot, true).unwrap();

    assert_eq!(view_a.was_seen(&p, 1), view_b.was_seen(&p, 1));
    assert_eq!(view_a.was_seen(&p, 1), Some(rot));
}

/// Receipt ingestion round-trips through the Git-trailer encoding a verifier
/// parses, and the typed `t` survives as the constant `rct` (D.4).
#[test]
fn signed_receipt_ingestion_round_trip() {
    let signed = Receipt::builder()
        .said(Said::new_unchecked("EEvent0".to_string()))
        .witness("BWitness1")
        .sequence(0)
        .signature(vec![0xa1; 64])
        .build()
        .expect("builder has all required fields");

    let trailer = signed.to_trailer_value().unwrap();
    let parsed = SignedReceipt::from_trailer_value(&trailer).unwrap();

    assert_eq!(parsed, signed);
    assert_eq!(parsed.receipt.t, "rct");
}
