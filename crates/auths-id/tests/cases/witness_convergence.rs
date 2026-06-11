//! Epic D.12 — end-to-end witness convergence through the receipt gate.
//!
//! Exercises the trust-decision path as an integration: provenance-carrying
//! witness receipts persisted in Git (`GitReceiptStorage`, D.2) → resolved via
//! the replay-gate seam (`GitWitnessReceiptLookup`, D.5) → receipt-gated replay
//! (`validate_kel_with_receipts`, D.6) → verdict, plus cross-view duplicity
//! (`detect_duplicity`, D.8). Quorum-met key-state is `Accepted`; under-quorum and
//! non-designated ("forged"/foreign) receipts are not; a `kt=1` fork surfaces as
//! `Diverging`, never silently accepted.
//!
//! The live HTTP collection path (witness server ↔ client ↔ collector, and the
//! collection-time *signature* verification of D.2) is integration-tested in the
//! `auths-infra-http` witness suite; this e2e covers storage → lookup → gate, so
//! its receipts carry witness AIDs with empty signatures (the replay gate keys on
//! the witness AID + event SAID, not the signature — signature verification is a
//! collection-time concern).

use auths_core::witness::{Receipt, ReceiptTag, SignedReceipt, StoredReceipt};
use auths_id::keri::event::EventReceipts;
use auths_id::storage::{GitReceiptStorage, GitWitnessReceiptLookup, ReceiptStorage};
use auths_keri::{
    CesrKey, Event, IcpEvent, IxnEvent, KeriPublicKey, KeriSequence, Prefix, Said, Seal, Threshold,
    TrustedKel, VersionString, WitnessedReplay, compute_next_commitment, finalize_icp_event,
    finalize_ixn_event,
};
use auths_verifier::duplicity::{DuplicityReport, KelEventRef, detect_duplicity};

/// A witness AID (`D…` Ed25519 CESR verkey prefix) from a fixed seed.
fn witness_aid(seed: u8) -> String {
    KeriPublicKey::ed25519(&[seed; 32])
        .unwrap()
        .to_qb64()
        .unwrap()
}

/// A finalized inception designating `backers` with threshold `bt`.
fn icp_with_backers(backers: &[&str], bt: u64) -> Event {
    let key = KeriPublicKey::ed25519(&[1u8; 32]).unwrap();
    let next = KeriPublicKey::ed25519(&[2u8; 32]).unwrap();
    let icp = IcpEvent {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: Prefix::default(),
        s: KeriSequence::new(0),
        kt: Threshold::Simple(1),
        k: vec![CesrKey::new_unchecked(key.to_qb64().unwrap())],
        nt: Threshold::Simple(1),
        n: vec![compute_next_commitment(&next)],
        bt: Threshold::Simple(bt),
        b: backers
            .iter()
            .map(|a| Prefix::new_unchecked(a.to_string()))
            .collect(),
        c: vec![],
        a: vec![],
    };
    Event::Icp(finalize_icp_event(icp).unwrap())
}

/// A stored receipt by `witness` over `(controller, seq 0, event_said)`. The
/// signature is empty: the replay gate keys on the witness AID + SAID.
fn stored_receipt(witness: &str, controller: &str, event_said: &str) -> StoredReceipt {
    StoredReceipt {
        signed: SignedReceipt {
            receipt: Receipt {
                v: VersionString::placeholder(),
                t: ReceiptTag,
                d: Said::new_unchecked(event_said.to_string()),
                i: Prefix::new_unchecked(controller.to_string()),
                s: KeriSequence::new(0),
            },
            signature: vec![],
        },
        witness: Prefix::new_unchecked(witness.to_string()),
    }
}

/// Persist `receipts` for `(controller, said)` and return a gate lookup over the repo.
fn store_and_lookup(
    repo_path: &std::path::Path,
    controller: &Prefix,
    said: &str,
    receipts: Vec<StoredReceipt>,
) -> GitWitnessReceiptLookup {
    let storage = GitReceiptStorage::new(repo_path.to_path_buf());
    storage
        .store_receipts(
            controller,
            &EventReceipts::new(said.to_string(), receipts),
            chrono::Utc::now(),
        )
        .unwrap();
    GitWitnessReceiptLookup::new(repo_path.to_path_buf())
}

fn icp_parts(icp: &Event) -> (Prefix, String) {
    match icp {
        Event::Icp(e) => (e.i.clone(), e.d.as_str().to_string()),
        _ => unreachable!(),
    }
}

/// An anchoring `ixn` at seq 1 carrying a `Seal::KeyEvent` — the exact shape a TEL
/// `vcp`/`iss`/`rev` anchor uses (Epic F). Chains onto `icp_said`.
fn anchoring_ixn(controller: &Prefix, icp_said: &str) -> IxnEvent {
    finalize_ixn_event(IxnEvent {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: controller.clone(),
        s: KeriSequence::new(1),
        p: Said::new_unchecked(icp_said.to_string()),
        a: vec![Seal::KeyEvent {
            i: Prefix::new_unchecked("ECredentialRegistryOrTelEvent".to_string()),
            s: KeriSequence::new(0),
            d: Said::new_unchecked("ETelEventSaidAnchoredHere".to_string()),
        }],
    })
    .unwrap()
}

// ── Epic F pre-flight (F.9): does the Epic-D witness gate cover the TEL-anchoring
// `ixn`? ──────────────────────────────────────────────────────────────────────
//
// FINDING: `validate_kel_with_receipts` gates ESTABLISHMENT events (icp/rot/drt) on
// witness quorum but, by design (`auths-keri/src/validate.rs` "ixn never gates"),
// does NOT quorum-gate interaction events. TEL revocation (F.5/D2) anchors `rev` via
// an `ixn`, so the "verifier enforces witness quorum on the anchoring ixn" sub-claim
// is NOT delivered by reusing the gate as-is. What DOES hold: (a) establishment-event
// witnessing is real + fail-closed (proved below + in the e2e tests above), and (b)
// `detect_duplicity` catches an `ixn`-level fork (revocation-hiding-via-equivocation
// is detectable — see `two_diverging_views_converge_with_witness`). The decision this
// forces on F.5 is recorded in the F.9 done-summary + the F.7 threat model.

#[test]
fn anchoring_ixn_is_not_witness_quorum_gated() {
    // A fully witnessed inception (quorum met), then a TEL-style anchoring `ixn` at
    // seq 1 with NO receipts of its own. If the gate covered ixn this would be
    // `Pending`; it is `Accepted` — documenting that ixn is not quorum-gated.
    let (dir, _repo) = auths_test_utils::git::init_test_repo();
    let w1 = witness_aid(51);
    let icp = icp_with_backers(&[&w1], 1);
    let (controller, said) = icp_parts(&icp);
    let lookup = store_and_lookup(
        dir.path(),
        &controller,
        &said,
        vec![stored_receipt(&w1, controller.as_str(), &said)],
    );

    let ixn = anchoring_ixn(&controller, &said);
    let outcome = TrustedKel::from_trusted_source(&[icp, Event::Ixn(ixn)])
        .replay_with_receipts(None, &lookup)
        .unwrap();
    assert!(
        matches!(outcome, WitnessedReplay::Accepted(_)),
        "ixn is NOT witness-quorum-gated: an anchoring ixn with no receipts of its own \
         still yields Accepted once the establishment event meets quorum. Got {outcome:?}. \
         F.5 must EXTEND gating to the TEL-anchoring ixn (or rest revocation robustness on \
         establishment-witnessing + duplicity-detection — recorded in the F.9 finding)."
    );
}

#[test]
fn under_quorum_establishment_still_fails_closed_with_anchoring_ixn() {
    // The establishment-event protection holds even when an anchoring ixn follows:
    // under-quorum icp short-circuits to Pending before the ixn is reached.
    let (dir, _repo) = auths_test_utils::git::init_test_repo();
    let (w1, w2) = (witness_aid(61), witness_aid(62));
    let icp = icp_with_backers(&[&w1, &w2], 2); // needs 2
    let (controller, said) = icp_parts(&icp);
    let lookup = store_and_lookup(
        dir.path(),
        &controller,
        &said,
        vec![stored_receipt(&w1, controller.as_str(), &said)], // only 1
    );

    let ixn = anchoring_ixn(&controller, &said);
    match TrustedKel::from_trusted_source(&[icp, Event::Ixn(ixn)])
        .replay_with_receipts(None, &lookup)
        .unwrap()
    {
        WitnessedReplay::Pending {
            sequence,
            collected,
            ..
        } => {
            assert_eq!(
                sequence, 0,
                "fails closed at the under-quorum establishment event"
            );
            assert_eq!(collected, 1);
        }
        other => panic!("expected Pending at the under-quorum icp, got {other:?}"),
    }
}

#[test]
fn witness_quorum_end_to_end_verifies() {
    let (dir, _repo) = auths_test_utils::git::init_test_repo();
    let (w1, w2) = (witness_aid(11), witness_aid(12));
    let icp = icp_with_backers(&[&w1, &w2], 2);
    let (controller, said) = icp_parts(&icp);

    let lookup = store_and_lookup(
        dir.path(),
        &controller,
        &said,
        vec![
            stored_receipt(&w1, controller.as_str(), &said),
            stored_receipt(&w2, controller.as_str(), &said),
        ],
    );

    let outcome = TrustedKel::from_trusted_source(&[icp])
        .replay_with_receipts(None, &lookup)
        .unwrap();
    assert!(
        matches!(outcome, WitnessedReplay::Accepted(_)),
        "quorum-met key-state must verify, got {outcome:?}"
    );
}

#[test]
fn under_quorum_end_to_end_refused_when_required() {
    let (dir, _repo) = auths_test_utils::git::init_test_repo();
    let (w1, w2) = (witness_aid(21), witness_aid(22));
    let icp = icp_with_backers(&[&w1, &w2], 2); // needs 2
    let (controller, said) = icp_parts(&icp);

    // Only one receipt persisted → quorum not met.
    let lookup = store_and_lookup(
        dir.path(),
        &controller,
        &said,
        vec![stored_receipt(&w1, controller.as_str(), &said)],
    );

    // The replay gate reports Pending; a verifier under --require-witnesses
    // (D.7) maps this to a fail-closed verdict.
    match TrustedKel::from_trusted_source(&[icp])
        .replay_with_receipts(None, &lookup)
        .unwrap()
    {
        WitnessedReplay::Pending {
            sequence,
            collected,
            ..
        } => {
            assert_eq!(sequence, 0);
            assert_eq!(collected, 1);
        }
        other => panic!("expected Pending under quorum, got {other:?}"),
    }
}

#[test]
fn forged_receipt_does_not_satisfy_quorum_e2e() {
    let (dir, _repo) = auths_test_utils::git::init_test_repo();
    let (w1, w2) = (witness_aid(31), witness_aid(32));
    let foreign = witness_aid(99); // NOT designated in b[]
    let icp = icp_with_backers(&[&w1, &w2], 2);
    let (controller, said) = icp_parts(&icp);

    // One designated receipt + one from a non-designated (foreign) witness.
    // KAWA ignores the foreign receipt, so quorum (2) is not met.
    let lookup = store_and_lookup(
        dir.path(),
        &controller,
        &said,
        vec![
            stored_receipt(&w1, controller.as_str(), &said),
            stored_receipt(&foreign, controller.as_str(), &said),
        ],
    );

    assert!(
        matches!(
            TrustedKel::from_trusted_source(&[icp])
                .replay_with_receipts(None, &lookup)
                .unwrap(),
            WitnessedReplay::Pending { .. }
        ),
        "a non-designated witness receipt must not count toward quorum"
    );
}

#[test]
fn two_diverging_views_converge_with_witness() {
    // A witnessed base inception, then two divergent seq-1 events (a kt=1 fork).
    let (dir, _repo) = auths_test_utils::git::init_test_repo();
    let w1 = witness_aid(41);
    let icp = icp_with_backers(&[&w1], 1);
    let (controller, said) = icp_parts(&icp);
    let icp_said = Said::new_unchecked(said.clone());

    // The witnessed base view verifies.
    let lookup = store_and_lookup(
        dir.path(),
        &controller,
        &said,
        vec![stored_receipt(&w1, controller.as_str(), &said)],
    );
    assert!(matches!(
        TrustedKel::from_trusted_source(std::slice::from_ref(&icp))
            .replay_with_receipts(None, &lookup)
            .unwrap(),
        WitnessedReplay::Accepted(_)
    ));

    // Two divergent ixn events at seq 1 (different anchors → different SAIDs).
    let ixn_a = finalize_ixn_event(IxnEvent {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: controller.clone(),
        s: KeriSequence::new(1),
        p: icp_said.clone(),
        a: vec![],
    })
    .unwrap();
    let ixn_b = finalize_ixn_event(IxnEvent {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: controller.clone(),
        s: KeriSequence::new(1),
        p: icp_said.clone(),
        a: vec![Seal::digest("EDivergentAnchor")],
    })
    .unwrap();

    // The fork surfaces as Diverging — never silently accepted.
    let refs = vec![
        KelEventRef {
            prefix: controller.as_str(),
            seq: 1,
            said: ixn_a.d.as_str(),
        },
        KelEventRef {
            prefix: controller.as_str(),
            seq: 1,
            said: ixn_b.d.as_str(),
        },
    ];
    assert!(matches!(
        detect_duplicity(&refs),
        DuplicityReport::Diverging { seq: 1, .. }
    ));
}
