//! Escrow threat-model rows (plan RC-E5.2 rows 11–15 and 18) plus the rule
//! track's anchored-absence proofs — reserved mode.

use auths_crypto::CurveType;
use auths_receipts::escrow::{
    ESCROW_GENESIS, EscrowAnchor, EscrowEvent, EscrowEventBody, EscrowMode, EscrowRecord,
    Milestone, Party, PartyKey, RulingOutcome, evaluate_rule_track,
};
use chrono::{DateTime, Duration, TimeZone, Utc};

fn t0() -> DateTime<Utc> {
    Utc.timestamp_opt(1_760_000_000, 0).unwrap()
}

struct Deal {
    buyer: PartyKey,
    seller: PartyKey,
    arbiter: PartyKey,
    record: EscrowRecord,
    anchor_seed: auths_crypto::TypedSeed,
    anchor_key_hex: String,
}

fn hex_of(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn open_deal() -> Deal {
    let buyer = PartyKey::generate(CurveType::P256).unwrap();
    let seller = PartyKey::generate(CurveType::P256).unwrap();
    let arbiter = PartyKey::generate(CurveType::P256).unwrap();
    let (anchor_seed, anchor_public) = auths_crypto::typed_generate(CurveType::P256).unwrap();
    let body = EscrowEventBody::Open {
        buyer: Party {
            did: buyer.did.clone(),
            settlement_address: "0xbuyer".to_string(),
        },
        seller: Party {
            did: seller.did.clone(),
            settlement_address: "0xseller".to_string(),
        },
        arbiter: Some(arbiter.did.clone()),
        mode: EscrowMode::Reserved,
        milestones: vec![
            Milestone {
                amount_cents: 500,
                deliver_by: t0() + Duration::hours(1),
                objection_window_secs: 600,
            },
            Milestone {
                amount_cents: 300,
                deliver_by: t0() + Duration::hours(2),
                objection_window_secs: 600,
            },
        ],
        rail: "x402".to_string(),
        t_end: t0() + Duration::hours(6),
    };
    let sigs = vec![
        buyer.sign_event(0, ESCROW_GENESIS, t0(), &body).unwrap(),
        seller.sign_event(0, ESCROW_GENESIS, t0(), &body).unwrap(),
    ];
    let record = EscrowRecord::open(body, sigs, t0(), 5).unwrap();
    Deal {
        buyer,
        seller,
        arbiter,
        record,
        anchor_key_hex: hex_of(&anchor_public),
        anchor_seed,
    }
}

fn signed_event(
    record: &EscrowRecord,
    signer: &PartyKey,
    at: DateTime<Utc>,
    body: EscrowEventBody,
) -> EscrowEvent {
    let seq = record.events.len() as u64;
    let prev = record.head();
    let sig = signer.sign_event(seq, &prev, at, &body).unwrap();
    EscrowEvent {
        seq,
        prev,
        at,
        body,
        sigs: vec![sig],
    }
}

fn anchor_now(deal: &mut Deal, at: DateTime<Utc>) {
    let anchor = EscrowAnchor::commit(&deal.record, at, &deal.anchor_seed).unwrap();
    deal.record.attach_anchor(anchor, &deal.anchor_key_hex).unwrap();
}

#[test]
fn open_requires_both_signatures() {
    let buyer = PartyKey::generate(CurveType::P256).unwrap();
    let seller = PartyKey::generate(CurveType::P256).unwrap();
    let body = EscrowEventBody::Open {
        buyer: Party {
            did: buyer.did.clone(),
            settlement_address: "0xb".to_string(),
        },
        seller: Party {
            did: seller.did.clone(),
            settlement_address: "0xs".to_string(),
        },
        arbiter: None,
        mode: EscrowMode::Reserved,
        milestones: vec![Milestone {
            amount_cents: 100,
            deliver_by: t0() + Duration::hours(1),
            objection_window_secs: 60,
        }],
        rail: "x402".to_string(),
        t_end: t0() + Duration::hours(3),
    };
    let only_buyer = vec![buyer.sign_event(0, ESCROW_GENESIS, t0(), &body).unwrap()];
    assert!(EscrowRecord::open(body, only_buyer, t0(), 5).is_err());
}

#[test]
fn locked_mode_is_refused_until_contract_gated() {
    let buyer = PartyKey::generate(CurveType::P256).unwrap();
    let seller = PartyKey::generate(CurveType::P256).unwrap();
    let body = EscrowEventBody::Open {
        buyer: Party {
            did: buyer.did.clone(),
            settlement_address: "0xb".to_string(),
        },
        seller: Party {
            did: seller.did.clone(),
            settlement_address: "0xs".to_string(),
        },
        arbiter: None,
        mode: EscrowMode::Locked,
        milestones: vec![Milestone {
            amount_cents: 100,
            deliver_by: t0() + Duration::hours(1),
            objection_window_secs: 60,
        }],
        rail: "x402".to_string(),
        t_end: t0() + Duration::hours(3),
    };
    let sigs = vec![
        buyer.sign_event(0, ESCROW_GENESIS, t0(), &body).unwrap(),
        seller.sign_event(0, ESCROW_GENESIS, t0(), &body).unwrap(),
    ];
    assert!(EscrowRecord::open(body, sigs, t0(), 5).is_err());
}

/// Row 11 — a delivery signed by a non-seller key is rejected on append.
#[test]
fn delivery_by_non_seller_is_rejected() {
    let mut deal = open_deal();
    let intruder = PartyKey::generate(CurveType::P256).unwrap();
    let event = signed_event(
        &deal.record,
        &intruder,
        t0() + Duration::minutes(10),
        EscrowEventBody::Deliver {
            milestone: 0,
            evidence_hash: "abc".to_string(),
        },
    );
    assert!(deal.record.append(event).is_err());
}

/// Row 12 — an objection anchored OUTSIDE the window is ignored by rule: the
/// milestone stays releasable (the anchored-absence proof holds).
#[test]
fn late_objection_is_ignored_by_rule() {
    let mut deal = open_deal();
    let deliver_at = t0() + Duration::minutes(10);
    let event = signed_event(
        &deal.record,
        &deal.seller,
        deliver_at,
        EscrowEventBody::Deliver {
            milestone: 0,
            evidence_hash: "abc".to_string(),
        },
    );
    deal.record.append(event).unwrap();
    anchor_now(&mut deal, deliver_at);

    // The buyer objects LONG after the 600s window; the objection's anchor
    // stamps it there (S1 — the anchor's clock, never a party's claim).
    let late = deliver_at + Duration::seconds(1200);
    let objection = signed_event(
        &deal.record,
        &deal.buyer,
        late,
        EscrowEventBody::Object {
            milestone: 0,
            reason_hash: "meh".to_string(),
        },
    );
    deal.record.append(objection).unwrap();
    anchor_now(&mut deal, late);

    let eval = evaluate_rule_track(&deal.record, 0).unwrap();
    assert_eq!(eval.outcome, RulingOutcome::Release);
}

/// A TIMELY anchored objection converts to the subjective branch.
#[test]
fn timely_objection_needs_the_arbiter() {
    let mut deal = open_deal();
    let deliver_at = t0() + Duration::minutes(10);
    let event = signed_event(
        &deal.record,
        &deal.seller,
        deliver_at,
        EscrowEventBody::Deliver {
            milestone: 0,
            evidence_hash: "abc".to_string(),
        },
    );
    deal.record.append(event).unwrap();
    anchor_now(&mut deal, deliver_at);

    let objected_at = deliver_at + Duration::seconds(60);
    let objection = signed_event(
        &deal.record,
        &deal.buyer,
        objected_at,
        EscrowEventBody::Object {
            milestone: 0,
            reason_hash: "broken".to_string(),
        },
    );
    deal.record.append(objection).unwrap();
    anchor_now(&mut deal, objected_at);

    let eval = evaluate_rule_track(&deal.record, 0).unwrap();
    assert_eq!(eval.outcome, RulingOutcome::NeedsArbiter);
}

/// Row 13 — arbitrating a non-existent milestone is an input error, no ruling.
#[test]
fn missing_milestone_is_an_input_error() {
    let deal = open_deal();
    assert!(evaluate_rule_track(&deal.record, 7).is_err());
}

/// Row 14 — no delivery anchored by the deadline: refundable by rule, decided by
/// an anchor PAST the deadline whose covered record contains no delivery.
#[test]
fn undelivered_milestone_refunds_by_rule() {
    let mut deal = open_deal();
    anchor_now(&mut deal, t0() + Duration::hours(1) + Duration::seconds(30));
    let eval = evaluate_rule_track(&deal.record, 0).unwrap();
    assert_eq!(eval.outcome, RulingOutcome::Refund);
    assert!(eval.proof.delivered_anchored_at.is_none());
}

/// Before any decisive anchor exists, the rule track holds — nothing is
/// decidable from committed heads yet.
#[test]
fn undecided_window_holds() {
    let mut deal = open_deal();
    anchor_now(&mut deal, t0() + Duration::minutes(1));
    let eval = evaluate_rule_track(&deal.record, 0).unwrap();
    assert_eq!(eval.outcome, RulingOutcome::Hold);
}

/// Row 15 — a release signature cannot be replayed against a different
/// milestone: the index lives INSIDE the signed body.
#[test]
fn release_signature_is_index_bound() {
    let mut deal = open_deal();
    let at = t0() + Duration::minutes(5);
    let release0 = signed_event(
        &deal.record,
        &deal.buyer,
        at,
        EscrowEventBody::Release {
            milestone: 0,
            tx: None,
        },
    );
    // Replay the SIGNATURE from milestone 0 on a body claiming milestone 1.
    let mut forged = release0.clone();
    forged.body = EscrowEventBody::Release {
        milestone: 1,
        tx: None,
    };
    assert!(deal.record.append(forged).is_err());
    // The genuine event still appends.
    deal.record.append(release0).unwrap();
}

/// Row 18 (S2) — the arbiter has ZERO fund-moving power in reserved mode: an
/// arbiter-signed Release event is rejected (only the buyer's signature
/// settles), and a recorded Ruling moves nothing.
#[test]
fn arbiter_cannot_move_funds() {
    let mut deal = open_deal();
    let at = t0() + Duration::minutes(5);
    // An arbiter-signed Release is structurally rejected.
    let arbiter_release = signed_event(
        &deal.record,
        &deal.arbiter,
        at,
        EscrowEventBody::Release {
            milestone: 0,
            tx: None,
        },
    );
    assert!(deal.record.append(arbiter_release).is_err());

    // A recorded Ruling is a signed opinion: it appends, but the milestone has
    // no release and the record's state shows none.
    let ruling = signed_event(
        &deal.record,
        &deal.arbiter,
        at,
        EscrowEventBody::Ruling {
            milestone: 0,
            outcome: RulingOutcome::Release,
            reason: "delivered fine".to_string(),
        },
    );
    deal.record.append(ruling).unwrap();
    let state = deal.record.milestone_state(0);
    assert!(state.released_seq.is_none());
    assert!(state.ruling.is_some());
}

/// A record that arrived by value fully re-verifies — and an edited event breaks it.
#[test]
fn verify_value_catches_edits() {
    let mut deal = open_deal();
    let deliver_at = t0() + Duration::minutes(10);
    let event = signed_event(
        &deal.record,
        &deal.seller,
        deliver_at,
        EscrowEventBody::Deliver {
            milestone: 0,
            evidence_hash: "abc".to_string(),
        },
    );
    deal.record.append(event).unwrap();
    anchor_now(&mut deal, deliver_at);

    let raw = serde_json::to_value(&deal.record).unwrap();
    EscrowRecord::verify_value(&raw, Some(&deal.anchor_key_hex)).unwrap();

    let mut tampered = raw.clone();
    tampered["events"][1]["body"]["evidence_hash"] = serde_json::json!("swapped");
    assert!(EscrowRecord::verify_value(&tampered, Some(&deal.anchor_key_hex)).is_err());

    // Dropping the delivery event breaks the chain the anchors commit to.
    let mut truncated = raw;
    truncated["events"].as_array_mut().unwrap().truncate(1);
    assert!(EscrowRecord::verify_value(&truncated, Some(&deal.anchor_key_hex)).is_err());
}
