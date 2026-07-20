//! The `activity/v1` verifier battery: a witness anchor is a required gate when
//! demanded, every tampered or forged anchor fails the WHOLE document with a
//! named check, a genuinely-signed but false aggregate is never laundered into a
//! witnessed fact, and freshness is honest against an injected clock.
//!
//! These exercise the pure, keys-injected surface (`verify_activity` and
//! `verify_activity_with_keys`) so no git registry is needed; the registry
//! wrapper only adds KEL key resolution around this same core.

use auths_anchor::test_support::{
    finalized_matching, finalized_sample, party_seed_bytes, party_verifying_key_bytes,
    with_cosigners,
};
use auths_crypto::{CurveType, TypedSeed};
use auths_evidence::{
    ACTIVITY_VERSION, ActivityAsOf, ActivityV1, EvidenceError, Subject, VerifyActivityOpts,
    activity_seed_id, activity_signing_bytes, verify_activity, verify_activity_with_keys,
};
use auths_keri::KeriPublicKey;
use auths_verifier::freshness::Freshness;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::{DateTime, Duration, TimeZone, Utc};

/// A fixed verification instant, so every case is deterministic.
fn t0() -> DateTime<Utc> {
    Utc.timestamp_opt(1_760_000_000, 0).unwrap()
}

/// A genuinely-signed, unanchored `activity/v1` document over the given tuple,
/// plus the agent's current keys. The document is signed by the same party key
/// the anchor fixtures use, so an attached fixture anchor's party-key check
/// resolves to a current key. The curve travels with the key material via the
/// typed seed and the CESR-taggable verkey — never assumed.
fn honest_doc(
    head: [u8; 32],
    count: u64,
    cumulative_cents: u64,
    as_of: DateTime<Utc>,
) -> (ActivityV1, Vec<KeriPublicKey>) {
    let (curve, seed_bytes) = (CurveType::Ed25519, party_seed_bytes());
    let mut doc = ActivityV1 {
        version: ACTIVITY_VERSION.to_string(),
        suite: "json-canon/ed25519".to_string(),
        subject: Subject {
            root: "did:keri:root".to_string(),
            agent: "did:keri:agent".to_string(),
        },
        head: auths_anchor::Head::from_bytes(head).to_hex(),
        count,
        cumulative_cents,
        as_of: ActivityAsOf {
            ts: as_of,
            anchor: None,
        },
        signature: String::new(),
        anchor: None,
    };
    let seed = TypedSeed::from_curve(curve, seed_bytes);
    let message = activity_signing_bytes(&doc).unwrap();
    let signature = auths_crypto::typed_sign(&seed, &message).unwrap();
    doc.signature = BASE64.encode(signature);
    let verkey = party_verifying_key_bytes();
    let keys = vec![KeriPublicKey::from_verkey_bytes(&verkey, curve).unwrap()];
    (doc, keys)
}

/// Attach a witness anchor that legitimately restates the document's tuple.
fn attach_matching_anchor(doc: &mut ActivityV1) {
    let seed_id = activity_seed_id(doc);
    let head = auths_anchor::Head::from_hex(&doc.head).unwrap();
    let finalized = finalized_matching(
        seed_id,
        doc.count,
        *head.as_bytes(),
        u128::from(doc.cumulative_cents),
        3,
        2,
    );
    doc.anchor = Some(finalized);
}

fn require_witness() -> VerifyActivityOpts {
    VerifyActivityOpts {
        require_witness: true,
        witness_tip_index: None,
    }
}

// ---- a witness anchor is a required gate when the tier is demanded ----

#[test]
fn anchor_removed_with_require_witness_fails_whole() {
    let (doc, keys) = honest_doc([0x11; 32], 3, 300, t0());
    let err = verify_activity_with_keys(&doc, &keys, t0(), &require_witness()).unwrap_err();
    assert!(
        matches!(
            err,
            EvidenceError::AnchorInvalid {
                code: "anchor-required",
                ..
            }
        ),
        "{err:?}"
    );
}

#[test]
fn anchor_removed_without_require_witness_passes_with_null_anchor() {
    let (doc, keys) = honest_doc([0x11; 32], 3, 300, t0());
    let verdict =
        verify_activity_with_keys(&doc, &keys, t0(), &VerifyActivityOpts::default()).unwrap();
    assert!(verdict.anchor.is_none());
    assert!(!verdict.head_bound);
}

// ---- every tampered/forged anchor fails the whole document with a named leg ----

#[test]
fn spliced_anchor_for_a_different_chain_fails_whole() {
    let (mut doc, keys) = honest_doc([0x11; 32], 1, 100, t0());
    // A finalized anchor from a different spend chain (its own seed id).
    doc.anchor = Some(finalized_sample(3, 2));
    let err =
        verify_activity_with_keys(&doc, &keys, t0(), &VerifyActivityOpts::default()).unwrap_err();
    assert!(
        matches!(
            err,
            EvidenceError::AnchorInvalid {
                code: "chain-mismatch",
                ..
            }
        ),
        "{err:?}"
    );
}

#[test]
fn under_threshold_anchor_fails_whole() {
    // A finalization failure (fewer distinct cosignatures than the threshold)
    // fails the whole document and names the leg.
    let (mut doc, keys) = honest_doc([0x11; 32], 4, 400, t0());
    let seed_id = activity_seed_id(&doc);
    let finalized = with_cosigners(finalized_matching(seed_id, 4, [0x11; 32], 400, 3, 2), 1);
    doc.anchor = Some(finalized);
    let err =
        verify_activity_with_keys(&doc, &keys, t0(), &VerifyActivityOpts::default()).unwrap_err();
    assert!(
        matches!(
            err,
            EvidenceError::AnchorInvalid {
                code: "threshold-not-met",
                ..
            }
        ),
        "{err:?}"
    );
}

#[test]
fn rewritten_head_under_a_real_anchor_fails_whole() {
    let (mut doc, keys) = honest_doc([0x11; 32], 5, 300, t0());
    // The document is signed over one head; the anchor (same chain, same
    // count/cumulative) restates a different head — the aggregate no longer
    // matches, so moving the head under a real anchor is caught.
    let seed_id = activity_seed_id(&doc);
    doc.anchor = Some(finalized_matching(seed_id, 5, [0x22; 32], 300, 3, 2));
    let err =
        verify_activity_with_keys(&doc, &keys, t0(), &VerifyActivityOpts::default()).unwrap_err();
    assert!(
        matches!(
            err,
            EvidenceError::AnchorInvalid {
                code: "aggregate-mismatch",
                ..
            }
        ),
        "{err:?}"
    );
}

// ---- freshness against an injected clock ----

#[test]
fn future_as_of_is_rejected() {
    let future = t0() + Duration::hours(1);
    let (doc, keys) = honest_doc([0x11; 32], 1, 100, future);
    let err =
        verify_activity_with_keys(&doc, &keys, t0(), &VerifyActivityOpts::default()).unwrap_err();
    assert!(
        matches!(err, EvidenceError::Input(ref m) if m.contains("in the future")),
        "{err:?}"
    );
}

#[test]
fn recent_standalone_reads_unknown() {
    let (doc, keys) = honest_doc([0x11; 32], 1, 100, t0());
    let now = t0() + Duration::hours(1);
    let verdict =
        verify_activity_with_keys(&doc, &keys, now, &VerifyActivityOpts::default()).unwrap();
    assert_eq!(verdict.freshness, Freshness::Unknown);
    assert!(verdict.anchor.is_none());
}

#[test]
fn stale_standalone_reads_stale() {
    let (doc, keys) = honest_doc([0x11; 32], 1, 100, t0());
    let now = t0() + Duration::hours(48);
    let verdict =
        verify_activity_with_keys(&doc, &keys, now, &VerifyActivityOpts::default()).unwrap();
    assert_eq!(verdict.freshness, Freshness::Stale);
}

#[test]
fn require_witness_denies_unconfirmable() {
    // An unanchored, recent document under a witness-tier demand fails — the
    // anchor is required and absent, so it never reaches a soft freshness pass.
    let (doc, keys) = honest_doc([0x11; 32], 1, 100, t0());
    let now = t0() + Duration::hours(1);
    assert!(verify_activity_with_keys(&doc, &keys, now, &require_witness()).is_err());
}

// ---- anchored / never-anchored / stale distinguishable on the verdict ----

#[test]
fn unanchored_verdict_anchor_is_null() {
    let (doc, keys) = honest_doc([0x11; 32], 1, 100, t0());
    let now = t0() + Duration::hours(1);
    let verdict =
        verify_activity_with_keys(&doc, &keys, now, &VerifyActivityOpts::default()).unwrap();
    assert!(verdict.anchor.is_none());
    assert_eq!(verdict.freshness, Freshness::Unknown);
    assert!(!verdict.head_bound);
}

#[test]
fn anchored_live_verdict_is_witness_tier_and_not_stale() {
    let (mut doc, keys) = honest_doc([0x11; 32], 4, 400, t0());
    attach_matching_anchor(&mut doc);
    let now = t0() + Duration::hours(1);
    let verdict =
        verify_activity_with_keys(&doc, &keys, now, &VerifyActivityOpts::default()).unwrap();
    let anchor = verdict.anchor.expect("anchored");
    assert_eq!(anchor.tier, "witness");
    assert!(!anchor.stale);
    assert_eq!(verdict.freshness, Freshness::Fresh);
    assert!(verdict.head_bound);
}

#[test]
fn anchored_but_witness_moved_on_is_stale() {
    let (mut doc, keys) = honest_doc([0x11; 32], 4, 400, t0());
    attach_matching_anchor(&mut doc);
    let now = t0() + Duration::hours(1);
    let opts = VerifyActivityOpts {
        require_witness: false,
        witness_tip_index: Some(doc.count + 1),
    };
    let verdict = verify_activity_with_keys(&doc, &keys, now, &opts).unwrap();
    let anchor = verdict.anchor.expect("anchored");
    assert!(anchor.stale);
    assert_eq!(verdict.freshness, Freshness::Stale);
}

// ---- an unanchored aggregate is never laundered into a witnessed fact ----

#[test]
fn genuinely_signed_false_aggregate_stays_unwitnessed() {
    // A $500k aggregate over a trivial log, signed by a genuine key: the
    // signature verifies, but with no anchor the tier proves it is unwitnessed —
    // the magnitude is present but not presented as a proven fact.
    let (doc, keys) = honest_doc([0x11; 32], 2, 50_000_000, t0());
    let verdict =
        verify_activity_with_keys(&doc, &keys, t0(), &VerifyActivityOpts::default()).unwrap();
    assert!(
        verdict.anchor.is_none(),
        "an unanchored aggregate is first-seen, never witnessed"
    );
}

// ---- head binding ----

#[test]
fn fabricated_head_is_not_head_bound() {
    // A fabricated 32-byte head verifies (it rides in the signed body) but is not
    // bound — no witness anchor cosigns it.
    let (doc, keys) = honest_doc([0xde; 32], 1, 100, t0());
    let verdict =
        verify_activity_with_keys(&doc, &keys, t0(), &VerifyActivityOpts::default()).unwrap();
    assert!(!verdict.head_bound);
}

#[test]
fn anchored_head_is_head_bound() {
    let (mut doc, keys) = honest_doc([0x11; 32], 4, 400, t0());
    attach_matching_anchor(&mut doc);
    let verdict =
        verify_activity_with_keys(&doc, &keys, t0(), &VerifyActivityOpts::default()).unwrap();
    assert!(verdict.head_bound);
}

// ---- the signature binds the content: editing any number breaks it ----

#[test]
fn inflated_cumulative_with_old_signature_fails() {
    let (mut doc, keys) = honest_doc([0x11; 32], 2, 300, t0());
    doc.cumulative_cents = 50_000_000;
    assert!(matches!(
        verify_activity(&doc, &keys, false),
        Err(EvidenceError::Input(_))
    ));
}

#[test]
fn lowered_cumulative_with_old_signature_fails() {
    let (mut doc, keys) = honest_doc([0x11; 32], 2, 300, t0());
    doc.cumulative_cents = 1;
    assert!(matches!(
        verify_activity(&doc, &keys, false),
        Err(EvidenceError::Input(_))
    ));
}

#[test]
fn edited_count_with_old_signature_fails() {
    let (mut doc, keys) = honest_doc([0x11; 32], 2, 300, t0());
    doc.count = 99;
    assert!(matches!(
        verify_activity(&doc, &keys, false),
        Err(EvidenceError::Input(_))
    ));
}
