//! Anchor-tier threat rows (plan RC-E5.2 rows 4 and 10, unit legs): the treasury
//! checkpoint trail as the head witness — forged signers and stale heads must
//! fail closed.

use auths_evidence::anchor::{treasury_anchor, verify_anchor};
use auths_evidence::{AnchorCheck, check_trail};
use auths_mcp_core::treasury::encode_hex;
use auths_mcp_core::{Cents, SignedTreasuryCheckpoint, TreasuryCheckpoint};
use chrono::{Duration, TimeZone, Utc};

fn t0() -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(1_760_000_000, 0).unwrap()
}

struct Coordinator {
    seed: auths_crypto::TypedSeed,
    pubkey_hex: String,
}

fn coordinator() -> Coordinator {
    let (seed, public) = auths_crypto::typed_generate(auths_crypto::CurveType::P256).unwrap();
    Coordinator {
        seed,
        pubkey_hex: encode_hex(&public),
    }
}

fn signed_line(coord: &Coordinator, count: u64, cumulative: u64, at_offset_secs: i64) -> String {
    let checkpoint = TreasuryCheckpoint {
        fleet: "did:keri:Eroot".to_string(),
        count,
        cumulative_cents: Cents::new(cumulative),
        at: t0() + Duration::seconds(at_offset_secs),
    };
    let signature =
        auths_crypto::typed_sign(&coord.seed, &checkpoint.signing_bytes().unwrap()).unwrap();
    serde_json::to_string(&SignedTreasuryCheckpoint {
        checkpoint,
        public_key_hex: coord.pubkey_hex.clone(),
        signature_hex: encode_hex(&signature),
    })
    .unwrap()
}

#[test]
fn valid_trail_verifies_and_anchors() {
    let coord = coordinator();
    let lines = vec![
        signed_line(&coord, 1, 100, 0),
        signed_line(&coord, 2, 250, 5),
    ];
    let last = check_trail(&lines, Some(&coord.pubkey_hex)).unwrap();
    assert_eq!(last.cumulative_cents.get(), 250);

    let anchor = treasury_anchor(
        "composite-head".to_string(),
        1,
        lines,
        coord.pubkey_hex.clone(),
        &last,
    )
    .unwrap();
    assert_eq!(verify_anchor(&anchor, 250), AnchorCheck::Valid);
}

/// Row 10 — a trail signed by the WRONG key must not verify against the pinned
/// committer: `anchor-unverifiable`.
#[test]
fn forged_committer_is_rejected() {
    let real = coordinator();
    let forger = coordinator();
    let lines = vec![signed_line(&forger, 1, 100, 0)];
    assert!(check_trail(&lines, Some(&real.pubkey_hex)).is_err());

    let last = check_trail(&lines, Some(&forger.pubkey_hex)).unwrap();
    let mut anchor = treasury_anchor(
        "composite-head".to_string(),
        1,
        lines,
        forger.pubkey_hex.clone(),
        &last,
    )
    .unwrap();
    // The bundle pins the REAL coordinator; the embedded trail is the forger's.
    anchor.committer = Some(real.pubkey_hex.clone());
    match verify_anchor(&anchor, 100) {
        AnchorCheck::Invalid { code, .. } => assert_eq!(code, "anchor-unverifiable"),
        AnchorCheck::Valid => panic!("forged committer verified"),
    }
}

/// Row 4 — the stale-head attack: an OLD checkpoint that predates later
/// over-budget calls commits a cumulative below the re-derived settled total —
/// the anchor equality check catches it (`head-mismatch`).
#[test]
fn stale_checkpoint_cannot_cover_later_spend() {
    let coord = coordinator();
    let lines = vec![signed_line(&coord, 1, 100, 0)];
    let last = check_trail(&lines, Some(&coord.pubkey_hex)).unwrap();
    let anchor = treasury_anchor(
        "composite-head".to_string(),
        1,
        lines,
        coord.pubkey_hex.clone(),
        &last,
    )
    .unwrap();
    // The embedded log actually re-derives 300c settled — the stale trail says 100c.
    match verify_anchor(&anchor, 300) {
        AnchorCheck::Invalid { code, .. } => assert_eq!(code, "head-mismatch"),
        AnchorCheck::Valid => panic!("stale trail accepted"),
    }
}

/// A tampered trail (edited cumulative on a signed line) breaks its signature.
#[test]
fn edited_checkpoint_line_fails() {
    let coord = coordinator();
    let line = signed_line(&coord, 1, 100, 0).replace("100", "1");
    assert!(check_trail(&[line], Some(&coord.pubkey_hex)).is_err());
}

/// A regressing trail (cumulative going down) is rejected as a rollback.
#[test]
fn rollback_trail_fails() {
    let coord = coordinator();
    let lines = vec![
        signed_line(&coord, 2, 250, 0),
        signed_line(&coord, 3, 100, 5),
    ];
    assert!(check_trail(&lines, Some(&coord.pubkey_hex)).is_err());
}
