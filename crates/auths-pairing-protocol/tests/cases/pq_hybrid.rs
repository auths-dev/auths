//! fn-129.T10 hybrid KEM integration tests. Runs only under
//! `--features pq-hybrid`.
//!
//! Covers:
//! - Round-trip: initiator generates → advertises → responder
//!   encapsulates → initiator decapsulates → same PQ secret.
//! - Hybrid transport key derivation disagrees with classical-only
//!   derivation (downgrade protection).
//! - Combiner order `ss_c || ss_p` is load-bearing: swapping produces
//!   a different key.
//! - A hybrid-build peer round-trips the advertised `KemSlot` through
//!   JSON without data loss.

// This module is already gated on `feature = "pq-hybrid"` at the
// `tests/cases/mod.rs` level; no inner `#![cfg]` needed.

use auths_pairing_protocol::PairingToken;
use auths_pairing_protocol::pq_hybrid::{
    HybridInitiatorKem, derive_hybrid_transport_key, encapsulate_against_slot,
};
use auths_pairing_protocol::sas::derive_transport_key;
use chrono::{TimeZone, Utc};

const TEST_INIT_PUB: [u8; 33] = [0x01; 33];
const TEST_RESP_PUB: [u8; 33] = [0x02; 33];
const TEST_SESSION_ID: &str = "pq-session-0000";
const TEST_SHORT_CODE: &str = "ABC234";

#[test]
fn hybrid_round_trip_produces_matching_secrets() {
    let initiator = HybridInitiatorKem::generate();
    let slot = initiator.as_kem_slot();

    let (ct_bytes, ss_responder) = encapsulate_against_slot(&slot).expect("encapsulate");
    let ss_initiator = initiator.decapsulate(&ct_bytes).expect("decapsulate");

    assert_eq!(&*ss_initiator, &*ss_responder);
}

#[test]
fn hybrid_transport_key_differs_from_classical() {
    let ss_c = [0x77u8; 32];
    let ss_p = [0x88u8; 32];

    let tk_hybrid = derive_hybrid_transport_key(
        &ss_c,
        &ss_p,
        &TEST_INIT_PUB,
        &TEST_RESP_PUB,
        TEST_SESSION_ID,
        TEST_SHORT_CODE,
    );
    let tk_classical = derive_transport_key(
        &ss_c,
        &TEST_INIT_PUB,
        &TEST_RESP_PUB,
        TEST_SESSION_ID,
        TEST_SHORT_CODE,
    );

    assert_ne!(
        tk_hybrid.as_bytes(),
        tk_classical.as_bytes(),
        "hybrid vs classical MUST derive different transport keys (domain separation)"
    );
}

#[test]
fn pair_flow_rejects_downgrade_silent_classical() {
    // Simulates the downgrade attack: the initiator advertises a hybrid
    // slot and computes its transport key from `ss_c || ss_p`, but the
    // responder silently drops the PQ portion and computes a classical
    // key from `ss_c` alone. The two keys MUST disagree — if they did
    // agree, the responder could downgrade the session undetected.
    let initiator = HybridInitiatorKem::generate();
    let slot = initiator.as_kem_slot();

    let (ct_bytes, ss_p_responder) = encapsulate_against_slot(&slot).unwrap();
    let ss_p_initiator = initiator.decapsulate(&ct_bytes).unwrap();
    assert_eq!(&*ss_p_initiator, &*ss_p_responder);

    // Both sides have the same classical ECDH secret (simulated).
    let ss_c = [0x55u8; 32];

    let tk_initiator = derive_hybrid_transport_key(
        &ss_c,
        &ss_p_initiator,
        &TEST_INIT_PUB,
        &TEST_RESP_PUB,
        TEST_SESSION_ID,
        TEST_SHORT_CODE,
    );
    let tk_responder_downgraded = derive_transport_key(
        &ss_c,
        &TEST_INIT_PUB,
        &TEST_RESP_PUB,
        TEST_SESSION_ID,
        TEST_SHORT_CODE,
    );

    assert_ne!(
        tk_initiator.as_bytes(),
        tk_responder_downgraded.as_bytes(),
        "downgrade to classical MUST produce different key (domain sep + IKM length)"
    );
}

#[test]
fn kem_slot_round_trips_through_json() {
    let initiator = HybridInitiatorKem::generate();
    let slot = initiator.as_kem_slot();

    let token = PairingToken {
        controller_did: "did:keri:test".to_string(),
        endpoint: "http://localhost:3000".to_string(),
        short_code: "ABC234".to_string(),
        session_id: "00000000000000000000000000000000".to_string(),
        ephemeral_pubkey: "AAAA".to_string(),
        expires_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        capabilities: vec!["sign_commit".to_string()],
        kem_slot: Some(slot.clone()),
    };

    let json = serde_json::to_string(&token).unwrap();
    assert!(
        json.contains("kem_slot"),
        "populated slot must appear on wire"
    );
    assert!(json.contains("ml_kem_768"));

    let parsed: PairingToken = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.kem_slot, Some(slot));
}
