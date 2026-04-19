//! fn-129.T10 wire-compat: a `PairingToken` emitted with `kem_slot = None`
//! round-trips identically, and a parser on a default (no-`pq-hybrid`) build
//! accepts-but-ignores a populated `kem_slot` field if one arrives on the
//! wire from a hybrid-build peer.
//!
//! These tests run on both `default` and `--features pq-hybrid` builds so
//! the wire-format contract is frozen independently of whether any
//! cryptography module is active in the current compile.

use auths_pairing_protocol::{KemSlot, PairingToken};
use chrono::{TimeZone, Utc};

fn sample_token_no_slot() -> PairingToken {
    PairingToken {
        controller_did: "did:keri:test".to_string(),
        endpoint: "http://localhost:3000".to_string(),
        short_code: "ABC234".to_string(),
        session_id: "00000000000000000000000000000000".to_string(),
        ephemeral_pubkey: "AAAA".to_string(),
        expires_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
        capabilities: vec!["sign_commit".to_string()],
        kem_slot: None,
    }
}

/// Default-build token never emits the `kem_slot` field (it's Option +
/// `skip_serializing_if`), so old consumers see exactly the pre-T10 wire
/// shape.
#[test]
fn default_token_omits_kem_slot_key() {
    let token = sample_token_no_slot();
    let json = serde_json::to_string(&token).unwrap();
    assert!(
        !json.contains("kem_slot"),
        "None kem_slot must not appear on the wire; got: {json}"
    );
}

/// A JSON payload that DOES include `kem_slot: null` is still accepted,
/// because the field is `#[serde(default)]`.
#[test]
fn null_kem_slot_parses_as_none() {
    let json = r#"{
        "controller_did": "did:keri:test",
        "endpoint": "http://localhost:3000",
        "short_code": "ABC234",
        "session_id": "00000000000000000000000000000000",
        "ephemeral_pubkey": "AAAA",
        "expires_at": "2026-01-01T00:00:00Z",
        "capabilities": ["sign_commit"],
        "kem_slot": null
    }"#;
    let parsed: PairingToken = serde_json::from_str(json).unwrap();
    assert!(parsed.kem_slot.is_none());
}

/// A JSON payload without `kem_slot` at all — the shape emitted by
/// pre-T10 peers — parses cleanly.
#[test]
fn absent_kem_slot_parses_as_none() {
    let json = r#"{
        "controller_did": "did:keri:test",
        "endpoint": "http://localhost:3000",
        "short_code": "ABC234",
        "session_id": "00000000000000000000000000000000",
        "ephemeral_pubkey": "AAAA",
        "expires_at": "2026-01-01T00:00:00Z",
        "capabilities": ["sign_commit"]
    }"#;
    let parsed: PairingToken = serde_json::from_str(json).unwrap();
    assert!(parsed.kem_slot.is_none());
}

/// A hybrid-build peer emits `kem_slot = Some(MlKem768 { … })`. A
/// default-build (no `pq-hybrid`) deserializer accepts the field — it
/// cannot act on the contents, but the wire parse succeeds. This is
/// the foundation of the "accept-but-don't-act" downgrade-safe path.
#[test]
fn populated_kem_slot_parses_on_any_build() {
    let json = r#"{
        "controller_did": "did:keri:test",
        "endpoint": "http://localhost:3000",
        "short_code": "ABC234",
        "session_id": "00000000000000000000000000000000",
        "ephemeral_pubkey": "AAAA",
        "expires_at": "2026-01-01T00:00:00Z",
        "capabilities": ["sign_commit"],
        "kem_slot": {
            "algo": "ml_kem_768",
            "public_key": "AAAA"
        }
    }"#;
    let parsed: PairingToken = serde_json::from_str(json).unwrap();
    match parsed.kem_slot {
        Some(KemSlot::MlKem768 { public_key }) => assert_eq!(public_key, "AAAA"),
        other => panic!("expected Some(MlKem768 {{..}}), got {other:?}"),
    }
}

/// Unknown future algorithm: a peer advertising an ML-KEM parameter set
/// we haven't shipped yet (e.g. `ml_kem_1024`) must fail to deserialize
/// loudly — we do NOT want to silently treat an unknown PQ algo as "no
/// slot", because that IS the downgrade attack.
#[test]
fn unknown_kem_algo_is_rejected() {
    let json = r#"{
        "controller_did": "did:keri:test",
        "endpoint": "http://localhost:3000",
        "short_code": "ABC234",
        "session_id": "00000000000000000000000000000000",
        "ephemeral_pubkey": "AAAA",
        "expires_at": "2026-01-01T00:00:00Z",
        "capabilities": ["sign_commit"],
        "kem_slot": {
            "algo": "future_pq_algo",
            "public_key": "AAAA"
        }
    }"#;
    let result: Result<PairingToken, _> = serde_json::from_str(json);
    assert!(
        result.is_err(),
        "unknown PQ algo must not silently parse as None (downgrade hazard)"
    );
}
