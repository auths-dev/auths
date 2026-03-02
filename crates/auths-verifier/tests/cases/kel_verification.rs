use auths_verifier::{KeriKeyState, KeriVerifyError, Prefix, Said, parse_kel_json, verify_kel};

use auths_crypto::RingCryptoProvider;

fn provider() -> RingCryptoProvider {
    RingCryptoProvider
}

#[test]
fn keri_key_state_serializes_without_raw_key_bytes() {
    let state = KeriKeyState {
        prefix: Prefix::new_unchecked("ETestPrefix123".to_string()),
        current_key: vec![1, 2, 3, 4],
        current_key_encoded: "DTestKey456".to_string(),
        next_commitment: Some("ENextCommitment789".to_string()),
        sequence: 3,
        is_abandoned: false,
        last_event_said: Said::new_unchecked("ELastSaid000".to_string()),
    };

    let json = serde_json::to_string(&state).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed["prefix"], "ETestPrefix123");
    assert_eq!(parsed["current_key_encoded"], "DTestKey456");
    assert_eq!(parsed["next_commitment"], "ENextCommitment789");
    assert_eq!(parsed["sequence"], 3);
    assert_eq!(parsed["is_abandoned"], false);
    assert_eq!(parsed["last_event_said"], "ELastSaid000");
    assert!(
        parsed.get("current_key").is_none(),
        "raw key bytes should be skipped in serialization"
    );
}

#[test]
fn keri_key_state_serializes_with_null_next_commitment_when_abandoned() {
    let state = KeriKeyState {
        prefix: Prefix::new_unchecked("ETestPrefix".to_string()),
        current_key: vec![],
        current_key_encoded: "DKey".to_string(),
        next_commitment: None,
        sequence: 0,
        is_abandoned: true,
        last_event_said: Said::new_unchecked("ESaid".to_string()),
    };

    let json = serde_json::to_string(&state).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert!(parsed["next_commitment"].is_null());
    assert_eq!(parsed["is_abandoned"], true);
}

#[test]
fn parse_kel_json_rejects_invalid_json() {
    let result = parse_kel_json("not valid json");
    assert!(result.is_err());
    match result.unwrap_err() {
        KeriVerifyError::Serialization(_) => {}
        other => panic!("expected Serialization error, got: {:?}", other),
    }
}

#[test]
fn parse_kel_json_returns_empty_vec_for_empty_array() {
    let events = parse_kel_json("[]").unwrap();
    assert!(events.is_empty());
}

#[tokio::test]
async fn verify_kel_rejects_empty_events() {
    let result = verify_kel(&[], &provider()).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        KeriVerifyError::EmptyKel => {}
        other => panic!("expected EmptyKel error, got: {:?}", other),
    }
}

#[test]
fn parse_kel_json_rejects_non_array_json() {
    let result = parse_kel_json(r#"{"t": "icp"}"#);
    assert!(result.is_err());
}
