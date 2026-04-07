use auths_crypto::RingCryptoProvider;
use auths_verifier::{
    AttestationBuilder, DeviceLinkVerification, ValidationError, parse_kel_json, verify_device_link,
};

fn provider() -> RingCryptoProvider {
    RingCryptoProvider
}

#[test]
fn parse_kel_json_rejects_invalid_json() {
    let result = parse_kel_json("not valid json");
    assert!(result.is_err());
    match result.unwrap_err() {
        ValidationError::Serialization(_) => {}
        other => panic!("expected Serialization error, got: {:?}", other),
    }
}

#[test]
fn parse_kel_json_returns_empty_vec_for_empty_array() {
    let events = parse_kel_json("[]").unwrap();
    assert!(events.is_empty());
}

#[test]
fn validate_kel_rejects_empty_events() {
    let result = auths_keri::validate_kel(&[]);
    assert!(result.is_err());
    match result.unwrap_err() {
        ValidationError::EmptyKel => {}
        other => panic!("expected EmptyKel error, got: {:?}", other),
    }
}

#[test]
fn parse_kel_json_rejects_non_array_json() {
    let result = parse_kel_json(r#"{"t": "icp"}"#);
    assert!(result.is_err());
}

// --- DeviceLinkVerification tests ---

#[tokio::test]
async fn verify_device_link_fails_on_empty_kel() {
    let att = minimal_attestation("did:keri:ETest", "did:key:z6MkTest");
    let result = verify_device_link(
        &[],
        &att,
        "did:key:z6MkTest",
        chrono::Utc::now(),
        &provider(),
    )
    .await;

    assert!(!result.valid);
    assert!(
        result
            .error
            .as_ref()
            .unwrap()
            .contains("KEL verification failed")
    );
    assert!(result.key_state.is_none());
}

#[test]
fn device_link_verification_failure_serializes_correctly() {
    let result = DeviceLinkVerification {
        valid: false,
        error: Some("Device DID mismatch".to_string()),
        key_state: None,
        seal_sequence: None,
    };

    let json = serde_json::to_string(&result).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed["valid"], false);
    assert_eq!(parsed["error"], "Device DID mismatch");
    assert!(parsed.get("key_state").is_none());
    assert!(parsed.get("seal_sequence").is_none());
}

fn minimal_attestation(issuer: &str, subject: &str) -> auths_verifier::core::Attestation {
    AttestationBuilder::default()
        .rid("")
        .issuer(issuer)
        .subject(subject)
        .build()
}
