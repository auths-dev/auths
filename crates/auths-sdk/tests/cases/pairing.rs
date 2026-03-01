use auths_sdk::pairing::{self, PairingError};
use auths_storage::git::RegistryIdentityStorage;

#[test]
fn test_validate_short_code_valid() {
    let result = pairing::validate_short_code("ABC123");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "ABC123");
}

#[test]
fn test_validate_short_code_with_dash() {
    let result = pairing::validate_short_code("ABC-123");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "ABC123");
}

#[test]
fn test_validate_short_code_with_spaces() {
    let result = pairing::validate_short_code("ABC 123");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "ABC123");
}

#[test]
fn test_validate_short_code_lowercase() {
    let result = pairing::validate_short_code("abc123");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "ABC123");
}

#[test]
fn test_validate_short_code_too_short() {
    let result = pairing::validate_short_code("ABC");
    assert!(result.is_err());
    match result.unwrap_err() {
        PairingError::InvalidShortCode(msg) => assert!(msg.contains("6 characters")),
        other => panic!("expected InvalidShortCode, got: {}", other),
    }
}

#[test]
fn test_validate_short_code_empty() {
    let result = pairing::validate_short_code("");
    assert!(result.is_err());
}

#[test]
fn test_verify_session_status_pending() {
    use auths_core::pairing::types::SessionStatus;
    let result = pairing::verify_session_status(&SessionStatus::Pending);
    assert!(result.is_ok());
}

#[test]
fn test_verify_session_status_expired() {
    use auths_core::pairing::types::SessionStatus;
    let result = pairing::verify_session_status(&SessionStatus::Expired);
    assert!(result.is_err());
    match result.unwrap_err() {
        PairingError::SessionExpired => {}
        other => panic!("expected SessionExpired, got: {}", other),
    }
}

#[test]
fn test_verify_session_status_responded() {
    use auths_core::pairing::types::SessionStatus;
    let result = pairing::verify_session_status(&SessionStatus::Responded);
    assert!(result.is_err());
    match result.unwrap_err() {
        PairingError::SessionNotAvailable(_) => {}
        other => panic!("expected SessionNotAvailable, got: {}", other),
    }
}

#[test]
fn test_verify_device_did_matches() {
    use auths_verifier::types::DeviceDID;

    let pubkey = [0x42u8; 32];
    let expected_did = DeviceDID::from_ed25519(&pubkey);
    let result = pairing::verify_device_did(&pubkey, &expected_did.to_string());
    assert!(result.is_ok());
}

#[test]
fn test_verify_device_did_mismatch() {
    let pubkey = [0x42u8; 32];
    let result = pairing::verify_device_did(&pubkey, "did:key:zFAKE");
    assert!(result.is_err());
    match result.unwrap_err() {
        PairingError::DidMismatch { response, derived } => {
            assert_eq!(response, "did:key:zFAKE");
            assert!(!derived.is_empty());
        }
        other => panic!("expected DidMismatch, got: {}", other),
    }
}

#[test]
fn test_load_controller_did_nonexistent_dir() {
    let storage = RegistryIdentityStorage::new("/nonexistent/path");
    let result = pairing::load_controller_did(&storage);
    assert!(result.is_err());
    match result.unwrap_err() {
        PairingError::IdentityNotFound(_) => {}
        other => panic!("expected IdentityNotFound, got: {}", other),
    }
}

#[test]
fn test_pairing_error_display() {
    let err = PairingError::SessionExpired;
    assert_eq!(err.to_string(), "session expired");

    let err = PairingError::DidMismatch {
        response: "did:a".to_string(),
        derived: "did:b".to_string(),
    };
    assert!(err.to_string().contains("did:a"));
    assert!(err.to_string().contains("did:b"));
}
