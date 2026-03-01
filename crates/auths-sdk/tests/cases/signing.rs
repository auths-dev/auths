use auths_sdk::signing::{self, SigningConfig, SigningError};

#[test]
fn test_validate_freeze_state_unfrozen() {
    let temp = tempfile::tempdir().unwrap();
    let result = signing::validate_freeze_state(temp.path(), chrono::Utc::now());
    assert!(result.is_ok(), "unfrozen state should pass validation");
}

#[test]
fn test_construct_signature_payload() {
    let data = b"test data";
    let result = signing::construct_signature_payload(data, "git");
    assert!(result.is_ok());

    let payload = result.unwrap();
    assert_eq!(
        &payload[0..6],
        b"SSHSIG",
        "payload must start with SSHSIG magic"
    );
    assert_eq!(&payload[6..10], &3u32.to_be_bytes(), "namespace length");
    assert_eq!(&payload[10..13], b"git");
}

#[test]
fn test_sign_with_known_seed() {
    use auths_core::crypto::ssh::SecureSeed;

    let seed = SecureSeed::new([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ]);

    let pem = signing::sign_with_seed(&seed, b"test data", "git").unwrap();
    assert!(pem.starts_with("-----BEGIN SSH SIGNATURE-----"));
    assert!(pem.contains("-----END SSH SIGNATURE-----"));
}

#[test]
fn test_signing_error_is_thiserror() {
    let err = SigningError::IdentityFrozen("test freeze".to_string());
    assert!(err.to_string().contains("frozen"));

    let err = SigningError::InvalidPassphrase;
    assert_eq!(err.to_string(), "invalid passphrase");
}

#[test]
fn test_signing_config_fields() {
    let config = SigningConfig {
        namespace: "git".to_string(),
    };
    assert_eq!(config.namespace, "git");
}
