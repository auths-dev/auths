use auths_sdk::testing::fakes::FakeAllowedSignersStore;
use auths_sdk::workflows::allowed_signers::*;
use auths_verifier::core::Ed25519PublicKey;
use auths_verifier::types::DeviceDID;

#[test]
fn email_validation_accepts_valid() {
    assert!(EmailAddress::new("user@example.com").is_ok());
    assert!(EmailAddress::new("a@b.co").is_ok());
    assert!(EmailAddress::new("user+tag@domain.org").is_ok());
}

#[test]
fn email_validation_rejects_invalid() {
    assert!(EmailAddress::new("").is_err());
    assert!(EmailAddress::new("@").is_err());
    assert!(EmailAddress::new("user@").is_err());
    assert!(EmailAddress::new("@domain.com").is_err());
    assert!(EmailAddress::new("user@domain").is_err());
    assert!(EmailAddress::new("nope").is_err());
}

#[test]
fn email_injection_defense() {
    assert!(EmailAddress::new("a\0b@evil.com").is_err());
    assert!(EmailAddress::new("a\n@evil.com").is_err());
    assert!(EmailAddress::new("a\r@evil.com").is_err());
    assert!(EmailAddress::new("a b@evil.com").is_err());
}

#[test]
fn signer_principal_display_email() {
    let p = SignerPrincipal::Email(EmailAddress::new("user@example.com").unwrap());
    assert_eq!(p.to_string(), "user@example.com");
}

#[test]
fn signer_principal_display_did() {
    let did = DeviceDID::new_unchecked("did:key:z6MkTest123");
    let p = SignerPrincipal::DeviceDid(did);
    assert_eq!(p.to_string(), "z6MkTest123@auths.local");
}

#[test]
fn load_nonexistent_file_returns_empty() {
    let store = FakeAllowedSignersStore::new();
    let signers = AllowedSigners::load("/tmp/auths-test-nonexistent-12345", &store).unwrap();
    assert!(signers.list().is_empty());
}

#[test]
fn add_and_list() {
    let mut signers = AllowedSigners::new("/tmp/test");
    let key = Ed25519PublicKey::from_bytes([1u8; 32]);
    let principal = SignerPrincipal::Email(EmailAddress::new("user@example.com").unwrap());
    signers
        .add(principal.clone(), key, SignerSource::Manual)
        .unwrap();
    assert_eq!(signers.list().len(), 1);
    assert_eq!(signers.list()[0].principal, principal);
}

#[test]
fn add_duplicate_rejected() {
    let mut signers = AllowedSigners::new("/tmp/test");
    let key = Ed25519PublicKey::from_bytes([1u8; 32]);
    let principal = SignerPrincipal::Email(EmailAddress::new("user@example.com").unwrap());
    signers
        .add(principal.clone(), key, SignerSource::Manual)
        .unwrap();
    let result = signers.add(principal, key, SignerSource::Manual);
    assert!(result.is_err());
}

#[test]
fn remove_manual_entry() {
    let mut signers = AllowedSigners::new("/tmp/test");
    let key = Ed25519PublicKey::from_bytes([1u8; 32]);
    let principal = SignerPrincipal::Email(EmailAddress::new("user@example.com").unwrap());
    signers
        .add(principal.clone(), key, SignerSource::Manual)
        .unwrap();
    assert!(signers.remove(&principal).unwrap());
    assert!(signers.list().is_empty());
}

#[test]
fn remove_nonexistent_returns_false() {
    let mut signers = AllowedSigners::new("/tmp/test");
    let principal = SignerPrincipal::Email(EmailAddress::new("user@example.com").unwrap());
    assert!(!signers.remove(&principal).unwrap());
}

#[test]
fn remove_attestation_entry_rejected() {
    let mut signers = AllowedSigners::new("/tmp/test");
    let key = Ed25519PublicKey::from_bytes([1u8; 32]);
    let principal = SignerPrincipal::Email(EmailAddress::new("user@example.com").unwrap());
    signers
        .add(principal.clone(), key, SignerSource::Attestation)
        .unwrap();
    let result = signers.remove(&principal);
    assert!(result.is_err());
}

#[test]
fn save_and_load_roundtrip() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("allowed_signers");

    let mut signers = AllowedSigners::new(&path);
    let key1 = Ed25519PublicKey::from_bytes([1u8; 32]);
    let key2 = Ed25519PublicKey::from_bytes([2u8; 32]);
    signers
        .add(
            SignerPrincipal::Email(EmailAddress::new("manual@example.com").unwrap()),
            key1,
            SignerSource::Manual,
        )
        .unwrap();
    signers
        .add(
            SignerPrincipal::Email(EmailAddress::new("auto@example.com").unwrap()),
            key2,
            SignerSource::Attestation,
        )
        .unwrap();
    let store = FakeAllowedSignersStore::new();
    signers.save(&store).unwrap();

    let loaded = AllowedSigners::load(&path, &store).unwrap();
    assert_eq!(loaded.list().len(), 2);

    let manual = loaded
        .list()
        .iter()
        .find(|e| e.source == SignerSource::Manual)
        .unwrap();
    assert_eq!(manual.principal.to_string(), "manual@example.com");

    let attestation = loaded
        .list()
        .iter()
        .find(|e| e.source == SignerSource::Attestation)
        .unwrap();
    assert_eq!(attestation.principal.to_string(), "auto@example.com");
}

#[test]
fn load_unmarked_file_treats_as_manual() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("allowed_signers");

    // Write a file without section markers
    let key = Ed25519PublicKey::from_bytes([1u8; 32]);
    let ssh_key = auths_sdk::workflows::git_integration::public_key_to_ssh(key.as_bytes()).unwrap();
    let content = format!("user@example.com namespaces=\"git\" {}\n", ssh_key);
    let store = FakeAllowedSignersStore::new().with_file(&path, &content);

    let loaded = AllowedSigners::load(&path, &store).unwrap();
    assert_eq!(loaded.list().len(), 1);
    assert_eq!(loaded.list()[0].source, SignerSource::Manual);
}

#[test]
fn error_info_implemented() {
    use auths_core::error::AuthsErrorInfo;

    let err = AllowedSignersError::InvalidEmail("test".to_string());
    assert!(!err.error_code().is_empty());
    assert!(err.suggestion().is_some());

    let err = AllowedSignersError::DuplicatePrincipal("test".to_string());
    assert!(!err.error_code().is_empty());
    assert!(err.suggestion().is_some());
}
