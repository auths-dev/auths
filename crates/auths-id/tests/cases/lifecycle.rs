use auths_core::signing::StorageSigner;
use auths_core::storage::keychain::{IdentityDID, KeyAlias};
use auths_core::testing::{MemoryKeychainHandle, TestPassphraseProvider, get_test_memory_keychain};
use auths_id::attestation::create::create_signed_attestation;
use auths_id::identity::initialize::initialize_keri_identity;
use auths_id::identity::rotate::rotate_keri_identity;
use auths_id::keri::{Event, GitKel, resolve_did_keri, resolve_did_keri_at_sequence, validate_kel};
use auths_id::storage::git_refs::AttestationMetadata;
use auths_id::storage::layout::StorageLayoutConfig;
use auths_verifier::verify::{verify_at_time, verify_with_keys};
use auths_verifier::{DeviceDID, VerificationStatus, verify_chain, verify_device_authorization};

use chrono::Utc;
use git2::Repository;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serial_test::serial;
use std::path::Path;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Initializes a KERI identity via the high-level API.
/// Clears the memory keychain first (fresh state per test).
/// Returns (identity_did, alias).
fn init_identity(repo_path: &Path, alias: &str, passphrase: &str) -> (String, String) {
    let provider = TestPassphraseProvider::new(passphrase);
    // get_test_memory_keychain() clears global state - only call this once per test
    let keychain = get_test_memory_keychain();
    let config = StorageLayoutConfig::default();

    let alias = KeyAlias::new_unchecked(alias);
    let (did, alias) =
        initialize_keri_identity(repo_path, &alias, None, &provider, &config, &*keychain)
            .expect("Failed to initialize identity");
    (did.to_string(), alias.into_inner())
}

/// Returns a MemoryKeychainHandle without clearing the keychain.
/// Use this for all operations after init_identity.
fn keychain_handle() -> MemoryKeychainHandle {
    MemoryKeychainHandle
}

/// Generates a fresh Ed25519 device keypair and stores it in the memory keychain.
/// Returns (device_did, device_public_key_bytes_32).
fn generate_device_keypair(
    identity_did: &str,
    device_alias: &str,
    passphrase: &str,
) -> (DeviceDID, [u8; 32]) {
    let rng = SystemRandom::new();
    let device_pkcs8 =
        Ed25519KeyPair::generate_pkcs8(&rng).expect("Failed to generate device keypair");
    let device_keypair =
        Ed25519KeyPair::from_pkcs8(device_pkcs8.as_ref()).expect("Failed to parse device keypair");
    let device_pk: [u8; 32] = device_keypair
        .public_key()
        .as_ref()
        .try_into()
        .expect("Public key should be 32 bytes");

    let device_did = DeviceDID::from_ed25519(&device_pk);

    // Store device key in the memory keychain so the signer can find it
    let encrypted = auths_core::crypto::signer::encrypt_keypair(device_pkcs8.as_ref(), passphrase)
        .expect("Failed to encrypt device key");
    let identity_did_typed = IdentityDID::new(identity_did);
    auths_core::testing::MEMORY_KEYCHAIN
        .lock()
        .unwrap()
        .store_key(
            &KeyAlias::new_unchecked(device_alias),
            &identity_did_typed,
            &encrypted,
        )
        .expect("Failed to store device key");

    (device_did, device_pk)
}

/// Creates a signed attestation using the real `create_signed_attestation` API.
/// Uses MemoryKeychainHandle directly (does NOT clear the keychain).
fn create_test_attestation(
    rid: &str,
    identity_did: &str,
    identity_alias: &str,
    device_did: &DeviceDID,
    device_pk: &[u8],
    device_alias: Option<&str>,
    passphrase: &str,
) -> auths_verifier::core::Attestation {
    let signer = StorageSigner::new(keychain_handle());
    let provider = TestPassphraseProvider::new(passphrase);
    let now = Utc::now();
    let meta = AttestationMetadata {
        note: Some("integration test".to_string()),
        timestamp: Some(now),
        expires_at: None,
    };
    let identity_did = IdentityDID::new(identity_did);
    let identity_alias = KeyAlias::new_unchecked(identity_alias);
    let device_alias = device_alias.map(KeyAlias::new_unchecked);

    create_signed_attestation(
        now,
        rid,
        &identity_did,
        device_did,
        device_pk,
        None,
        &meta,
        &signer,
        &provider,
        Some(&identity_alias),
        device_alias.as_ref(),
        vec![],
        None,
        None,
    )
    .expect("Failed to create signed attestation")
}

/// Resolves the current public key for a did:keri identity by replaying the KEL.
fn resolve_identity_public_key(repo_path: &Path, did: &str) -> Vec<u8> {
    let repo = Repository::open(repo_path).expect("Failed to open repo");
    let resolution = resolve_did_keri(&repo, did).expect("Failed to resolve did:keri");
    resolution.public_key
}

/// Resolves the public key at a specific KEL sequence.
fn resolve_identity_public_key_at_sequence(repo_path: &Path, did: &str, sequence: u64) -> Vec<u8> {
    let repo = Repository::open(repo_path).expect("Failed to open repo");
    let resolution =
        resolve_did_keri_at_sequence(&repo, did, sequence).expect("Failed to resolve at sequence");
    resolution.public_key
}

/// Rotates a KERI identity via the high-level API.
/// Uses MemoryKeychainHandle directly (does NOT clear the keychain).
fn rotate_identity(repo_path: &Path, current_alias: &str, next_alias: &str, passphrase: &str) {
    let provider = TestPassphraseProvider::new(passphrase);
    let kc = keychain_handle();
    let config = StorageLayoutConfig::default();

    let current_alias = KeyAlias::new_unchecked(current_alias);
    let next_alias = KeyAlias::new_unchecked(next_alias);
    rotate_keri_identity(
        repo_path,
        &current_alias,
        &next_alias,
        &provider,
        &config,
        &kc,
        None,
    )
    .expect("Failed to rotate identity");
}

// ---------------------------------------------------------------------------
// Test cases
// ---------------------------------------------------------------------------

/// Full lifecycle: init -> attest -> verify -> rotate -> historical verify -> new attest -> verify
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_full_identity_lifecycle() {
    let (_dir, _repo) = auths_test_utils::git::init_test_repo();
    let repo_path = _dir.path().to_path_buf();
    let passphrase = "Test-P@ss12345";

    // 1. Initialize identity (clears keychain)
    let (identity_did, identity_alias) = init_identity(&repo_path, "main", passphrase);
    assert!(
        identity_did.starts_with("did:keri:"),
        "DID should be a KERI DID"
    );

    // 2. Resolve the identity public key from KEL
    let identity_pk = resolve_identity_public_key(&repo_path, &identity_did);
    assert_eq!(
        identity_pk.len(),
        32,
        "Ed25519 public key should be 32 bytes"
    );

    // 3. Generate a device keypair and create attestation
    let (device_did, device_pk) =
        generate_device_keypair(&identity_did, "device-laptop", passphrase);
    let attestation = create_test_attestation(
        "test-repo",
        &identity_did,
        &identity_alias,
        &device_did,
        &device_pk,
        Some("device-laptop"),
        passphrase,
    );

    // 4. Verify the attestation with the identity's public key
    verify_with_keys(&attestation, &identity_pk)
        .await
        .expect("Attestation should verify");

    // 5. Rotate the identity key
    rotate_identity(&repo_path, "main", "main-rot1", passphrase);

    // 6. Verify OLD attestation still passes with historical key (sequence 0)
    let old_pk = resolve_identity_public_key_at_sequence(&repo_path, &identity_did, 0);
    assert_eq!(old_pk, identity_pk, "Historical key should match original");
    verify_at_time(&attestation, &old_pk, attestation.timestamp.unwrap())
        .await
        .expect("Old attestation should verify with historical key");

    // 7. Create NEW attestation with rotated key
    let new_identity_pk = resolve_identity_public_key(&repo_path, &identity_did);
    assert_ne!(
        new_identity_pk, identity_pk,
        "Rotated key should differ from original"
    );

    let (device_did2, device_pk2) =
        generate_device_keypair(&identity_did, "device-phone", passphrase);
    let new_attestation = create_test_attestation(
        "test-repo",
        &identity_did,
        "main-rot1",
        &device_did2,
        &device_pk2,
        Some("device-phone"),
        passphrase,
    );

    // 8. Verify new attestation with new public key
    verify_with_keys(&new_attestation, &new_identity_pk)
        .await
        .expect("New attestation should verify with rotated key");
}

/// Chain verification: identity -> device1 -> device2, then rotate and re-verify chain.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_attestation_chain_after_rotation() {
    let (_dir, _repo) = auths_test_utils::git::init_test_repo();
    let repo_path = _dir.path().to_path_buf();
    let passphrase = "Test-P@ss12345";

    // Init identity (clears keychain)
    let (identity_did, identity_alias) = init_identity(&repo_path, "chain-id", passphrase);
    let identity_pk = resolve_identity_public_key(&repo_path, &identity_did);

    // Create device1 and attestation: identity -> device1
    let (device1_did, device1_pk) =
        generate_device_keypair(&identity_did, "chain-device1", passphrase);
    let att1 = create_test_attestation(
        "test-repo",
        &identity_did,
        &identity_alias,
        &device1_did,
        &device1_pk,
        Some("chain-device1"),
        passphrase,
    );

    // Create device2 and attestation: device1 -> device2
    let (device2_did, device2_pk) =
        generate_device_keypair(&identity_did, "chain-device2", passphrase);

    let device1_did_str = device1_did.to_string();
    let att2 = create_test_attestation(
        "test-repo",
        &device1_did_str,
        "chain-device1",
        &device2_did,
        &device2_pk,
        Some("chain-device2"),
        passphrase,
    );

    // Verify 2-link chain
    let report = verify_chain(&[att1.clone(), att2], &identity_pk)
        .await
        .expect("Chain verify failed");
    assert!(report.is_valid(), "Chain should be valid");
    assert_eq!(report.chain.len(), 2);

    // Rotate identity key
    rotate_identity(&repo_path, "chain-id", "chain-id-rot1", passphrase);

    // Verify the first link still works with historical key
    let old_pk = resolve_identity_public_key_at_sequence(&repo_path, &identity_did, 0);
    verify_at_time(&att1, &old_pk, att1.timestamp.unwrap())
        .await
        .expect("First chain link should still verify with historical key");
}

/// Device authorization lifecycle: create -> verify valid -> mark revoked -> verify revoked.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_verify_device_authorization_lifecycle() {
    let (_dir, _repo) = auths_test_utils::git::init_test_repo();
    let repo_path = _dir.path().to_path_buf();
    let passphrase = "Test-P@ss12345";

    // Init identity (clears keychain)
    let (identity_did, identity_alias) = init_identity(&repo_path, "authz-id", passphrase);
    let identity_pk = resolve_identity_public_key(&repo_path, &identity_did);

    // Create device and attestation
    let (device_did, device_pk) =
        generate_device_keypair(&identity_did, "authz-device", passphrase);
    let attestation = create_test_attestation(
        "test-repo",
        &identity_did,
        &identity_alias,
        &device_did,
        &device_pk,
        Some("authz-device"),
        passphrase,
    );

    // Verify device is authorized
    let report = verify_device_authorization(
        &identity_did,
        &device_did,
        std::slice::from_ref(&attestation),
        &identity_pk,
    )
    .await
    .expect("verify_device_authorization failed");
    assert!(report.is_valid(), "Device should be authorized");

    // Create a "revoked" version of the attestation
    let mut revoked_att = attestation;
    revoked_att.revoked_at = Some(Utc::now());
    // Note: The verifier checks the revoked flag before signature verification,
    // so this tests the revocation check path.

    let report =
        verify_device_authorization(&identity_did, &device_did, &[revoked_att], &identity_pk)
            .await
            .expect("verify_device_authorization failed");
    assert!(
        !report.is_valid(),
        "Revoked device should not be authorized"
    );
    match report.status {
        VerificationStatus::Revoked { .. } => {}
        _ => panic!("Expected Revoked status, got {:?}", report.status),
    }
}

/// Multiple rotations: verify that the original attestation remains verifiable
/// through the entire key history.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_multiple_rotations_maintain_verification() {
    let (_dir, _repo) = auths_test_utils::git::init_test_repo();
    let repo_path = _dir.path().to_path_buf();
    let passphrase = "Test-P@ss12345";

    // Init identity (clears keychain)
    let (identity_did, _identity_alias) = init_identity(&repo_path, "multi-rot", passphrase);
    let original_pk = resolve_identity_public_key(&repo_path, &identity_did);

    // Create attestation with initial key
    let (device_did, device_pk) =
        generate_device_keypair(&identity_did, "multi-rot-device", passphrase);
    let original_attestation = create_test_attestation(
        "test-repo",
        &identity_did,
        "multi-rot",
        &device_did,
        &device_pk,
        Some("multi-rot-device"),
        passphrase,
    );

    // Verify initial attestation
    verify_with_keys(&original_attestation, &original_pk)
        .await
        .expect("Original attestation should verify");

    // Rotate 3 times: multi-rot -> multi-rot2 -> multi-rot3 -> multi-rot4
    rotate_identity(&repo_path, "multi-rot", "multi-rot2", passphrase);
    rotate_identity(&repo_path, "multi-rot2", "multi-rot3", passphrase);
    rotate_identity(&repo_path, "multi-rot3", "multi-rot4", passphrase);

    // Verify original attestation still works with historical key (sequence 0)
    let historical_pk = resolve_identity_public_key_at_sequence(&repo_path, &identity_did, 0);
    assert_eq!(historical_pk, original_pk);
    verify_at_time(
        &original_attestation,
        &historical_pk,
        original_attestation.timestamp.unwrap(),
    )
    .await
    .expect("Original attestation should verify with historical key after 3 rotations");

    // Create new attestation with final rotated key
    let current_pk = resolve_identity_public_key(&repo_path, &identity_did);
    assert_ne!(
        current_pk, original_pk,
        "Key should have changed after rotations"
    );

    let (device_did2, device_pk2) =
        generate_device_keypair(&identity_did, "multi-rot-device2", passphrase);
    let new_attestation = create_test_attestation(
        "test-repo",
        &identity_did,
        "multi-rot4",
        &device_did2,
        &device_pk2,
        Some("multi-rot-device2"),
        passphrase,
    );

    // Verify new attestation with current key
    verify_with_keys(&new_attestation, &current_pk)
        .await
        .expect("New attestation should verify with current key");
}

/// Inception creates exactly one KEL event with the correct prefix.
#[test]
#[serial]
fn test_init_creates_keri_kel() {
    let (_dir, _repo) = auths_test_utils::git::init_test_repo();
    let repo_path = _dir.path().to_path_buf();
    let passphrase = "Test-P@ss12345";

    let (identity_did, _alias) = init_identity(&repo_path, "kel-test", passphrase);

    // Extract prefix from DID
    let prefix = identity_did
        .strip_prefix("did:keri:")
        .expect("Should be a did:keri");

    // Read KEL from Git storage
    let repo = Repository::open(&repo_path).expect("Failed to open repo");
    let kel = GitKel::new(&repo, prefix);
    let events = kel.get_events().expect("Failed to read KEL events");

    // Assert exactly 1 event (inception)
    assert_eq!(events.len(), 1, "KEL should have exactly 1 inception event");
    assert!(
        matches!(events[0], Event::Icp(_)),
        "First event should be inception"
    );

    // Validate the KEL
    let state = validate_kel(&events).expect("KEL validation failed");
    assert_eq!(state.sequence, 0, "Inception should be sequence 0");
}

/// Rotation appends to the KEL with correct sequence numbers.
#[test]
#[serial]
fn test_rotation_appends_to_kel() {
    let (_dir, _repo) = auths_test_utils::git::init_test_repo();
    let repo_path = _dir.path().to_path_buf();
    let passphrase = "Test-P@ss12345";

    let (identity_did, _alias) = init_identity(&repo_path, "kel-rot", passphrase);
    let prefix = identity_did
        .strip_prefix("did:keri:")
        .expect("Should be a did:keri");
    let repo = Repository::open(&repo_path).expect("Failed to open repo");

    // After init: 1 event
    let kel = GitKel::new(&repo, prefix);
    let events = kel.get_events().expect("Failed to read KEL");
    assert_eq!(events.len(), 1);

    // Rotate once
    rotate_identity(&repo_path, "kel-rot", "kel-rot2", passphrase);

    // Reopen to see updates
    let repo = Repository::open(&repo_path).expect("Failed to reopen repo");
    let kel = GitKel::new(&repo, prefix);
    let events = kel.get_events().expect("Failed to read KEL after rotation");
    assert_eq!(events.len(), 2, "KEL should have 2 events after 1 rotation");
    assert!(matches!(events[0], Event::Icp(_)));
    assert!(matches!(events[1], Event::Rot(_)));

    let state = validate_kel(&events).expect("KEL validation failed");
    assert_eq!(state.sequence, 1);

    // Rotate again
    rotate_identity(&repo_path, "kel-rot2", "kel-rot3", passphrase);

    let repo = Repository::open(&repo_path).expect("Failed to reopen repo");
    let kel = GitKel::new(&repo, prefix);
    let events = kel
        .get_events()
        .expect("Failed to read KEL after 2nd rotation");
    assert_eq!(
        events.len(),
        3,
        "KEL should have 3 events after 2 rotations"
    );

    // Validate sequence numbers: 0, 1, 2
    let state = validate_kel(&events).expect("KEL validation failed");
    assert_eq!(state.sequence, 2);

    for (i, event) in events.iter().enumerate() {
        assert_eq!(
            event.sequence().unwrap(),
            i as u64,
            "Event {} should have sequence {}",
            i,
            i
        );
    }
}
