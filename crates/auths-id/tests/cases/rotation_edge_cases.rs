use std::ops::ControlFlow;

use auths_core::crypto::signer::encrypt_keypair;
use auths_core::signing::StorageSigner;
use auths_core::storage::keychain::{IdentityDID, KeyAlias, KeyRole, KeyStorage};
use auths_core::testing::{IsolatedKeychainHandle, TestPassphraseProvider};
use auths_id::keri::{
    Event, GitKel, RotationError, anchor_and_persist, create_keri_identity_with_backend,
    create_keri_identity_with_curve, get_key_state, rotate_keys, rotate_keys_with_backend,
    validate_kel,
};
use auths_id::storage::registry::backend::RegistryBackend;
use auths_id::testing::fakes::FakeRegistryBackend;
use serde::{Deserialize, Serialize};

const TEST_PASSPHRASE: &str = "Test-passphrase1!";

#[derive(Debug, Serialize, Deserialize)]
struct TestAttestation {
    issuer: String,
    subject: String,
    capabilities: Vec<String>,
}

fn make_test_attestation(issuer: &str, subject: &str) -> TestAttestation {
    TestAttestation {
        issuer: issuer.to_string(),
        subject: subject.to_string(),
        capabilities: vec!["sign-commit".to_string()],
    }
}

fn store_keypair_in_keychain(
    keychain: &IsolatedKeychainHandle,
    pkcs8: &[u8],
    alias_name: &str,
    identity_did: &str,
) -> KeyAlias {
    let alias = KeyAlias::new_unchecked(alias_name);
    let identity_did_typed = IdentityDID::new_unchecked(identity_did);
    let encrypted = encrypt_keypair(pkcs8, TEST_PASSPHRASE).expect("encrypt keypair");
    keychain
        .store_key(&alias, &identity_did_typed, KeyRole::Primary, &encrypted)
        .expect("store key");
    alias
}

fn anchor_via_kel(
    repo: &git2::Repository,
    prefix: &auths_id::keri::Prefix,
    att: &TestAttestation,
    signer: &dyn auths_core::signing::SecureSigner,
    alias: &KeyAlias,
    provider: &TestPassphraseProvider,
) {
    let kel = GitKel::new(repo, prefix.as_str());
    anchor_and_persist(
        &kel,
        signer,
        alias,
        provider,
        prefix,
        att,
        chrono::Utc::now(),
    )
    .unwrap();
}

// =========================================================================
// Double rotation: replaying a consumed next-key must fail
// =========================================================================

#[test]
fn double_rotation_with_consumed_next_key_fails() {
    let backend = FakeRegistryBackend::new();

    let init = create_keri_identity_with_backend(&backend, None).unwrap();

    let rot1 = rotate_keys_with_backend(
        &backend,
        &init.prefix,
        &init.next_keypair_pkcs8,
        chrono::Utc::now(),
        None,
    )
    .unwrap();
    assert_eq!(rot1.sequence, 1);

    let result = rotate_keys_with_backend(
        &backend,
        &init.prefix,
        &init.next_keypair_pkcs8,
        chrono::Utc::now(),
        None,
    );
    assert!(
        matches!(result, Err(RotationError::CommitmentMismatch)),
        "Replaying a consumed next-key must fail with CommitmentMismatch, got: {:?}",
        result
    );

    let rot2 = rotate_keys_with_backend(
        &backend,
        &init.prefix,
        &rot1.new_next_keypair_pkcs8,
        chrono::Utc::now(),
        None,
    )
    .unwrap();
    assert_eq!(rot2.sequence, 2);
}

#[test]
fn double_rotation_does_not_corrupt_kel() {
    let backend = FakeRegistryBackend::new();

    let init = create_keri_identity_with_backend(&backend, None).unwrap();

    let rot1 = rotate_keys_with_backend(
        &backend,
        &init.prefix,
        &init.next_keypair_pkcs8,
        chrono::Utc::now(),
        None,
    )
    .unwrap();

    let _ = rotate_keys_with_backend(
        &backend,
        &init.prefix,
        &init.next_keypair_pkcs8,
        chrono::Utc::now(),
        None,
    );

    let mut events = Vec::new();
    backend
        .visit_events(&init.prefix, 0, &mut |e| {
            events.push(e.clone());
            ControlFlow::Continue(())
        })
        .unwrap();
    assert_eq!(events.len(), 2, "Failed rotation must not append to KEL");

    let state = validate_kel(&events).unwrap();
    assert_eq!(state.sequence, 1);
    assert!(!state.is_abandoned);

    let rot2 = rotate_keys_with_backend(
        &backend,
        &init.prefix,
        &rot1.new_next_keypair_pkcs8,
        chrono::Utc::now(),
        None,
    )
    .unwrap();
    assert_eq!(rot2.sequence, 2);
}

// =========================================================================
// Rotation after interaction events (IXN interleaved with ROT)
// =========================================================================

#[test]
fn rotation_after_interaction_events_preserves_kel_integrity() {
    let (_dir, repo) = auths_test_utils::git::init_test_repo();
    let keychain = IsolatedKeychainHandle::new();
    let provider = TestPassphraseProvider::new(TEST_PASSPHRASE);

    let init = create_keri_identity_with_curve(
        &repo,
        None,
        chrono::Utc::now(),
        auths_crypto::CurveType::Ed25519,
    )
    .unwrap();
    let identity_did = format!("did:keri:{}", init.prefix);

    let alias = store_keypair_in_keychain(
        &keychain,
        init.current_keypair_pkcs8.as_ref(),
        "current-key",
        &identity_did,
    );
    let signer = StorageSigner::new(keychain);

    let att1 = make_test_attestation(&identity_did, "did:key:device1");
    anchor_via_kel(&repo, &init.prefix, &att1, &signer, &alias, &provider);

    let att2 = make_test_attestation(&identity_did, "did:key:device2");
    anchor_via_kel(&repo, &init.prefix, &att2, &signer, &alias, &provider);

    let rot1 = rotate_keys(
        &repo,
        &init.prefix,
        &init.next_keypair_pkcs8,
        None,
        chrono::Utc::now(),
    )
    .unwrap();
    assert_eq!(rot1.sequence, 3);

    let kel = GitKel::new(&repo, init.prefix.as_str());
    let events = kel.get_events().unwrap();
    assert_eq!(events.len(), 4);
    assert!(matches!(events[0], Event::Icp(_)));
    assert!(matches!(events[1], Event::Ixn(_)));
    assert!(matches!(events[2], Event::Ixn(_)));
    assert!(matches!(events[3], Event::Rot(_)));

    let state = validate_kel(&events).unwrap();
    assert_eq!(state.sequence, 3);
    assert!(!state.is_abandoned);
    assert!(state.can_rotate());
}

#[test]
fn anchoring_works_with_rotated_key_after_ixn() {
    let (_dir, repo) = auths_test_utils::git::init_test_repo();
    let keychain = IsolatedKeychainHandle::new();
    let provider = TestPassphraseProvider::new(TEST_PASSPHRASE);

    let init = create_keri_identity_with_curve(
        &repo,
        None,
        chrono::Utc::now(),
        auths_crypto::CurveType::Ed25519,
    )
    .unwrap();
    let identity_did = format!("did:keri:{}", init.prefix);

    let alias0 = store_keypair_in_keychain(
        &keychain,
        init.current_keypair_pkcs8.as_ref(),
        "key-0",
        &identity_did,
    );
    let signer = StorageSigner::new(keychain.clone());

    let att1 = make_test_attestation(&identity_did, "did:key:device1");
    anchor_via_kel(&repo, &init.prefix, &att1, &signer, &alias0, &provider);

    let rot1 = rotate_keys(
        &repo,
        &init.prefix,
        &init.next_keypair_pkcs8,
        None,
        chrono::Utc::now(),
    )
    .unwrap();

    let alias1 = store_keypair_in_keychain(
        &keychain,
        rot1.new_current_keypair_pkcs8.as_ref(),
        "key-1",
        &identity_did,
    );
    let signer = StorageSigner::new(keychain);

    let att2 = make_test_attestation(&identity_did, "did:key:device2");
    anchor_via_kel(&repo, &init.prefix, &att2, &signer, &alias1, &provider);

    let kel = GitKel::new(&repo, init.prefix.as_str());
    let events = kel.get_events().unwrap();
    assert_eq!(events.len(), 4);
    assert!(matches!(events[0], Event::Icp(_)));
    assert!(matches!(events[1], Event::Ixn(_)));
    assert!(matches!(events[2], Event::Rot(_)));
    assert!(matches!(events[3], Event::Ixn(_)));

    let state = validate_kel(&events).unwrap();
    assert_eq!(state.sequence, 3);
}

#[test]
fn multiple_rotations_interleaved_with_ixn() {
    let (_dir, repo) = auths_test_utils::git::init_test_repo();
    let keychain = IsolatedKeychainHandle::new();
    let provider = TestPassphraseProvider::new(TEST_PASSPHRASE);

    let init = create_keri_identity_with_curve(
        &repo,
        None,
        chrono::Utc::now(),
        auths_crypto::CurveType::Ed25519,
    )
    .unwrap();
    let identity_did = format!("did:keri:{}", init.prefix);

    let alias0 = store_keypair_in_keychain(
        &keychain,
        init.current_keypair_pkcs8.as_ref(),
        "key-0",
        &identity_did,
    );

    let att1 = make_test_attestation(&identity_did, "did:key:device1");
    let signer = StorageSigner::new(keychain.clone());
    anchor_via_kel(&repo, &init.prefix, &att1, &signer, &alias0, &provider);

    let rot1 = rotate_keys(
        &repo,
        &init.prefix,
        &init.next_keypair_pkcs8,
        None,
        chrono::Utc::now(),
    )
    .unwrap();
    assert_eq!(rot1.sequence, 2);

    let alias1 = store_keypair_in_keychain(
        &keychain,
        rot1.new_current_keypair_pkcs8.as_ref(),
        "key-1",
        &identity_did,
    );

    let att2 = make_test_attestation(&identity_did, "did:key:device2");
    let signer = StorageSigner::new(keychain.clone());
    anchor_via_kel(&repo, &init.prefix, &att2, &signer, &alias1, &provider);

    let rot2 = rotate_keys(
        &repo,
        &init.prefix,
        &rot1.new_next_keypair_pkcs8,
        None,
        chrono::Utc::now(),
    )
    .unwrap();
    assert_eq!(rot2.sequence, 4);

    let alias2 = store_keypair_in_keychain(
        &keychain,
        rot2.new_current_keypair_pkcs8.as_ref(),
        "key-2",
        &identity_did,
    );

    let att3 = make_test_attestation(&identity_did, "did:key:device3");
    let signer = StorageSigner::new(keychain);
    anchor_via_kel(&repo, &init.prefix, &att3, &signer, &alias2, &provider);

    let kel = GitKel::new(&repo, init.prefix.as_str());
    let events = kel.get_events().unwrap();
    assert_eq!(events.len(), 6);

    let state = validate_kel(&events).unwrap();
    assert_eq!(state.sequence, 5);
    assert!(!state.is_abandoned);
    assert!(state.can_rotate());

    let key_state = get_key_state(&repo, &init.prefix).unwrap();
    assert_eq!(key_state.sequence, 5);
}
