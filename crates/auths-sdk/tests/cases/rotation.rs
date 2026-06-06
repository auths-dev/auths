use std::sync::Arc;

use auths_core::AgentError;
use auths_core::PrefilledPassphraseProvider;
use auths_core::ports::clock::SystemClock;
use auths_core::signing::{PassphraseProvider, StorageSigner};
use auths_core::storage::keychain::KeyStorage;
use auths_core::storage::keychain::{IdentityDID, KeyAlias, KeyRole};
use auths_core::testing::IsolatedKeychainHandle;
use auths_id::keri::{CesrKey, KeyState, Prefix, Said, Threshold, VersionString};
use auths_id::ports::registry::RegistryBackend;
use auths_id::testing::fakes::FakeRegistryBackend;
use auths_sdk::domains::identity::error::RotationError;
use auths_sdk::domains::identity::service::initialize;
use auths_sdk::domains::identity::types::InitializeResult;
use auths_sdk::domains::identity::types::{
    CreateDeveloperIdentityConfig, IdentityConfig, IdentityRotationConfig,
};
use auths_sdk::domains::signing::types::GitSigningScope;
use auths_sdk::workflows::rotation::{
    RotationKeyMaterial, apply_rotation, compute_rotation_event, rotate_identity,
};
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;

use crate::cases::helpers::{build_test_context, build_test_context_with_provider};

fn setup_test_identity(registry_path: &std::path::Path) -> (KeyAlias, IsolatedKeychainHandle) {
    let keychain = IsolatedKeychainHandle::new();
    let signer = StorageSigner::new(keychain.clone());
    let provider = PrefilledPassphraseProvider::new("Test-passphrase1!");
    let config = CreateDeveloperIdentityConfig::builder(KeyAlias::new_unchecked("test-key"))
        .with_git_signing_scope(GitSigningScope::Skip)
        .with_curve(auths_crypto::CurveType::Ed25519)
        .build();
    let ctx = build_test_context(registry_path, Arc::new(keychain.clone()));
    let result = match initialize(
        IdentityConfig::Developer(config),
        &ctx,
        Arc::new(keychain.clone()),
        &signer,
        &provider,
        None,
    )
    .unwrap()
    {
        InitializeResult::Developer(r) => r,
        _ => unreachable!(),
    };
    (result.key_alias, keychain)
}

/// Test-local: failure-mode `KeyStorage` for testing error paths.
/// Not shared because no other test file needs a universally-failing keychain.
struct FailingKeyStorage;

impl KeyStorage for FailingKeyStorage {
    fn store_key(
        &self,
        _alias: &KeyAlias,
        _identity_did: &IdentityDID,
        _role: KeyRole,
        _encrypted_key_data: &[u8],
    ) -> Result<(), AgentError> {
        Err(AgentError::SigningFailed(
            "simulated keychain failure".into(),
        ))
    }

    fn load_key(&self, _alias: &KeyAlias) -> Result<(IdentityDID, KeyRole, Vec<u8>), AgentError> {
        Err(AgentError::KeyNotFound)
    }

    fn delete_key(&self, _alias: &KeyAlias) -> Result<(), AgentError> {
        Ok(())
    }

    fn list_aliases(&self) -> Result<Vec<KeyAlias>, AgentError> {
        Ok(vec![])
    }

    fn list_aliases_for_identity(
        &self,
        _identity_did: &IdentityDID,
    ) -> Result<Vec<KeyAlias>, AgentError> {
        Ok(vec![])
    }

    fn get_identity_for_alias(&self, _alias: &KeyAlias) -> Result<IdentityDID, AgentError> {
        Err(AgentError::KeyNotFound)
    }

    fn backend_name(&self) -> &'static str {
        "failing-test-storage"
    }
}

#[test]
fn rotate_identity_updates_fingerprints() {
    let tmp = tempfile::tempdir().unwrap();
    let registry_path = tmp.path().join(".auths");

    let (key_alias, keychain) = setup_test_identity(&registry_path);

    let config = IdentityRotationConfig {
        repo_path: registry_path.clone(),
        identity_key_alias: Some(key_alias),
        next_key_alias: None,
    };

    let ctx = build_test_context_with_provider(
        &registry_path,
        Arc::new(keychain.clone()),
        Some(
            Arc::new(PrefilledPassphraseProvider::new("Test-passphrase1!"))
                as Arc<dyn PassphraseProvider + Send + Sync>,
        ),
    );

    let result = rotate_identity(config, &ctx, &SystemClock).unwrap();

    assert!(result.controller_did.starts_with("did:keri:"));
    assert!(!result.new_key_fingerprint.is_empty());
    assert!(!result.previous_key_fingerprint.is_empty());
    assert_ne!(
        result.new_key_fingerprint, result.previous_key_fingerprint,
        "new and previous fingerprints must differ after rotation"
    );
}

#[test]
fn rotate_identity_nonexistent_registry_returns_error() {
    let tmp = tempfile::tempdir().unwrap();
    let missing_path = tmp.path().join(".auths-does-not-exist");

    let config = IdentityRotationConfig {
        repo_path: missing_path.clone(),
        identity_key_alias: Some(KeyAlias::new_unchecked("any-alias")),
        next_key_alias: None,
    };

    let ctx = build_test_context_with_provider(
        &missing_path,
        Arc::new(IsolatedKeychainHandle::new()),
        Some(
            Arc::new(PrefilledPassphraseProvider::new("Test-passphrase1!"))
                as Arc<dyn PassphraseProvider + Send + Sync>,
        ),
    );

    let result = rotate_identity(config, &ctx, &SystemClock);
    assert!(
        matches!(result, Err(RotationError::IdentityNotFound { .. })),
        "Expected IdentityNotFound, got: {:?}",
        result.unwrap_err()
    );
}

#[test]
fn rotate_identity_registry_cleared_returns_error() {
    let tmp = tempfile::tempdir().unwrap();
    let registry_path = tmp.path().join(".auths");
    let (key_alias, keychain) = setup_test_identity(&registry_path);

    let repo = git2::Repository::open(&registry_path).unwrap();
    if let Ok(mut reference) = repo.find_reference("refs/auths/registry") {
        reference.delete().unwrap();
    }

    let config = IdentityRotationConfig {
        repo_path: registry_path.clone(),
        identity_key_alias: Some(key_alias),
        next_key_alias: None,
    };

    let ctx = build_test_context_with_provider(
        &registry_path,
        Arc::new(keychain.clone()),
        Some(
            Arc::new(PrefilledPassphraseProvider::new("Test-passphrase1!"))
                as Arc<dyn PassphraseProvider + Send + Sync>,
        ),
    );

    let result = rotate_identity(config, &ctx, &SystemClock);
    assert!(
        matches!(result, Err(RotationError::IdentityNotFound { .. })),
        "Expected IdentityNotFound, got: {:?}",
        result.unwrap_err()
    );
}

/// Golden-file regression: `compute_rotation_event` with fixed inputs produces
/// byte-identical output across two calls (determinism guarantee).
#[test]
fn compute_rotation_event_is_deterministic() {
    let rng = SystemRandom::new();

    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let new_next_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();

    let state = KeyState {
        prefix: Prefix::new_unchecked("test_prefix_determinism".to_string()),
        current_keys: vec![CesrKey::new_unchecked("D_testkey_placeholder".to_string())],
        next_commitment: vec![Said::new_unchecked("hash_placeholder".to_string())],
        sequence: 0,
        last_event_said: Said::new_unchecked("E_prior_said_placeholder".to_string()),
        is_abandoned: false,
        threshold: Threshold::Simple(1),
        next_threshold: Threshold::Simple(1),
        backers: vec![],
        backer_threshold: Threshold::Simple(0),
        config_traits: vec![],
        is_non_transferable: false,
        delegator: None,
        last_establishment_sequence: 0,
    };

    let signer1 = auths_crypto::TypedSignerKey::from_pkcs8(pkcs8.as_ref()).unwrap();
    let new_next_signer1 =
        auths_crypto::TypedSignerKey::from_pkcs8(new_next_pkcs8.as_ref()).unwrap();
    let (_, bytes1) = compute_rotation_event(
        &state,
        &signer1,
        new_next_signer1.public_key(),
        new_next_signer1.curve(),
        None,
    )
    .unwrap();

    let signer2 = auths_crypto::TypedSignerKey::from_pkcs8(pkcs8.as_ref()).unwrap();
    let new_next_signer2 =
        auths_crypto::TypedSignerKey::from_pkcs8(new_next_pkcs8.as_ref()).unwrap();
    let (_, bytes2) = compute_rotation_event(
        &state,
        &signer2,
        new_next_signer2.public_key(),
        new_next_signer2.curve(),
        None,
    )
    .unwrap();

    assert_eq!(
        bytes1, bytes2,
        "compute_rotation_event must produce identical bytes for identical inputs"
    );
    assert!(!bytes1.is_empty());
}

/// Error path: `apply_rotation` must return `RotationError::PartialRotation` when
/// the KEL append succeeds but the subsequent keychain write fails.
///
/// Uses a RotEvent at sequence 0 (no prior inception required for this test)
/// so `FakeRegistryBackend::append_event` accepts it directly.
#[test]
fn apply_rotation_returns_partial_rotation_on_keychain_failure() {
    use auths_id::keri::Event;

    let rng = SystemRandom::new();
    let next_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let next_signer = auths_crypto::TypedSignerKey::from_pkcs8(next_pkcs8.as_ref()).unwrap();
    let new_next_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let new_next_signer =
        auths_crypto::TypedSignerKey::from_pkcs8(new_next_pkcs8.as_ref()).unwrap();

    let prefix = Prefix::new_unchecked("test_prefix_partial_rotation".to_string());

    // Build a KeyState at sequence 0 so compute_rotation_event produces a seq-1 event
    let state = KeyState {
        prefix: prefix.clone(),
        current_keys: vec![CesrKey::new_unchecked("D_placeholder".to_string())],
        next_commitment: vec![Said::new_unchecked("hash_placeholder".to_string())],
        sequence: 0,
        last_event_said: Said::new_unchecked("E_placeholder_said".to_string()),
        is_abandoned: false,
        threshold: Threshold::Simple(1),
        next_threshold: Threshold::Simple(1),
        backers: vec![],
        backer_threshold: Threshold::Simple(0),
        config_traits: vec![],
        is_non_transferable: false,
        delegator: None,
        last_establishment_sequence: 0,
    };

    let (rot, _bytes) = compute_rotation_event(
        &state,
        &next_signer,
        new_next_signer.public_key(),
        new_next_signer.curve(),
        None,
    )
    .unwrap();

    // Pre-seed the registry with a fake event at seq 0 so the seq-1 RotEvent is accepted
    let registry = Arc::new(FakeRegistryBackend::new());
    let dummy_rot = auths_id::keri::RotEvent {
        v: VersionString::placeholder(),
        d: Said::new_unchecked("E_dummy".to_string()),
        i: prefix.clone(),
        s: auths_id::keri::KeriSequence::new(0),
        p: Said::default(),
        kt: Threshold::Simple(1),
        k: vec![],
        nt: Threshold::Simple(1),
        n: vec![],
        bt: Threshold::Simple(0),
        br: vec![],
        ba: vec![],
        c: vec![],
        a: vec![],
    };
    let _ = registry.append_event(&prefix, &Event::Rot(dummy_rot));

    let key_material = RotationKeyMaterial {
        did: IdentityDID::new_unchecked(format!("did:keri:{}", prefix.as_str())),
        next_alias: KeyAlias::new_unchecked("rotated-key"),
        new_next_alias: KeyAlias::new_unchecked("rotated-key--next-1"),
        old_next_alias: KeyAlias::new_unchecked("test-key--next-0"),
        new_current_encrypted: vec![0u8; 32],
        new_next_encrypted: vec![1u8; 32],
    };

    let failing_keychain = FailingKeyStorage;

    let result = apply_rotation(
        &rot,
        &prefix,
        key_material,
        registry.as_ref(),
        &failing_keychain,
    );

    assert!(
        matches!(result, Err(RotationError::PartialRotation(_))),
        "Expected PartialRotation when keychain write fails after KEL append, got: {:?}",
        result.unwrap_err()
    );
}
