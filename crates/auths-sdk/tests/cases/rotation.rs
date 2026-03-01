use std::sync::Arc;

use auths_core::AgentError;
use auths_core::PrefilledPassphraseProvider;
use auths_core::ports::clock::SystemClock;
use auths_core::signing::{PassphraseProvider, StorageSigner};
use auths_core::storage::keychain::KeyStorage;
use auths_core::storage::keychain::{IdentityDID, KeyAlias};
use auths_core::storage::memory::{MEMORY_KEYCHAIN, MemoryKeychainHandle};
use auths_id::keri::{KeyState, Prefix, Said};
use auths_id::ports::registry::RegistryBackend;
use auths_sdk::error::RotationError;
use auths_sdk::setup::setup_developer;
use auths_sdk::types::{DeveloperSetupConfig, GitSigningScope, RotationConfig};
use auths_sdk::workflows::rotation::{
    RotationKeyMaterial, apply_rotation, compute_rotation_event, rotate_identity,
};
use auths_test_utils::fakes::registry::FakeRegistryBackend;
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;

use crate::cases::helpers::{build_test_context, build_test_context_with_provider};

fn setup_test_identity(registry_path: &std::path::Path) -> KeyAlias {
    MEMORY_KEYCHAIN.lock().unwrap().clear_all().ok();
    let keychain = MemoryKeychainHandle;
    let signer = StorageSigner::new(MemoryKeychainHandle);
    let provider = PrefilledPassphraseProvider::new("Test-passphrase1!");
    let config = DeveloperSetupConfig::builder(KeyAlias::new_unchecked("test-key"))
        .with_git_signing_scope(GitSigningScope::Skip)
        .build();
    let ctx = build_test_context(registry_path, Arc::new(MemoryKeychainHandle));
    let result = setup_developer(config, &ctx, &keychain, &signer, &provider, None).unwrap();
    result.key_alias
}

/// A `KeyStorage` implementation that always fails on `store_key`.
struct FailingKeyStorage;

impl KeyStorage for FailingKeyStorage {
    fn store_key(
        &self,
        _alias: &KeyAlias,
        _identity_did: &IdentityDID,
        _encrypted_key_data: &[u8],
    ) -> Result<(), AgentError> {
        Err(AgentError::SigningFailed(
            "simulated keychain failure".into(),
        ))
    }

    fn load_key(&self, _alias: &KeyAlias) -> Result<(IdentityDID, Vec<u8>), AgentError> {
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

    let key_alias = setup_test_identity(&registry_path);

    let config = RotationConfig {
        repo_path: registry_path.clone(),
        identity_key_alias: Some(key_alias),
        next_key_alias: None,
    };

    let ctx = build_test_context_with_provider(
        &registry_path,
        Arc::new(MemoryKeychainHandle),
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

    let config = RotationConfig {
        repo_path: missing_path.clone(),
        identity_key_alias: Some(KeyAlias::new_unchecked("any-alias")),
        next_key_alias: None,
    };

    let ctx = build_test_context_with_provider(
        &missing_path,
        Arc::new(MemoryKeychainHandle),
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
    let key_alias = setup_test_identity(&registry_path);

    // Delete the packed registry ref to simulate registry corruption
    let repo = git2::Repository::open(&registry_path).unwrap();
    if let Ok(mut reference) = repo.find_reference("refs/auths/registry") {
        reference.delete().unwrap();
    }

    let config = RotationConfig {
        repo_path: registry_path.clone(),
        identity_key_alias: Some(key_alias),
        next_key_alias: None,
    };

    let ctx = build_test_context_with_provider(
        &registry_path,
        Arc::new(MemoryKeychainHandle),
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
        current_keys: vec!["D_testkey_placeholder".to_string()],
        next_commitment: vec!["hash_placeholder".to_string()],
        sequence: 0,
        last_event_said: Said::new_unchecked("E_prior_said_placeholder".to_string()),
        is_abandoned: false,
    };

    let kp1 = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let new_next_kp1 = Ed25519KeyPair::from_pkcs8(new_next_pkcs8.as_ref()).unwrap();
    let (_, bytes1) = compute_rotation_event(&state, &kp1, &new_next_kp1, None).unwrap();

    let kp2 = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let new_next_kp2 = Ed25519KeyPair::from_pkcs8(new_next_pkcs8.as_ref()).unwrap();
    let (_, bytes2) = compute_rotation_event(&state, &kp2, &new_next_kp2, None).unwrap();

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
    let next_kp = Ed25519KeyPair::from_pkcs8(next_pkcs8.as_ref()).unwrap();
    let new_next_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let new_next_kp = Ed25519KeyPair::from_pkcs8(new_next_pkcs8.as_ref()).unwrap();

    let prefix = Prefix::new_unchecked("test_prefix_partial_rotation".to_string());

    // Build a KeyState at sequence 0 so compute_rotation_event produces a seq-1 event
    let state = KeyState {
        prefix: prefix.clone(),
        current_keys: vec!["D_placeholder".to_string()],
        next_commitment: vec!["hash_placeholder".to_string()],
        sequence: 0,
        last_event_said: Said::new_unchecked("E_placeholder_said".to_string()),
        is_abandoned: false,
    };

    let (rot, _bytes) = compute_rotation_event(&state, &next_kp, &new_next_kp, None).unwrap();

    // Pre-seed the registry with a fake event at seq 0 so the seq-1 RotEvent is accepted
    let registry = Arc::new(FakeRegistryBackend::new());
    let dummy_rot = auths_id::keri::RotEvent {
        v: auths_id::keri::KERI_VERSION.to_string(),
        d: Said::new_unchecked("E_dummy".to_string()),
        i: prefix.clone(),
        s: "0".to_string(),
        p: Said::default(),
        kt: "1".to_string(),
        k: vec![],
        nt: "1".to_string(),
        n: vec![],
        bt: "0".to_string(),
        b: vec![],
        a: vec![],
        x: String::new(),
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
