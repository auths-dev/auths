use std::sync::Arc;

use auths_core::PrefilledPassphraseProvider;
use auths_core::ports::clock::SystemClock;
use auths_core::signing::{PassphraseProvider, StorageSigner};
use auths_core::storage::keychain::KeyAlias;
use auths_core::storage::memory::{MEMORY_KEYCHAIN, MemoryKeychainHandle};
use auths_sdk::device::{extend_device_authorization, link_device};
use auths_sdk::error::DeviceExtensionError;
use auths_sdk::setup::setup_developer;
use auths_sdk::types::{
    DeveloperSetupConfig, DeviceExtensionConfig, DeviceLinkConfig, GitSigningScope,
};

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

fn link_test_device(registry_path: &std::path::Path, key_alias: &KeyAlias) -> String {
    // Use a separate registry dir so device keypair generation does not
    // conflict with the existing identity already stored in registry_path.
    let device_tmp = tempfile::tempdir().unwrap();
    let _device_registry = device_tmp.path().join(".auths-device");

    let keychain = MemoryKeychainHandle;
    let signer = StorageSigner::new(MemoryKeychainHandle);
    let provider = PrefilledPassphraseProvider::new("Test-passphrase1!");
    let config = DeveloperSetupConfig::builder(KeyAlias::new_unchecked("device-key"))
        .with_git_signing_scope(GitSigningScope::Skip)
        .build();
    let ctx = build_test_context(registry_path, Arc::new(MemoryKeychainHandle));
    let _device_result =
        setup_developer(config, &ctx, &keychain, &signer, &provider, None).unwrap();

    let link_config = DeviceLinkConfig {
        identity_key_alias: key_alias.clone(),
        device_key_alias: Some(KeyAlias::new_unchecked("device-key")),
        device_did: None,
        capabilities: vec![],
        expires_in_days: Some(30),
        note: Some("test device".into()),
        payload: None,
    };

    let link_ctx = build_test_context_with_provider(
        registry_path,
        Arc::new(MemoryKeychainHandle),
        Some(
            Arc::new(PrefilledPassphraseProvider::new("Test-passphrase1!"))
                as Arc<dyn PassphraseProvider + Send + Sync>,
        ),
    );
    let link_result = link_device(link_config, &link_ctx, &SystemClock).unwrap();
    link_result.device_did
}

#[test]
fn extend_device_authorization_updates_expiry() {
    let tmp = tempfile::tempdir().unwrap();
    let registry_path = tmp.path().join(".auths");

    let key_alias = setup_test_identity(&registry_path);
    let device_did = link_test_device(&registry_path, &key_alias);

    let ctx = build_test_context_with_provider(
        &registry_path,
        Arc::new(MemoryKeychainHandle),
        Some(
            Arc::new(PrefilledPassphraseProvider::new("Test-passphrase1!"))
                as Arc<dyn PassphraseProvider + Send + Sync>,
        ),
    );
    let config = DeviceExtensionConfig {
        repo_path: registry_path,
        device_did: device_did.clone(),
        days: 365,
        identity_key_alias: key_alias.clone(),
        device_key_alias: KeyAlias::new_unchecked("device-key"),
    };

    let result = extend_device_authorization(config, &ctx, &SystemClock).unwrap();

    assert_eq!(result.device_did, device_did);
    let now = chrono::Utc::now();
    let diff = result.new_expires_at - now;
    assert!(
        diff.num_days() >= 364,
        "Expected ~365 days, got {}",
        diff.num_days()
    );
}

#[test]
fn extend_device_authorization_nonexistent_device_returns_error() {
    let tmp = tempfile::tempdir().unwrap();
    let registry_path = tmp.path().join(".auths");

    let key_alias = setup_test_identity(&registry_path);

    let ctx = build_test_context_with_provider(
        &registry_path,
        Arc::new(MemoryKeychainHandle),
        Some(
            Arc::new(PrefilledPassphraseProvider::new("Test-passphrase1!"))
                as Arc<dyn PassphraseProvider + Send + Sync>,
        ),
    );
    let config = DeviceExtensionConfig {
        repo_path: registry_path,
        device_did: "did:key:zDoesNotExist".to_string(),
        days: 30,
        identity_key_alias: key_alias,
        device_key_alias: KeyAlias::new_unchecked("device-key"),
    };

    let result = extend_device_authorization(config, &ctx, &SystemClock);

    assert!(
        matches!(result, Err(DeviceExtensionError::NoAttestationFound { .. })),
        "Expected NoAttestationFound, got: {:?}",
        result.unwrap_err()
    );
}
