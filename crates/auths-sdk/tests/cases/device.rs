use std::sync::Arc;

use auths_core::PrefilledPassphraseProvider;
use auths_core::ports::clock::SystemClock;
use auths_core::signing::{PassphraseProvider, StorageSigner};
use auths_core::storage::keychain::KeyAlias;
use auths_core::testing::IsolatedKeychainHandle;
use auths_sdk::domains::device::error::DeviceExtensionError;
use auths_sdk::domains::device::service::{extend_device, link_device};
use auths_sdk::domains::device::types::{DeviceExtensionConfig, DeviceLinkConfig};
use auths_sdk::domains::identity::service::initialize;
use auths_sdk::domains::identity::types::InitializeResult;
use auths_sdk::domains::identity::types::{CreateDeveloperIdentityConfig, IdentityConfig};
use auths_sdk::domains::signing::types::GitSigningScope;

use crate::cases::helpers::{build_test_context, build_test_context_with_provider};

fn setup_test_identity(registry_path: &std::path::Path) -> (KeyAlias, IsolatedKeychainHandle) {
    let keychain = IsolatedKeychainHandle::new();
    let signer = StorageSigner::new(keychain.clone());
    let provider = PrefilledPassphraseProvider::new("Test-passphrase1!");
    let config = CreateDeveloperIdentityConfig::builder(KeyAlias::new_unchecked("test-key"))
        .with_git_signing_scope(GitSigningScope::Skip)
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

fn link_test_device(
    registry_path: &std::path::Path,
    key_alias: &KeyAlias,
    keychain: &IsolatedKeychainHandle,
) -> String {
    let signer = StorageSigner::new(keychain.clone());
    let provider = PrefilledPassphraseProvider::new("Test-passphrase1!");
    let config = CreateDeveloperIdentityConfig::builder(KeyAlias::new_unchecked("device-key"))
        .with_git_signing_scope(GitSigningScope::Skip)
        .with_conflict_policy(auths_sdk::domains::identity::types::IdentityConflictPolicy::ForceNew)
        .build();
    let ctx = build_test_context(registry_path, Arc::new(keychain.clone()));
    initialize(
        IdentityConfig::Developer(config),
        &ctx,
        Arc::new(keychain.clone()),
        &signer,
        &provider,
        None,
    )
    .unwrap();

    let link_config = DeviceLinkConfig {
        identity_key_alias: key_alias.clone(),
        device_key_alias: Some(KeyAlias::new_unchecked("device-key")),
        device_did: None,
        capabilities: vec![],
        expires_in: Some(2_592_000),
        note: Some("test device".into()),
        payload: None,
    };

    let link_ctx = build_test_context_with_provider(
        registry_path,
        Arc::new(keychain.clone()),
        Some(
            Arc::new(PrefilledPassphraseProvider::new("Test-passphrase1!"))
                as Arc<dyn PassphraseProvider + Send + Sync>,
        ),
    );
    let link_result = link_device(link_config, &link_ctx, &SystemClock).unwrap();
    link_result.device_did.to_string()
}

#[test]
fn extend_device_updates_expiry() {
    let tmp = tempfile::tempdir().unwrap();
    let registry_path = tmp.path().join(".auths");

    let (key_alias, keychain) = setup_test_identity(&registry_path);
    let device_did = link_test_device(&registry_path, &key_alias, &keychain);

    let ctx = build_test_context_with_provider(
        &registry_path,
        Arc::new(keychain.clone()),
        Some(
            Arc::new(PrefilledPassphraseProvider::new("Test-passphrase1!"))
                as Arc<dyn PassphraseProvider + Send + Sync>,
        ),
    );
    let config = DeviceExtensionConfig {
        repo_path: registry_path,
        device_did: auths_verifier::types::DeviceDID::new_unchecked(device_did.clone()),
        expires_in: 31_536_000,
        identity_key_alias: key_alias.clone(),
        device_key_alias: Some(KeyAlias::new_unchecked("device-key")),
    };

    let result = extend_device(config, &ctx, &SystemClock).unwrap();

    assert_eq!(result.device_did.to_string(), device_did);
    let now = chrono::Utc::now();
    let diff = result.new_expires_at - now;
    assert!(
        diff.num_days() >= 364,
        "Expected ~365 days, got {}",
        diff.num_days()
    );
}

#[test]
fn extend_device_nonexistent_device_returns_error() {
    let tmp = tempfile::tempdir().unwrap();
    let registry_path = tmp.path().join(".auths");

    let (key_alias, keychain) = setup_test_identity(&registry_path);

    let ctx = build_test_context_with_provider(
        &registry_path,
        Arc::new(keychain.clone()),
        Some(
            Arc::new(PrefilledPassphraseProvider::new("Test-passphrase1!"))
                as Arc<dyn PassphraseProvider + Send + Sync>,
        ),
    );
    let config = DeviceExtensionConfig {
        repo_path: registry_path,
        device_did: auths_verifier::types::DeviceDID::new_unchecked("did:key:zDoesNotExist"),
        expires_in: 2_592_000,
        identity_key_alias: key_alias,
        device_key_alias: Some(KeyAlias::new_unchecked("device-key")),
    };

    let result = extend_device(config, &ctx, &SystemClock);

    assert!(
        matches!(result, Err(DeviceExtensionError::NoAttestationFound { .. })),
        "Expected NoAttestationFound, got: {:?}",
        result.unwrap_err()
    );
}
