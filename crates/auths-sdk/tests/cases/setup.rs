use std::sync::Arc;

use auths_core::PrefilledPassphraseProvider;
use auths_core::signing::StorageSigner;
use auths_core::storage::keychain::KeyAlias;
use auths_core::storage::memory::{MEMORY_KEYCHAIN, MemoryKeychainHandle};
use auths_sdk::setup::create_developer_identity;
use auths_sdk::types::{CreateDeveloperIdentityConfig, GitSigningScope, IdentityConflictPolicy};

use crate::cases::helpers::build_test_context;

fn keychain_handle() -> MemoryKeychainHandle {
    MemoryKeychainHandle
}

#[test]
fn quick_setup_creates_identity_in_temp_dir() {
    MEMORY_KEYCHAIN.lock().unwrap().clear_all().ok();

    let tmp = tempfile::tempdir().unwrap();
    let registry_path = tmp.path().join(".auths");

    let config = CreateDeveloperIdentityConfig::builder(KeyAlias::new_unchecked("test-key"))
        .with_git_signing_scope(GitSigningScope::Skip)
        .build();

    let keychain = keychain_handle();
    let signer = StorageSigner::new(keychain_handle());
    let provider = PrefilledPassphraseProvider::new("Test-passphrase1!");
    let ctx = build_test_context(&registry_path, Arc::new(keychain_handle()));

    let result =
        create_developer_identity(config, &ctx, &keychain, &signer, &provider, None).unwrap();

    assert!(result.identity_did.starts_with("did:keri:"));
    assert!(result.device_did.starts_with("did:key:z"));
    assert_eq!(result.key_alias, "test-key");
    assert!(!result.git_signing_configured);
    assert!(result.registered.is_none());
}

#[test]
fn create_developer_identity_reuse_existing_identity() {
    MEMORY_KEYCHAIN.lock().unwrap().clear_all().ok();

    let tmp = tempfile::tempdir().unwrap();
    let registry_path = tmp.path().join(".auths");

    let keychain = keychain_handle();
    let signer = StorageSigner::new(keychain_handle());
    let provider = PrefilledPassphraseProvider::new("Test-passphrase1!");

    let config = CreateDeveloperIdentityConfig::builder(KeyAlias::new_unchecked("test-key"))
        .with_git_signing_scope(GitSigningScope::Skip)
        .build();

    let ctx = build_test_context(&registry_path, Arc::new(keychain_handle()));
    let first =
        create_developer_identity(config, &ctx, &keychain, &signer, &provider, None).unwrap();

    let config2 = CreateDeveloperIdentityConfig::builder(KeyAlias::new_unchecked("test-key"))
        .with_conflict_policy(IdentityConflictPolicy::ReuseExisting)
        .with_git_signing_scope(GitSigningScope::Skip)
        .build();

    let ctx2 = build_test_context(&registry_path, Arc::new(keychain_handle()));
    let second =
        create_developer_identity(config2, &ctx2, &keychain, &signer, &provider, None).unwrap();

    assert_eq!(first.identity_did, second.identity_did);
}

#[test]
fn create_developer_identity_errors_on_existing_identity_by_default() {
    MEMORY_KEYCHAIN.lock().unwrap().clear_all().ok();

    let tmp = tempfile::tempdir().unwrap();
    let registry_path = tmp.path().join(".auths");

    let keychain = keychain_handle();
    let signer = StorageSigner::new(keychain_handle());
    let provider = PrefilledPassphraseProvider::new("Test-passphrase1!");

    let config = CreateDeveloperIdentityConfig::builder(KeyAlias::new_unchecked("test-key"))
        .with_git_signing_scope(GitSigningScope::Skip)
        .build();

    let ctx = build_test_context(&registry_path, Arc::new(keychain_handle()));
    let _first =
        create_developer_identity(config, &ctx, &keychain, &signer, &provider, None).unwrap();

    let config2 = CreateDeveloperIdentityConfig::builder(KeyAlias::new_unchecked("test-key"))
        .with_git_signing_scope(GitSigningScope::Skip)
        .build();

    let ctx2 = build_test_context(&registry_path, Arc::new(keychain_handle()));
    let result = create_developer_identity(config2, &ctx2, &keychain, &signer, &provider, None);
    assert!(result.is_err());
}
