use std::sync::Arc;

use auths_core::PrefilledPassphraseProvider;
use auths_core::signing::StorageSigner;
use auths_core::storage::keychain::KeyAlias;
use auths_core::storage::memory::{MEMORY_KEYCHAIN, MemoryKeychainHandle};
use auths_sdk::result::InitializeResult;
use auths_sdk::setup::initialize;
use auths_sdk::types::{
    CreateDeveloperIdentityConfig, GitSigningScope, IdentityConfig, IdentityConflictPolicy,
};

use crate::cases::helpers::build_test_context;

fn keychain_handle() -> MemoryKeychainHandle {
    MemoryKeychainHandle
}

fn dev_result(
    config: CreateDeveloperIdentityConfig,
    ctx: &auths_sdk::context::AuthsContext,
    signer: &dyn auths_core::signing::SecureSigner,
    provider: &dyn auths_core::signing::PassphraseProvider,
) -> auths_sdk::result::DeveloperIdentityResult {
    match initialize(
        IdentityConfig::Developer(config),
        ctx,
        Arc::new(MemoryKeychainHandle),
        signer,
        provider,
        None,
    )
    .unwrap()
    {
        InitializeResult::Developer(r) => r,
        _ => unreachable!(),
    }
}

#[test]
fn quick_setup_creates_identity_in_temp_dir() {
    MEMORY_KEYCHAIN.lock().unwrap().clear_all().ok();

    let tmp = tempfile::tempdir().unwrap();
    let registry_path = tmp.path().join(".auths");

    let config = CreateDeveloperIdentityConfig::builder(KeyAlias::new_unchecked("test-key"))
        .with_git_signing_scope(GitSigningScope::Skip)
        .build();

    let signer = StorageSigner::new(keychain_handle());
    let provider = PrefilledPassphraseProvider::new("Test-passphrase1!");
    let ctx = build_test_context(&registry_path, Arc::new(keychain_handle()));

    let result = dev_result(config, &ctx, &signer, &provider);

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

    let signer = StorageSigner::new(keychain_handle());
    let provider = PrefilledPassphraseProvider::new("Test-passphrase1!");

    let config = CreateDeveloperIdentityConfig::builder(KeyAlias::new_unchecked("test-key"))
        .with_git_signing_scope(GitSigningScope::Skip)
        .build();

    let ctx = build_test_context(&registry_path, Arc::new(keychain_handle()));
    let first = dev_result(config, &ctx, &signer, &provider);

    let config2 = CreateDeveloperIdentityConfig::builder(KeyAlias::new_unchecked("test-key"))
        .with_conflict_policy(IdentityConflictPolicy::ReuseExisting)
        .with_git_signing_scope(GitSigningScope::Skip)
        .build();

    let ctx2 = build_test_context(&registry_path, Arc::new(keychain_handle()));
    let second = dev_result(config2, &ctx2, &signer, &provider);

    assert_eq!(first.identity_did, second.identity_did);
}

#[test]
fn create_developer_identity_errors_on_existing_identity_by_default() {
    MEMORY_KEYCHAIN.lock().unwrap().clear_all().ok();

    let tmp = tempfile::tempdir().unwrap();
    let registry_path = tmp.path().join(".auths");

    let signer = StorageSigner::new(keychain_handle());
    let provider = PrefilledPassphraseProvider::new("Test-passphrase1!");

    let config = CreateDeveloperIdentityConfig::builder(KeyAlias::new_unchecked("test-key"))
        .with_git_signing_scope(GitSigningScope::Skip)
        .build();

    let ctx = build_test_context(&registry_path, Arc::new(keychain_handle()));
    let _first = dev_result(config, &ctx, &signer, &provider);

    let config2 = CreateDeveloperIdentityConfig::builder(KeyAlias::new_unchecked("test-key"))
        .with_git_signing_scope(GitSigningScope::Skip)
        .build();

    let ctx2 = build_test_context(&registry_path, Arc::new(keychain_handle()));
    let result = initialize(
        IdentityConfig::Developer(config2),
        &ctx2,
        Arc::new(keychain_handle()),
        &signer,
        &provider,
        None,
    );
    assert!(result.is_err());
}
