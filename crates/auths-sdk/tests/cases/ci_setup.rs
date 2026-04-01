use std::sync::Arc;

use auths_core::PrefilledPassphraseProvider;
use auths_core::signing::StorageSigner;
use auths_core::storage::memory::{MEMORY_KEYCHAIN, MemoryKeychainHandle};
use auths_sdk::domains::ci::types::{CiEnvironment, CiIdentityConfig};
use auths_sdk::domains::identity::service::initialize;
use auths_sdk::domains::identity::types::IdentityConfig;
use auths_sdk::domains::identity::types::InitializeResult;

use crate::cases::helpers::build_test_context;

#[test]
fn create_ci_identity_creates_ephemeral_identity() {
    MEMORY_KEYCHAIN.lock().unwrap().clear_all().ok();

    let tmp = tempfile::tempdir().unwrap();
    let registry_path = tmp.path().join(".auths-ci");

    let config = CiIdentityConfig {
        ci_environment: CiEnvironment::GitHubActions,
        registry_path: registry_path.clone(),
    };

    let keychain: Arc<dyn auths_core::storage::keychain::KeyStorage + Send + Sync> =
        Arc::new(MemoryKeychainHandle);
    let signer = StorageSigner::new(MemoryKeychainHandle);
    let provider = PrefilledPassphraseProvider::new("Ci-ephemeral-pass1!");
    let ctx = build_test_context(&registry_path, Arc::clone(&keychain));
    let result = match initialize(
        IdentityConfig::Ci(config),
        &ctx,
        keychain,
        &signer,
        &provider,
        None,
    )
    .unwrap()
    {
        InitializeResult::Ci(r) => r,
        _ => unreachable!(),
    };

    assert!(result.identity_did.starts_with("did:keri:"));
    assert!(result.device_did.starts_with("did:key:z"));
    assert!(!result.env_block.is_empty());
    assert!(
        result
            .env_block
            .iter()
            .any(|l| l.contains("AUTHS_KEYCHAIN_BACKEND"))
    );
    assert!(
        result
            .env_block
            .iter()
            .any(|l| l.contains("GitHub Actions"))
    );
}

#[test]
fn create_ci_identity_gitlab_env_block() {
    MEMORY_KEYCHAIN.lock().unwrap().clear_all().ok();

    let tmp = tempfile::tempdir().unwrap();
    let registry_path = tmp.path().join(".auths-ci");

    let config = CiIdentityConfig {
        ci_environment: CiEnvironment::GitLabCi,
        registry_path: registry_path.clone(),
    };

    let keychain: Arc<dyn auths_core::storage::keychain::KeyStorage + Send + Sync> =
        Arc::new(MemoryKeychainHandle);
    let signer = StorageSigner::new(MemoryKeychainHandle);
    let provider = PrefilledPassphraseProvider::new("Ci-ephemeral-pass1!");
    let ctx = build_test_context(&registry_path, Arc::clone(&keychain));
    let result = match initialize(
        IdentityConfig::Ci(config),
        &ctx,
        keychain,
        &signer,
        &provider,
        None,
    )
    .unwrap()
    {
        InitializeResult::Ci(r) => r,
        _ => unreachable!(),
    };

    assert!(result.env_block.iter().any(|l| l.contains("GitLab CI")));
}
