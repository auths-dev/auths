use std::sync::Arc;

use auths_core::storage::memory::{MEMORY_KEYCHAIN, MemoryKeychainHandle};
use auths_sdk::setup::create_ci_identity;
use auths_sdk::types::{CiEnvironment, CreateCiIdentityConfig};

use crate::cases::helpers::build_test_context;

#[test]
fn create_ci_identity_creates_ephemeral_identity() {
    MEMORY_KEYCHAIN.lock().unwrap().clear_all().ok();

    let tmp = tempfile::tempdir().unwrap();
    let registry_path = tmp.path().join(".auths-ci");

    let config = CreateCiIdentityConfig {
        ci_environment: CiEnvironment::GitHubActions,
        passphrase: "Ci-ephemeral-pass1!".into(),
        registry_path: registry_path.clone(),
        keychain: Box::new(MemoryKeychainHandle),
    };

    let ctx = build_test_context(&registry_path, Arc::new(MemoryKeychainHandle));
    let result = create_ci_identity(config, &ctx).unwrap();

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

    let config = CreateCiIdentityConfig {
        ci_environment: CiEnvironment::GitLabCi,
        passphrase: "Ci-ephemeral-pass1!".into(),
        registry_path: registry_path.clone(),
        keychain: Box::new(MemoryKeychainHandle),
    };

    let ctx = build_test_context(&registry_path, Arc::new(MemoryKeychainHandle));
    let result = create_ci_identity(config, &ctx).unwrap();

    assert!(result.env_block.iter().any(|l| l.contains("GitLab CI")));
}
