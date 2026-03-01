use std::path::Path;
use std::sync::Arc;

use auths_core::PrefilledPassphraseProvider;
use auths_core::ports::clock::SystemClock;
use auths_core::signing::{PassphraseProvider, StorageSigner};
use auths_core::storage::keychain::{KeyAlias, KeyStorage};
use auths_core::storage::memory::{MEMORY_KEYCHAIN, MemoryKeychainHandle};
use auths_id::attestation::export::AttestationSink;
use auths_id::ports::registry::RegistryBackend;
use auths_id::storage::attestation::AttestationSource;
use auths_id::storage::identity::IdentityStorage;
use auths_sdk::context::AuthsContext;
use auths_sdk::setup::setup_developer;
use auths_sdk::types::{DeveloperSetupConfig, GitSigningScope};
use auths_storage::git::{
    GitRegistryBackend, RegistryAttestationStorage, RegistryConfig, RegistryIdentityStorage,
};

/// Build an [`AuthsContext`] backed by concrete git storage at `registry_path`.
///
/// Initializes the git repository if it does not already exist.
pub fn build_test_context(
    registry_path: &Path,
    key_storage: Arc<dyn KeyStorage + Send + Sync>,
) -> AuthsContext {
    build_test_context_with_provider(registry_path, key_storage, None)
}

/// Build an [`AuthsContext`] backed by concrete git storage, with an optional passphrase provider.
///
/// Use this variant for tests that exercise signing operations requiring key decryption.
pub fn build_test_context_with_provider(
    registry_path: &Path,
    key_storage: Arc<dyn KeyStorage + Send + Sync>,
    passphrase_provider: impl Into<Option<Arc<dyn PassphraseProvider + Send + Sync>>>,
) -> AuthsContext {
    if !registry_path.exists() {
        std::fs::create_dir_all(registry_path).expect("create registry dir");
    }
    if git2::Repository::open(registry_path).is_err() {
        git2::Repository::init(registry_path).expect("init git repo");
    }

    let backend: Arc<dyn RegistryBackend + Send + Sync> = Arc::new(
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(registry_path)),
    );
    let identity_storage: Arc<dyn IdentityStorage + Send + Sync> =
        Arc::new(RegistryIdentityStorage::new(registry_path.to_path_buf()));
    let attestation_store = Arc::new(RegistryAttestationStorage::new(registry_path));
    let attestation_sink: Arc<dyn AttestationSink + Send + Sync> =
        Arc::clone(&attestation_store) as Arc<dyn AttestationSink + Send + Sync>;
    let attestation_source: Arc<dyn AttestationSource + Send + Sync> =
        attestation_store as Arc<dyn AttestationSource + Send + Sync>;

    let mut builder = AuthsContext::builder()
        .registry(backend)
        .key_storage(key_storage)
        .clock(Arc::new(SystemClock))
        .identity_storage(identity_storage)
        .attestation_sink(attestation_sink)
        .attestation_source(attestation_source);

    if let Some(pp) = passphrase_provider.into() {
        builder = builder.passphrase_provider(pp);
    }

    builder.build()
}

/// Build an [`AuthsContext`] over a fresh empty git repository with no identity stored.
///
/// Returns `(TempDir, AuthsContext)`. The `TempDir` must be kept alive for the duration
/// of the test. Useful for testing "identity not found" error paths.
pub fn build_empty_test_context() -> (tempfile::TempDir, AuthsContext) {
    let tmp = tempfile::TempDir::new().expect("create temp dir");
    let registry_path = tmp.path().join(".auths-empty");
    let ctx =
        build_test_context_with_provider(&registry_path, Arc::new(MemoryKeychainHandle), None);
    (tmp, ctx)
}

/// Create a test identity and return the `(TempDir, key_alias, AuthsContext)` tuple.
///
/// The `TempDir` must be kept alive for the duration of the test. The context is
/// pre-configured with a `PrefilledPassphraseProvider` so signing operations work
/// without prompting.
pub fn setup_signed_artifact_context() -> (tempfile::TempDir, KeyAlias, AuthsContext) {
    MEMORY_KEYCHAIN.lock().unwrap().clear_all().ok();
    let tmp = tempfile::TempDir::new().expect("create temp dir");
    let registry_path = tmp.path().join(".auths");

    let keychain = MemoryKeychainHandle;
    let signer = StorageSigner::new(MemoryKeychainHandle);
    let provider = PrefilledPassphraseProvider::new("Test-passphrase1!");
    let config = DeveloperSetupConfig::builder(KeyAlias::new_unchecked("test-key"))
        .with_git_signing_scope(GitSigningScope::Skip)
        .build();
    let setup_ctx = build_test_context(&registry_path, Arc::new(MemoryKeychainHandle));
    let result = setup_developer(config, &setup_ctx, &keychain, &signer, &provider, None)
        .expect("setup_developer failed");

    let ctx = build_test_context_with_provider(
        &registry_path,
        Arc::new(MemoryKeychainHandle),
        Some(
            Arc::new(PrefilledPassphraseProvider::new("Test-passphrase1!"))
                as Arc<dyn PassphraseProvider + Send + Sync>,
        ),
    );

    (tmp, result.key_alias, ctx)
}
