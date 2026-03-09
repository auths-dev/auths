use std::path::PathBuf;
use std::sync::Arc;

use auths_core::signing::PrefilledPassphraseProvider;
use auths_core::storage::keychain::get_platform_keychain_with_config;
use auths_sdk::context::AuthsContext;
use auths_sdk::types::IdentityRotationConfig;
use auths_sdk::workflows::rotation::rotate_identity;
use auths_storage::git::{
    GitRegistryBackend, RegistryAttestationStorage, RegistryConfig, RegistryIdentityStorage,
};
use auths_verifier::clock::SystemClock;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;

use crate::identity::{make_keychain_config, resolve_key_alias, resolve_passphrase};

#[pyclass]
#[derive(Clone)]
pub struct PyIdentityRotationResult {
    #[pyo3(get)]
    pub controller_did: String,
    #[pyo3(get)]
    pub new_key_fingerprint: String,
    #[pyo3(get)]
    pub previous_key_fingerprint: String,
    #[pyo3(get)]
    pub sequence: u64,
}

#[pymethods]
impl PyIdentityRotationResult {
    fn __repr__(&self) -> String {
        format!(
            "RotationResult(did='{}...', seq={}, new_key='{}...')",
            &self.controller_did[..self.controller_did.len().min(25)],
            self.sequence,
            &self.new_key_fingerprint[..self.new_key_fingerprint.len().min(16)],
        )
    }
}

/// Rotate an identity's keys using the KERI pre-rotation ceremony.
///
/// Args:
/// * `repo_path`: Path to the auths repository.
/// * `identity_key_alias`: Current key alias (auto-detected if None).
/// * `next_key_alias`: New key alias (auto-generated if None).
/// * `passphrase`: Optional passphrase for the keychain.
///
/// Usage:
/// ```ignore
/// let result = rotate_identity_ffi(py, "~/.auths", None, None, None)?;
/// ```
#[pyfunction]
#[pyo3(signature = (repo_path, identity_key_alias=None, next_key_alias=None, passphrase=None))]
pub fn rotate_identity_ffi(
    py: Python<'_>,
    repo_path: &str,
    identity_key_alias: Option<&str>,
    next_key_alias: Option<&str>,
    passphrase: Option<String>,
) -> PyResult<PyIdentityRotationResult> {
    let passphrase_str = resolve_passphrase(passphrase);
    let env_config = make_keychain_config(&passphrase_str, repo_path);
    let provider = Arc::new(PrefilledPassphraseProvider::new(&passphrase_str));
    let clock = Arc::new(SystemClock);

    let repo = PathBuf::from(shellexpand::tilde(repo_path).as_ref());
    let config = RegistryConfig::single_tenant(&repo);
    let backend = Arc::new(
        GitRegistryBackend::open_existing(config)
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_REGISTRY_ERROR] Failed to open registry: {e}")))?,
    );

    let keychain = get_platform_keychain_with_config(&env_config)
        .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_KEYCHAIN_ERROR] Keychain error: {e}")))?;
    let keychain: Arc<dyn auths_core::storage::keychain::KeyStorage + Send + Sync> = Arc::from(keychain);

    let identity_storage = Arc::new(RegistryIdentityStorage::new(&repo));
    let attestation_storage = Arc::new(RegistryAttestationStorage::new(&repo));

    let alias = identity_key_alias
        .map(|a| resolve_key_alias(a, keychain.as_ref()))
        .transpose()?;

    let ctx = AuthsContext::builder()
        .registry(backend)
        .key_storage(keychain)
        .clock(clock.clone())
        .identity_storage(identity_storage)
        .attestation_sink(attestation_storage.clone())
        .attestation_source(attestation_storage)
        .passphrase_provider(provider)
        .build();

    let next_alias = next_key_alias
        .map(|a| {
            auths_core::storage::keychain::KeyAlias::new(a)
                .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_KEY_NOT_FOUND] Invalid next key alias: {e}")))
        })
        .transpose()?;

    let rotation_config = IdentityRotationConfig {
        repo_path: repo,
        identity_key_alias: alias,
        next_key_alias: next_alias,
    };

    py.allow_threads(|| {
        let result = rotate_identity(rotation_config, &ctx, clock.as_ref())
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_ROTATION_ERROR] Key rotation failed: {e}")))?;

        Ok(PyIdentityRotationResult {
            controller_did: result.controller_did.to_string(),
            new_key_fingerprint: result.new_key_fingerprint,
            previous_key_fingerprint: result.previous_key_fingerprint,
            sequence: result.sequence,
        })
    })
}
