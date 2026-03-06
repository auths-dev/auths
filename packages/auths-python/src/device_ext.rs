use std::path::PathBuf;
use std::sync::Arc;

use auths_core::signing::PrefilledPassphraseProvider;
use auths_core::storage::keychain::{get_platform_keychain_with_config, KeyAlias};
use auths_sdk::context::AuthsContext;
use auths_sdk::device::extend_device_authorization;
use auths_sdk::types::DeviceExtensionConfig;
use auths_storage::git::{
    GitRegistryBackend, RegistryAttestationStorage, RegistryConfig, RegistryIdentityStorage,
};
use auths_verifier::clock::SystemClock;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;

use crate::identity::{make_keychain_config, resolve_passphrase};

#[pyclass]
#[derive(Clone)]
pub struct PyDeviceExtension {
    #[pyo3(get)]
    pub device_did: String,
    #[pyo3(get)]
    pub new_expires_at: String,
    #[pyo3(get)]
    pub previous_expires_at: Option<String>,
}

#[pymethods]
impl PyDeviceExtension {
    fn __repr__(&self) -> String {
        format!(
            "DeviceExtension(device='{}...', expires='{}')",
            &self.device_did[..self.device_did.len().min(20)],
            self.new_expires_at,
        )
    }
}

/// Extend a device's authorization expiry.
///
/// Args:
/// * `device_did`: The DID of the device to extend.
/// * `identity_key_alias`: Keychain alias for the identity key.
/// * `days`: Number of days to extend from now.
/// * `repo_path`: Path to the auths repository.
/// * `passphrase`: Optional passphrase for the keychain.
///
/// Usage:
/// ```ignore
/// let result = extend_device_authorization_ffi(py, "did:key:...", "main", 90, "~/.auths", None)?;
/// ```
#[pyfunction]
#[pyo3(signature = (device_did, identity_key_alias, days, repo_path, passphrase=None))]
pub fn extend_device_authorization_ffi(
    py: Python<'_>,
    device_did: &str,
    identity_key_alias: &str,
    days: u32,
    repo_path: &str,
    passphrase: Option<String>,
) -> PyResult<PyDeviceExtension> {
    if days == 0 {
        return Err(PyValueError::new_err("days must be positive (> 0)"));
    }

    let passphrase_str = resolve_passphrase(passphrase);
    let env_config = make_keychain_config(&passphrase_str);
    let provider = Arc::new(PrefilledPassphraseProvider::new(&passphrase_str));
    let clock = Arc::new(SystemClock);

    let repo = PathBuf::from(shellexpand::tilde(repo_path).as_ref());
    let config = RegistryConfig::single_tenant(&repo);
    let backend = Arc::new(
        GitRegistryBackend::open_existing(config)
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to open registry: {e}")))?,
    );

    let keychain = get_platform_keychain_with_config(&env_config)
        .map_err(|e| PyRuntimeError::new_err(format!("Keychain error: {e}")))?;
    let keychain = Arc::from(keychain);

    let identity_storage = Arc::new(RegistryIdentityStorage::new(&repo));
    let attestation_storage = Arc::new(RegistryAttestationStorage::new(&repo));

    let alias = KeyAlias::new(identity_key_alias)
        .map_err(|e| PyRuntimeError::new_err(format!("Invalid key alias: {e}")))?;

    let ext_config = DeviceExtensionConfig {
        repo_path: repo,
        device_did: device_did.to_string(),
        days,
        identity_key_alias: alias,
        device_key_alias: None,
    };

    let ctx = AuthsContext::builder()
        .registry(backend)
        .key_storage(keychain)
        .clock(clock.clone())
        .identity_storage(identity_storage)
        .attestation_sink(attestation_storage.clone())
        .attestation_source(attestation_storage)
        .passphrase_provider(provider)
        .build()
        .map_err(|e| PyRuntimeError::new_err(format!("Context build failed: {e}")))?;

    py.allow_threads(|| {
        let result = extend_device_authorization(ext_config, &ctx, clock.as_ref())
            .map_err(|e| PyRuntimeError::new_err(format!("Device extension failed: {e}")))?;

        Ok(PyDeviceExtension {
            device_did: result.device_did.to_string(),
            new_expires_at: result.new_expires_at.to_rfc3339(),
            previous_expires_at: result.previous_expires_at.map(|t| t.to_rfc3339()),
        })
    })
}
