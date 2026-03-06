use std::path::PathBuf;
use std::sync::Arc;

use auths_core::config::{EnvironmentConfig, KeychainConfig};
use auths_core::signing::PrefilledPassphraseProvider;
use auths_core::storage::keychain::{get_platform_keychain_with_config, KeyAlias};
use auths_id::agent_identity::{provision_agent_identity, AgentProvisioningConfig, AgentStorageMode};
use auths_id::identity::initialize::initialize_registry_identity;
use auths_sdk::context::AuthsContext;
use auths_sdk::device::{link_device, revoke_device};
use auths_sdk::types::DeviceLinkConfig;
use auths_storage::git::GitRegistryBackend;
use auths_storage::git::RegistryAttestationStorage;
use auths_storage::git::RegistryConfig;
use auths_storage::git::RegistryIdentityStorage;
use auths_verifier::clock::SystemClock;
use auths_verifier::core::Capability;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;

pub(crate) fn resolve_passphrase(passphrase: Option<String>) -> String {
    passphrase.unwrap_or_else(|| std::env::var("AUTHS_PASSPHRASE").unwrap_or_default())
}

pub(crate) fn make_keychain_config(passphrase: &str) -> EnvironmentConfig {
    EnvironmentConfig {
        auths_home: None,
        keychain: KeychainConfig {
            backend: Some("file".to_string()),
            file_path: None,
            passphrase: Some(passphrase.to_string()),
        },
        ssh_agent_socket: None,
        #[cfg(feature = "keychain-pkcs11")]
        pkcs11: None,
    }
}

#[pyclass]
#[derive(Clone)]
pub struct AgentBundle {
    #[pyo3(get)]
    pub agent_did: String,
    #[pyo3(get)]
    pub key_alias: String,
    #[pyo3(get)]
    pub attestation_json: String,
    #[pyo3(get)]
    pub repo_path: Option<String>,
}

#[pymethods]
impl AgentBundle {
    fn __repr__(&self) -> String {
        format!("AgentBundle(agent_did='{}')", self.agent_did)
    }
}

/// Create a new identity in the registry.
///
/// Args:
/// * `key_alias`: Alias for the identity key in the keychain.
/// * `repo_path`: Path to the auths repository.
/// * `passphrase`: Optional passphrase for the keychain (reads AUTHS_PASSPHRASE if None).
///
/// Usage:
/// ```ignore
/// let (did, alias) = create_identity(py, "my-identity", "~/.auths", None)?;
/// ```
#[pyfunction]
pub fn create_identity(
    py: Python<'_>,
    key_alias: &str,
    repo_path: &str,
    passphrase: Option<String>,
) -> PyResult<(String, String)> {
    let passphrase_str = resolve_passphrase(passphrase);
    let env_config = make_keychain_config(&passphrase_str);
    let alias = KeyAlias::new(key_alias)
        .map_err(|e| PyRuntimeError::new_err(format!("Invalid key alias: {e}")))?;
    let provider = PrefilledPassphraseProvider::new(&passphrase_str);

    let repo = PathBuf::from(shellexpand::tilde(repo_path).as_ref());
    let config = RegistryConfig::single_tenant(&repo);
    let backend = Arc::new(
        GitRegistryBackend::open_existing(config)
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to open registry: {e}")))?,
    );

    let keychain = get_platform_keychain_with_config(&env_config)
        .map_err(|e| PyRuntimeError::new_err(format!("Keychain error: {e}")))?;

    py.allow_threads(|| {
        let (identity_did, result_alias) =
            initialize_registry_identity(backend, &alias, &provider, keychain.as_ref(), None)
                .map_err(|e| PyRuntimeError::new_err(format!("Identity creation failed: {e}")))?;
        Ok((identity_did.to_string(), result_alias.to_string()))
    })
}

/// Provision an agent identity.
///
/// Args:
/// * `agent_name`: Human-readable agent name.
/// * `capabilities`: Capabilities to grant.
/// * `parent_repo_path`: Path to the parent identity's repository.
/// * `passphrase`: Optional passphrase for the keychain.
/// * `expires_in_secs`: Optional expiry in seconds.
///
/// Usage:
/// ```ignore
/// let bundle = provision_agent(py, "ci-bot", vec!["sign".into()], "~/.auths", None, None)?;
/// ```
#[pyfunction]
pub fn provision_agent(
    py: Python<'_>,
    agent_name: &str,
    capabilities: Vec<String>,
    parent_repo_path: &str,
    passphrase: Option<String>,
    expires_in_secs: Option<u64>,
) -> PyResult<AgentBundle> {
    let passphrase_str = resolve_passphrase(passphrase);
    let env_config = make_keychain_config(&passphrase_str);
    let now = chrono::Utc::now();

    let repo = PathBuf::from(shellexpand::tilde(parent_repo_path).as_ref());
    let config = RegistryConfig::single_tenant(&repo);
    let backend = Arc::new(
        GitRegistryBackend::open_existing(config)
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to open registry: {e}")))?,
    );

    let keychain = get_platform_keychain_with_config(&env_config)
        .map_err(|e| PyRuntimeError::new_err(format!("Keychain error: {e}")))?;

    let provider = PrefilledPassphraseProvider::new(&passphrase_str);

    let agent_config = AgentProvisioningConfig {
        agent_name: agent_name.to_string(),
        capabilities,
        expires_in_secs,
        delegated_by: None,
        storage_mode: AgentStorageMode::Persistent { repo_path: None },
    };

    py.allow_threads(|| {
        let bundle =
            provision_agent_identity(now, backend, agent_config, &provider, keychain)
                .map_err(|e| PyRuntimeError::new_err(format!("Agent provisioning failed: {e}")))?;

        let attestation_json = serde_json::to_string(&bundle.attestation)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization failed: {e}")))?;

        Ok(AgentBundle {
            agent_did: bundle.agent_did.to_string(),
            key_alias: bundle.key_alias.to_string(),
            attestation_json,
            repo_path: bundle.repo_path.map(|p| p.to_string_lossy().to_string()),
        })
    })
}

/// Link a device to an identity.
///
/// Args:
/// * `identity_key_alias`: Alias of the identity key in the keychain.
/// * `capabilities`: Capabilities to grant to the device.
/// * `passphrase`: Optional passphrase for the keychain.
/// * `repo_path`: Path to the auths repository.
/// * `expires_in_days`: Optional expiration period in days.
///
/// Usage:
/// ```ignore
/// let (device_did, att_id) = link_device_ffi(py, "my-id", vec!["sign".into()], None, "~/.auths", None)?;
/// ```
#[pyfunction]
#[pyo3(signature = (identity_key_alias, capabilities, repo_path, passphrase=None, expires_in_days=None))]
pub fn link_device_to_identity(
    py: Python<'_>,
    identity_key_alias: &str,
    capabilities: Vec<String>,
    repo_path: &str,
    passphrase: Option<String>,
    expires_in_days: Option<u32>,
) -> PyResult<(String, String)> {
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

    let parsed_caps: Vec<Capability> = capabilities
        .iter()
        .map(|c| Capability::parse(c).map_err(|e| PyRuntimeError::new_err(format!("Invalid capability '{c}': {e}"))))
        .collect::<PyResult<Vec<_>>>()?;

    let link_config = DeviceLinkConfig {
        identity_key_alias: alias,
        device_key_alias: None,
        device_did: None,
        capabilities: parsed_caps,
        expires_in_days,
        note: None,
        payload: None,
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
        let result = link_device(link_config, &ctx, clock.as_ref())
            .map_err(|e| PyRuntimeError::new_err(format!("Device linking failed: {e}")))?;
        Ok((result.device_did.to_string(), result.attestation_id.to_string()))
    })
}

/// Revoke a device from an identity.
///
/// Args:
/// * `device_did`: The DID of the device to revoke.
/// * `identity_key_alias`: Alias of the identity key in the keychain.
/// * `passphrase`: Optional passphrase for the keychain.
/// * `repo_path`: Path to the auths repository.
/// * `note`: Optional revocation note.
///
/// Usage:
/// ```ignore
/// revoke_device_ffi(py, "did:key:z6Mk...", "my-id", None, "~/.auths", None)?;
/// ```
#[pyfunction]
#[pyo3(signature = (device_did, identity_key_alias, repo_path, passphrase=None, note=None))]
pub fn revoke_device_from_identity(
    py: Python<'_>,
    device_did: &str,
    identity_key_alias: &str,
    repo_path: &str,
    passphrase: Option<String>,
    note: Option<String>,
) -> PyResult<()> {
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
        revoke_device(device_did, &alias, &ctx, note, clock.as_ref())
            .map_err(|e| PyRuntimeError::new_err(format!("Device revocation failed: {e}")))?;
        Ok(())
    })
}
