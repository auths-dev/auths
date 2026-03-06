use std::path::PathBuf;
use std::sync::Arc;

use auths_core::config::{EnvironmentConfig, KeychainConfig};
use auths_core::crypto::signer::encrypt_keypair;
use auths_core::signing::PrefilledPassphraseProvider;
use auths_core::storage::keychain::{get_platform_keychain_with_config, IdentityDID, KeyAlias, KeyStorage};
use auths_id::identity::helpers::encode_seed_as_pkcs8;
use auths_id::identity::helpers::extract_seed_bytes;
use auths_id::identity::initialize::initialize_registry_identity;
use auths_id::storage::attestation::AttestationSource;
use auths_sdk::context::AuthsContext;
use auths_sdk::device::{link_device, revoke_device};
use auths_sdk::types::DeviceLinkConfig;
use auths_storage::git::GitRegistryBackend;
use auths_storage::git::RegistryAttestationStorage;
use auths_storage::git::RegistryConfig;
use auths_storage::git::RegistryIdentityStorage;
use auths_verifier::clock::SystemClock;
use auths_verifier::core::Capability;
use auths_verifier::types::DeviceDID;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

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

/// Resolve a DID-or-alias string to a KeyAlias.
///
/// If the input starts with "did:", look up the first non-rotation alias
/// for that identity in the keychain. Otherwise treat it as a direct alias.
pub(crate) fn resolve_key_alias(
    identity_ref: &str,
    keychain: &(dyn KeyStorage + Send + Sync),
) -> PyResult<KeyAlias> {
    if identity_ref.starts_with("did:") {
        let did = IdentityDID::new_unchecked(identity_ref.to_string());
        let aliases = keychain
            .list_aliases_for_identity(&did)
            .map_err(|e| PyRuntimeError::new_err(format!("Key lookup failed: {e}")))?;
        aliases
            .into_iter()
            .find(|a| !a.as_str().contains("--next-"))
            .ok_or_else(|| {
                PyRuntimeError::new_err(format!(
                    "No key found for identity '{identity_ref}'"
                ))
            })
    } else {
        KeyAlias::new(identity_ref)
            .map_err(|e| PyRuntimeError::new_err(format!("Invalid key alias: {e}")))
    }
}

#[pyclass]
#[derive(Clone)]
pub struct DelegatedAgentBundle {
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
impl DelegatedAgentBundle {
    fn __repr__(&self) -> String {
        format!("DelegatedAgentBundle(agent_did='{}')", self.agent_did)
    }
}

#[pyclass]
#[derive(Clone)]
pub struct AgentIdentityBundle {
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
impl AgentIdentityBundle {
    fn __repr__(&self) -> String {
        format!("AgentIdentityBundle(agent_did='{}')", self.agent_did)
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
    let backend = GitRegistryBackend::from_config_unchecked(config);
    backend
        .init_if_needed()
        .map_err(|e| PyRuntimeError::new_err(format!("Failed to initialize registry: {e}")))?;
    let backend = Arc::new(backend);

    let keychain = get_platform_keychain_with_config(&env_config)
        .map_err(|e| PyRuntimeError::new_err(format!("Keychain error: {e}")))?;

    py.allow_threads(|| {
        let (identity_did, result_alias) =
            initialize_registry_identity(backend, &alias, &provider, keychain.as_ref(), None)
                .map_err(|e| PyRuntimeError::new_err(format!("Identity creation failed: {e}")))?;
        Ok((identity_did.to_string(), result_alias.to_string()))
    })
}

/// Create a standalone agent identity with its own KERI identity (did:keri:).
///
/// Args:
/// * `agent_name`: Human-readable agent name.
/// * `capabilities`: Capabilities to grant.
/// * `repo_path`: Path to the auths repository.
/// * `passphrase`: Optional passphrase for the keychain.
///
/// Usage:
/// ```ignore
/// let bundle = create_agent_identity(py, "ci-bot", vec!["sign".into()], "~/.auths", None)?;
/// ```
#[pyfunction]
#[pyo3(signature = (agent_name, capabilities, repo_path, passphrase=None))]
pub fn create_agent_identity(
    py: Python<'_>,
    agent_name: &str,
    capabilities: Vec<String>,
    repo_path: &str,
    passphrase: Option<String>,
) -> PyResult<AgentIdentityBundle> {
    let passphrase_str = resolve_passphrase(passphrase);
    let env_config = make_keychain_config(&passphrase_str);
    let alias = KeyAlias::new_unchecked(format!("{}-agent", agent_name));
    let provider = PrefilledPassphraseProvider::new(&passphrase_str);

    let repo = PathBuf::from(shellexpand::tilde(repo_path).as_ref());
    let config = RegistryConfig::single_tenant(&repo);
    let backend = GitRegistryBackend::from_config_unchecked(config);
    backend
        .init_if_needed()
        .map_err(|e| PyRuntimeError::new_err(format!("Failed to initialize registry: {e}")))?;
    let backend = Arc::new(backend);

    let keychain = get_platform_keychain_with_config(&env_config)
        .map_err(|e| PyRuntimeError::new_err(format!("Keychain error: {e}")))?;

    // Validate capabilities
    let _parsed_caps: Vec<Capability> = capabilities
        .iter()
        .map(|c| {
            Capability::parse(c)
                .map_err(|e| PyRuntimeError::new_err(format!("Invalid capability '{c}': {e}")))
        })
        .collect::<PyResult<Vec<_>>>()?;

    py.allow_threads(|| {
        let (identity_did, result_alias) =
            initialize_registry_identity(backend, &alias, &provider, keychain.as_ref(), None)
                .map_err(|e| PyRuntimeError::new_err(format!("Agent identity creation failed: {e}")))?;

        Ok(AgentIdentityBundle {
            agent_did: identity_did.to_string(),
            key_alias: result_alias.to_string(),
            attestation_json: String::new(),
            repo_path: Some(repo.to_string_lossy().to_string()),
        })
    })
}

/// Delegate an agent under a parent identity using device-link delegation.
///
/// Generates a new Ed25519 keypair for the agent, stores it in the keychain,
/// and creates a parent-signed attestation delegating capabilities to the agent.
/// Returns a `did:key:` identifier for the delegated agent.
///
/// Args:
/// * `agent_name`: Human-readable agent name.
/// * `capabilities`: Capabilities to grant.
/// * `parent_repo_path`: Path to the parent identity's repository.
/// * `passphrase`: Optional passphrase for the keychain.
/// * `expires_in_days`: Optional expiry in days.
/// * `identity_did`: DID of the parent identity (did:keri:...).
///
/// Usage:
/// ```ignore
/// let bundle = delegate_agent(py, "ci-bot", vec!["sign".into()], "~/.auths", None, None, Some("did:keri:E..."))?;
/// ```
#[pyfunction]
#[pyo3(signature = (agent_name, capabilities, parent_repo_path, passphrase=None, expires_in_days=None, identity_did=None))]
pub fn delegate_agent(
    py: Python<'_>,
    agent_name: &str,
    capabilities: Vec<String>,
    parent_repo_path: &str,
    passphrase: Option<String>,
    expires_in_days: Option<u32>,
    identity_did: Option<String>,
) -> PyResult<DelegatedAgentBundle> {
    let passphrase_str = resolve_passphrase(passphrase);
    let env_config = make_keychain_config(&passphrase_str);
    let provider = Arc::new(PrefilledPassphraseProvider::new(&passphrase_str));
    let clock = Arc::new(SystemClock);

    let repo = PathBuf::from(shellexpand::tilde(parent_repo_path).as_ref());
    let config = RegistryConfig::single_tenant(&repo);
    let backend = Arc::new(
        GitRegistryBackend::open_existing(config)
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to open registry: {e}")))?,
    );

    let keychain = get_platform_keychain_with_config(&env_config)
        .map_err(|e| PyRuntimeError::new_err(format!("Keychain error: {e}")))?;

    // Resolve parent identity key alias
    let parent_alias = if let Some(ref did) = identity_did {
        resolve_key_alias(did, keychain.as_ref())?
    } else {
        let aliases = keychain
            .list_aliases()
            .map_err(|e| PyRuntimeError::new_err(format!("Keychain error: {e}")))?;
        aliases
            .into_iter()
            .find(|a| !a.as_str().contains("--next-"))
            .ok_or_else(|| PyRuntimeError::new_err("No identity key found in keychain"))?
    };

    // Generate a new Ed25519 keypair for the agent
    let agent_alias = KeyAlias::new_unchecked(format!("{}-agent", agent_name));
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|e| PyRuntimeError::new_err(format!("Key generation failed: {e}")))?;
    let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
        .map_err(|e| PyRuntimeError::new_err(format!("Key parsing failed: {e}")))?;
    let _agent_pubkey = keypair.public_key().as_ref().to_vec();

    // Get parent identity DID for key storage association
    let (parent_did, _) = keychain
        .load_key(&parent_alias)
        .map_err(|e| PyRuntimeError::new_err(format!("Key load failed: {e}")))?;

    // Encrypt and store the agent key
    let seed = extract_seed_bytes(pkcs8.as_ref())
        .map_err(|e| PyRuntimeError::new_err(format!("Seed extraction failed: {e}")))?;
    let seed_pkcs8 = encode_seed_as_pkcs8(seed)
        .map_err(|e| PyRuntimeError::new_err(format!("PKCS8 encoding failed: {e}")))?;
    let encrypted = encrypt_keypair(&seed_pkcs8, &passphrase_str)
        .map_err(|e| PyRuntimeError::new_err(format!("Key encryption failed: {e}")))?;
    keychain
        .store_key(&agent_alias, &parent_did, &encrypted)
        .map_err(|e| PyRuntimeError::new_err(format!("Key storage failed: {e}")))?;

    // Parse capabilities
    let parsed_caps: Vec<Capability> = capabilities
        .iter()
        .map(|c| {
            Capability::parse(c)
                .map_err(|e| PyRuntimeError::new_err(format!("Invalid capability '{c}': {e}")))
        })
        .collect::<PyResult<Vec<_>>>()?;

    let link_config = DeviceLinkConfig {
        identity_key_alias: parent_alias,
        device_key_alias: Some(agent_alias.clone()),
        device_did: None,
        capabilities: parsed_caps,
        expires_in_days,
        note: Some(format!("Agent: {}", agent_name)),
        payload: None,
    };

    let keychain: Arc<dyn KeyStorage + Send + Sync> = Arc::from(keychain);
    let identity_storage = Arc::new(RegistryIdentityStorage::new(&repo));
    let attestation_storage = Arc::new(RegistryAttestationStorage::new(&repo));

    let ctx = AuthsContext::builder()
        .registry(backend)
        .key_storage(keychain)
        .clock(clock.clone())
        .identity_storage(identity_storage)
        .attestation_sink(attestation_storage.clone())
        .attestation_source(attestation_storage.clone())
        .passphrase_provider(provider)
        .build()
        .map_err(|e| PyRuntimeError::new_err(format!("Context build failed: {e}")))?;

    py.allow_threads(|| {
        let result = link_device(link_config, &ctx, clock.as_ref())
            .map_err(|e| PyRuntimeError::new_err(format!("Agent provisioning failed: {e}")))?;

        let device_did = DeviceDID(result.device_did.to_string());
        let attestations = attestation_storage
            .load_attestations_for_device(&device_did)
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to load attestation: {e}")))?;

        let attestation = attestations.last().ok_or_else(|| {
            PyRuntimeError::new_err("No attestation found after provisioning")
        })?;

        let attestation_json = serde_json::to_string(attestation)
            .map_err(|e| PyRuntimeError::new_err(format!("Serialization failed: {e}")))?;

        Ok(DelegatedAgentBundle {
            agent_did: result.device_did.to_string(),
            key_alias: agent_alias.to_string(),
            attestation_json,
            repo_path: Some(repo.to_string_lossy().to_string()),
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

    let alias = resolve_key_alias(identity_key_alias, keychain.as_ref())?;

    let keychain: Arc<dyn KeyStorage + Send + Sync> = Arc::from(keychain);
    let identity_storage = Arc::new(RegistryIdentityStorage::new(&repo));
    let attestation_storage = Arc::new(RegistryAttestationStorage::new(&repo));

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

    let alias = resolve_key_alias(identity_key_alias, keychain.as_ref())?;

    let keychain: Arc<dyn KeyStorage + Send + Sync> = Arc::from(keychain);
    let identity_storage = Arc::new(RegistryIdentityStorage::new(&repo));
    let attestation_storage = Arc::new(RegistryAttestationStorage::new(&repo));

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
