//! Headless agent identity provisioning API.
//!
//! Provides a library-level API for creating AI agent identities without
//! interactive prompts. Designed for CI/CD pipelines, orchestration systems,
//! and daemon processes.
//!
//! # Storage Modes
//!
//! - [`AgentStorageMode::Persistent`]: Disk-based storage (default: `~/.auths-agent`).
//!   Agent identity survives process restarts.
//! - [`AgentStorageMode::InMemory`]: Ephemeral storage for stateless containers
//!   (Fargate, Docker). Agent identity lives only for the process lifetime.
//!   Explicitly trades persistence for statelessness.
//!
//! # Usage
//!
//! ```rust,ignore
//! use auths_id::agent_identity::{provision_agent_identity, AgentProvisioningConfig, AgentStorageMode};
//!
//! let config = AgentProvisioningConfig {
//!     agent_name: "ci-bot".to_string(),
//!     capabilities: vec!["sign_commit".to_string()],
//!     expires_in: Some(86400),
//!     delegated_by: Some(IdentityDID::new_unchecked("did:keri:Eabc123")),
//!     storage_mode: AgentStorageMode::Persistent { repo_path: None },
//! };
//!
//! let keychain = auths_core::storage::keychain::get_platform_keychain()?;
//! let bundle = provision_agent_identity(config, &my_passphrase_provider, keychain)?;
//! println!("Agent DID: {}", bundle.agent_did);
//! ```

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};

use auths_core::crypto::signer::decrypt_keypair;
use auths_core::signing::{PassphraseProvider, StorageSigner};
use auths_core::storage::keychain::{IdentityDID, KeyAlias, KeyStorage};
use auths_verifier::core::{Attestation, SignerType};
use auths_verifier::error::AttestationError;
use auths_verifier::types::DeviceDID;
use std::sync::Arc;

use crate::attestation::core::resign_attestation;
use crate::attestation::create::create_signed_attestation;
use crate::identity::initialize::initialize_registry_identity;
use crate::storage::git_refs::AttestationMetadata;
use crate::storage::registry::RegistryBackend;

// ── Public Types ────────────────────────────────────────────────────────────

/// Storage mode for agent identity.
#[derive(Debug, Clone)]
pub enum AgentStorageMode {
    /// Persistent storage at a filesystem path.
    /// Defaults to `~/.auths-agent` if `repo_path` is `None`.
    Persistent { repo_path: Option<PathBuf> },
    /// In-memory storage for ephemeral/stateless containers (Fargate, Docker).
    /// Agent identity lives only for the process lifetime.
    InMemory,
}

/// Configuration for provisioning an agent identity.
#[derive(Debug, Clone)]
pub struct AgentProvisioningConfig {
    /// Human-readable agent name (e.g., "ci-bot", "release-agent").
    pub agent_name: String,
    /// Capabilities to grant (e.g., `["sign_commit", "pr:create"]`).
    pub capabilities: Vec<String>,
    /// Duration in seconds until expiration (per RFC 6749).
    pub expires_in: Option<u64>,
    /// DID of the human who authorized this agent.
    pub delegated_by: Option<IdentityDID>,
    /// Storage mode (persistent or ephemeral).
    pub storage_mode: AgentStorageMode,
}

/// Result of a successful agent provisioning.
#[derive(Debug, Clone)]
pub struct AgentIdentityBundle {
    /// The agent's `did:keri:E...` identity.
    pub agent_did: IdentityDID,
    /// The key alias used for signing.
    pub key_alias: KeyAlias,
    /// The agent's attestation (with `signer_type: Agent`).
    pub attestation: Attestation,
    /// Path to the agent repo (`None` for `InMemory` mode).
    pub repo_path: Option<PathBuf>,
}

/// Errors that can occur during agent provisioning.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AgentProvisioningError {
    #[error("repository creation failed: {0}")]
    RepoCreation(#[from] git2::Error),
    #[error("identity creation failed: {0}")]
    IdentityCreation(#[from] crate::error::InitError),
    #[error("attestation creation failed: {0}")]
    AttestationCreation(#[from] AttestationError),
    #[error("keychain access failed: {0}")]
    KeychainAccess(String),
    #[error("config write failed: {0}")]
    ConfigWrite(#[from] std::io::Error),
}

impl auths_core::error::AuthsErrorInfo for AgentProvisioningError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::RepoCreation(_) => "AUTHS-E4301",
            Self::IdentityCreation(_) => "AUTHS-E4302",
            Self::AttestationCreation(_) => "AUTHS-E4303",
            Self::KeychainAccess(_) => "AUTHS-E4304",
            Self::ConfigWrite(_) => "AUTHS-E4305",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::RepoCreation(_) => Some("Check that the agent repo path is writable"),
            Self::IdentityCreation(_) => {
                Some("Identity creation failed; check keychain and backend")
            }
            Self::AttestationCreation(_) => Some("Attestation signing failed; verify key access"),
            Self::KeychainAccess(_) => Some("Check keychain permissions and passphrase"),
            Self::ConfigWrite(_) => Some("Check file permissions and disk space"),
        }
    }
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Provision a new agent identity.
///
/// Creates a KERI identity, signs an attestation with `signer_type: Agent`,
/// and optionally writes an `auths-agent.toml` config file.
///
/// Args:
/// * `backend` - The registry backend for KEL storage. Must be pre-initialized.
/// * `config` - Provisioning configuration (name, capabilities, storage mode).
/// * `passphrase_provider` - Plugin point for passphrase retrieval.
/// * `keychain` - Key storage backend.
///
/// Usage:
/// ```ignore
/// let bundle = provision_agent_identity(Arc::new(my_backend), config, &provider, keychain)?;
/// ```
pub fn provision_agent_identity(
    now: DateTime<Utc>,
    backend: Arc<dyn RegistryBackend + Send + Sync>,
    config: AgentProvisioningConfig,
    passphrase_provider: &dyn PassphraseProvider,
    keychain: Box<dyn KeyStorage + Send + Sync>,
) -> Result<AgentIdentityBundle, AgentProvisioningError> {
    let (repo_path, ephemeral) = resolve_repo_path(&config.storage_mode)?;
    ensure_git_repo(&repo_path)?;

    let key_alias = key_alias_for(&config.storage_mode);
    let agent_did = get_or_create_identity(
        backend,
        &key_alias,
        &config,
        passphrase_provider,
        &*keychain,
    )?;

    let attestation = sign_agent_attestation(
        now,
        &agent_did,
        &key_alias,
        &config,
        passphrase_provider,
        keychain,
    )?;

    if !ephemeral {
        write_agent_toml(&repo_path, agent_did.as_str(), key_alias.as_str(), &config)?;
    }

    Ok(AgentIdentityBundle {
        agent_did,
        key_alias,
        attestation,
        repo_path: if ephemeral { None } else { Some(repo_path) },
    })
}

// ── Repo Setup ──────────────────────────────────────────────────────────────

/// Resolve the repo path from storage mode. Returns `(path, is_ephemeral)`.
fn resolve_repo_path(mode: &AgentStorageMode) -> Result<(PathBuf, bool), AgentProvisioningError> {
    match mode {
        AgentStorageMode::Persistent { repo_path } => {
            let path = match repo_path {
                Some(p) => p.clone(),
                None => default_agent_repo_path()?,
            };
            Ok((path, false))
        }
        AgentStorageMode::InMemory => {
            // Leak the tempdir so it persists for the process lifetime.
            let tmp = tempfile::tempdir().map_err(AgentProvisioningError::ConfigWrite)?;
            let path = tmp.path().to_path_buf();
            // Leak the tempdir so cleanup doesn't run — ephemeral agents persist for process lifetime.
            std::mem::forget(tmp);
            Ok((path, true))
        }
    }
}

#[allow(clippy::disallowed_methods)] // INVARIANT: agent repo setup — directory creation before git init
fn ensure_git_repo(path: &Path) -> Result<(), AgentProvisioningError> {
    if !path.exists() {
        std::fs::create_dir_all(path)?;
    }
    if git2::Repository::open(path).is_err() {
        git2::Repository::init(path)?;
    }
    Ok(())
}

#[allow(clippy::disallowed_methods)] // INVARIANT: designated home-dir resolution for agent repo default path
fn default_agent_repo_path() -> Result<PathBuf, AgentProvisioningError> {
    let home = dirs::home_dir().ok_or_else(|| {
        AgentProvisioningError::ConfigWrite(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "could not determine home directory",
        ))
    })?;
    Ok(home.join(".auths-agent"))
}

fn key_alias_for(mode: &AgentStorageMode) -> KeyAlias {
    match mode {
        AgentStorageMode::Persistent { .. } => KeyAlias::new_unchecked("agent-key"),
        AgentStorageMode::InMemory => KeyAlias::new_unchecked("agent-key-ephemeral"),
    }
}

// ── Identity ────────────────────────────────────────────────────────────────

/// Return the existing identity DID or create a new one.
fn get_or_create_identity(
    backend: Arc<dyn RegistryBackend + Send + Sync>,
    key_alias: &KeyAlias,
    _config: &AgentProvisioningConfig,
    passphrase_provider: &dyn PassphraseProvider,
    keychain: &(dyn KeyStorage + Send + Sync),
) -> Result<IdentityDID, AgentProvisioningError> {
    let mut existing_did: Option<IdentityDID> = None;
    let _ = backend.visit_identities(&mut |prefix| {
        #[allow(clippy::disallowed_methods)]
        // INVARIANT: visit_identities yields KERI prefixes from the registry, format! produces a valid did:keri string
        {
            existing_did = Some(IdentityDID::new_unchecked(format!("did:keri:{}", prefix)));
        }
        std::ops::ControlFlow::Break(())
    });
    if let Some(did) = existing_did {
        return Ok(did);
    }

    let (did, _) =
        initialize_registry_identity(backend, key_alias, passphrase_provider, keychain, None)?;

    Ok(did)
}

// ── Attestation ─────────────────────────────────────────────────────────────

/// Create and sign an attestation with `signer_type: Agent`.
///
/// The flow:
/// 1. Decrypt the key to extract the device public key
/// 2. Create a base attestation via `create_signed_attestation`
/// 3. Stamp `signer_type` and `delegated_by`
/// 4. Re-sign so the canonical data covers the new fields
fn sign_agent_attestation(
    now: DateTime<Utc>,
    controller_did: &IdentityDID,
    key_alias: &KeyAlias,
    config: &AgentProvisioningConfig,
    passphrase_provider: &dyn PassphraseProvider,
    keychain: Box<dyn KeyStorage + Send + Sync>,
) -> Result<Attestation, AgentProvisioningError> {
    let (device_pk, curve) = extract_public_key(key_alias, passphrase_provider, &*keychain)?;
    let device_did = DeviceDID::from_public_key(&device_pk, curve);
    let meta = build_attestation_meta(now, config);
    let signer = StorageSigner::new(keychain);

    let rid = format!("agent:{}", config.agent_name);
    let mut att = create_signed_attestation(
        now,
        &rid,
        controller_did,
        &device_did,
        &device_pk,
        None,
        &meta,
        &signer,
        passphrase_provider,
        Some(key_alias),
        Some(key_alias),
        vec![],
        None,
        config.delegated_by.clone(),
        None, // commit_sha
        Some(SignerType::Agent),
    )?;

    resign_attestation(
        &mut att,
        &signer,
        passphrase_provider,
        Some(key_alias),
        key_alias,
    )?;

    Ok(att)
}

/// Decrypt the stored key and return the 32-byte Ed25519 public key.
fn extract_public_key(
    key_alias: &KeyAlias,
    passphrase_provider: &dyn PassphraseProvider,
    keychain: &dyn KeyStorage,
) -> Result<(Vec<u8>, auths_crypto::CurveType), AgentProvisioningError> {
    let (_did, _role, encrypted) = keychain
        .load_key(key_alias)
        .map_err(|e| AgentProvisioningError::KeychainAccess(e.to_string()))?;

    let passphrase = passphrase_provider
        .get_passphrase("agent key passphrase")
        .map_err(|e| AgentProvisioningError::KeychainAccess(e.to_string()))?;

    let decrypted = decrypt_keypair(&encrypted, &passphrase)
        .map_err(|e| AgentProvisioningError::KeychainAccess(e.to_string()))?;

    let (_seed, pubkey, curve) = auths_core::crypto::signer::load_seed_and_pubkey(&decrypted)
        .map_err(|e| AgentProvisioningError::KeychainAccess(format!("bad pkcs8: {}", e)))?;

    Ok((pubkey, curve))
}

fn build_attestation_meta(
    now: DateTime<Utc>,
    config: &AgentProvisioningConfig,
) -> AttestationMetadata {
    let expires_at = config
        .expires_in
        .map(|s| now + chrono::Duration::seconds(s as i64));

    AttestationMetadata {
        note: Some(format!("Agent: {}", config.agent_name)),
        timestamp: Some(now),
        expires_at,
    }
}

// ── Config File ─────────────────────────────────────────────────────────────

#[allow(clippy::disallowed_methods)] // INVARIANT: agent config file write — one-shot file creation during provisioning
fn write_agent_toml(
    repo_path: &Path,
    did: &str,
    key_alias: &str,
    config: &AgentProvisioningConfig,
) -> Result<(), AgentProvisioningError> {
    let content = format_agent_toml(did, key_alias, config);
    std::fs::write(repo_path.join("auths-agent.toml"), content)?;
    Ok(())
}

pub fn format_agent_toml(did: &str, key_alias: &str, config: &AgentProvisioningConfig) -> String {
    let caps = config
        .capabilities
        .iter()
        .map(|c| format!("\"{}\"", c))
        .collect::<Vec<_>>()
        .join(", ");

    let mut out = format!(
        "# Auths Agent Configuration\n\
         # Generated by provision_agent_identity()\n\n\
         [agent]\n\
         name = \"{}\"\n\
         did = \"{}\"\n\
         key_alias = \"{}\"\n\
         signer_type = \"Agent\"\n",
        config.agent_name, did, key_alias,
    );

    if let Some(ref delegator) = config.delegated_by {
        out.push_str(&format!("delegated_by = \"{}\"\n", delegator));
    }

    out.push_str(&format!("\n[capabilities]\ngranted = [{}]\n", caps));

    if let Some(secs) = config.expires_in {
        out.push_str(&format!("\n[expiry]\nexpires_in = {}\n", secs));
    }

    out
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    #[test]
    fn format_agent_toml_with_all_fields() {
        let config = AgentProvisioningConfig {
            agent_name: "ci-bot".to_string(),
            capabilities: vec!["sign_commit".to_string(), "pr:create".to_string()],
            expires_in: Some(86400),
            delegated_by: Some(IdentityDID::new_unchecked("did:keri:Eabc123")),
            storage_mode: AgentStorageMode::Persistent { repo_path: None },
        };
        let toml = format_agent_toml("did:keri:Eagent", "agent-key", &config);
        assert!(toml.contains("name = \"ci-bot\""));
        assert!(toml.contains("did = \"did:keri:Eagent\""));
        assert!(toml.contains("delegated_by = \"did:keri:Eabc123\""));
        assert!(toml.contains("\"sign_commit\", \"pr:create\""));
        assert!(toml.contains("expires_in = 86400"));
    }

    #[test]
    fn format_agent_toml_minimal() {
        let config = AgentProvisioningConfig {
            agent_name: "solo".to_string(),
            capabilities: vec![],
            expires_in: None,
            delegated_by: None,
            storage_mode: AgentStorageMode::InMemory,
        };
        let toml = format_agent_toml("did:keri:E1", "k", &config);
        assert!(!toml.contains("delegated_by"));
        assert!(!toml.contains("[expiry]"));
    }

    #[test]
    fn key_alias_persistent_vs_ephemeral() {
        assert_eq!(
            key_alias_for(&AgentStorageMode::Persistent { repo_path: None }).as_str(),
            "agent-key"
        );
        assert_eq!(
            key_alias_for(&AgentStorageMode::InMemory).as_str(),
            "agent-key-ephemeral"
        );
    }

    #[test]
    fn default_repo_path_ends_with_auths_agent() {
        let path = default_agent_repo_path().unwrap();
        assert!(path.ends_with(".auths-agent"));
    }
}
