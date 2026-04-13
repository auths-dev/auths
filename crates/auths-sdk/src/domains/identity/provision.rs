//! Declarative provisioning workflow for enterprise node setup.
//!
//! Receives a pre-deserialized `NodeConfig` and reconciles the node's identity
//! state. All I/O (TOML loading, env expansion) is handled by the caller.

use std::collections::HashMap;
use std::sync::Arc;

use auths_core::signing::PassphraseProvider;
use auths_core::storage::keychain::{KeyAlias, KeyStorage};
use auths_id::{
    identity::initialize::initialize_registry_identity,
    ports::registry::RegistryBackend,
    storage::identity::IdentityStorage,
    witness_config::{WitnessConfig, WitnessPolicy},
};
use serde::Deserialize;

/// Top-level node configuration for declarative provisioning.
#[derive(Debug, Deserialize)]
pub struct NodeConfig {
    /// Identity configuration section.
    pub identity: IdentityConfig,
    /// Optional witness configuration section.
    pub witness: Option<WitnessOverride>,
}

/// Identity section of the node configuration.
#[derive(Debug, Deserialize)]
pub struct IdentityConfig {
    /// Key alias for storing the generated private key.
    #[serde(default = "default_key_alias")]
    pub key_alias: String,

    /// Path to the Git repository storing identity data.
    #[serde(default = "default_repo_path")]
    pub repo_path: String,

    /// Storage layout preset (default, radicle, gitoxide).
    #[serde(default = "default_preset")]
    pub preset: String,

    /// Optional metadata key-value pairs attached to the identity.
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

/// Witness section of the node configuration (TOML-friendly view).
#[derive(Debug, Deserialize)]
pub struct WitnessOverride {
    /// Witness server URLs.
    #[serde(default)]
    pub urls: Vec<String>,

    /// Minimum witness receipts required (k-of-n threshold).
    #[serde(default = "default_threshold")]
    pub threshold: usize,

    /// Per-witness timeout in milliseconds.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,

    /// Witness policy: `enforce`, `warn`, or `skip`.
    #[serde(default = "default_policy")]
    pub policy: String,
}

fn default_key_alias() -> String {
    "main".to_string()
}

fn default_repo_path() -> String {
    auths_core::paths::auths_home()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "~/.auths".to_string())
}

fn default_preset() -> String {
    "default".to_string()
}

fn default_threshold() -> usize {
    1
}

fn default_timeout_ms() -> u64 {
    5000
}

fn default_policy() -> String {
    "enforce".to_string()
}

/// Result of a successful provisioning run.
#[derive(Debug)]
pub struct ProvisionResult {
    /// The controller DID of the newly provisioned identity.
    pub controller_did: String,
    /// The keychain alias under which the signing key was stored.
    pub key_alias: KeyAlias,
}

/// Errors from the provisioning workflow.
#[derive(Debug, thiserror::Error)]
pub enum ProvisionError {
    /// The platform keychain could not be accessed.
    #[error("failed to access platform keychain: {0}")]
    KeychainUnavailable(String),

    /// The identity initialization step failed.
    #[error("failed to initialize identity: {0}")]
    IdentityInit(String),

    /// An identity already exists and `force` was not set.
    #[error("identity already exists (use force=true to overwrite)")]
    IdentityExists,
}

/// Check for an existing identity and create one if absent (or if force=true).
///
/// Args:
/// * `config`: The resolved node configuration.
/// * `force`: Overwrite an existing identity when true.
/// * `passphrase_provider`: Provider used to encrypt the generated key.
/// * `keychain`: Platform keychain for key storage.
/// * `registry`: Pre-initialized registry backend.
/// * `identity_storage`: Pre-initialized identity storage adapter.
///
/// Usage:
/// ```ignore
/// let result = enforce_identity_state(
///     &config, false, passphrase_provider.as_ref(), keychain.as_ref(), registry, identity_storage,
/// )?;
/// println!("DID: {}", result.controller_did);
/// ```
pub fn enforce_identity_state(
    config: &NodeConfig,
    force: bool,
    passphrase_provider: &dyn PassphraseProvider,
    keychain: &(dyn KeyStorage + Send + Sync),
    registry: Arc<dyn RegistryBackend + Send + Sync>,
    identity_storage: Arc<dyn IdentityStorage + Send + Sync>,
) -> Result<Option<ProvisionResult>, ProvisionError> {
    if identity_storage.load_identity().is_ok() && !force {
        return Ok(None);
    }

    let witness_config = build_witness_config(config.witness.as_ref());

    let alias = KeyAlias::new_unchecked(&config.identity.key_alias);
    let (controller_did, key_alias) = initialize_registry_identity(
        registry,
        &alias,
        passphrase_provider,
        keychain,
        witness_config.as_ref(),
        auths_crypto::CurveType::default(),
    )
    .map_err(|e| ProvisionError::IdentityInit(e.to_string()))?;

    Ok(Some(ProvisionResult {
        controller_did: controller_did.into_inner(),
        key_alias,
    }))
}

fn build_witness_config(witness: Option<&WitnessOverride>) -> Option<WitnessConfig> {
    let w = witness?;
    if w.urls.is_empty() {
        return None;
    }
    let policy = match w.policy.as_str() {
        "warn" => WitnessPolicy::Warn,
        "skip" => WitnessPolicy::Skip,
        _ => WitnessPolicy::Enforce,
    };
    Some(WitnessConfig {
        witness_urls: w.urls.iter().filter_map(|u| u.parse().ok()).collect(),
        threshold: w.threshold,
        timeout_ms: w.timeout_ms,
        policy,
        ..Default::default()
    })
}
