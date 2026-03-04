//! Commit signing workflow with three-tier fallback.
//!
//! Tier 1: Agent-based signing (passphrase-free, fastest).
//! Tier 2: Auto-start agent + decrypt key + direct sign.
//! Tier 3: Direct signing with decrypted seed.

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use zeroize::Zeroizing;

use auths_core::AgentError;
use auths_core::crypto::signer::decrypt_keypair;
use auths_core::crypto::ssh::{SecureSeed, extract_seed_from_pkcs8};
use auths_core::storage::keychain::KeyAlias;

use crate::context::AuthsContext;
use crate::ports::agent::AgentSigningError;
use crate::signing::{self, SigningError};

const DEFAULT_MAX_PASSPHRASE_ATTEMPTS: usize = 3;

/// Parameters for a commit signing operation.
///
/// Args:
/// * `key_alias`: The keychain alias identifying the signing key.
/// * `namespace`: The SSHSIG namespace (typically `"git"`).
/// * `data`: The raw bytes to sign (commit or tag content).
/// * `pubkey`: Cached Ed25519 public key bytes for agent signing.
/// * `repo_path`: Optional path to the auths repository for freeze validation.
/// * `max_passphrase_attempts`: Maximum passphrase retry attempts (default 3).
///
/// Usage:
/// ```ignore
/// let params = CommitSigningParams::new("my-key", "git", commit_bytes)
///     .with_pubkey(cached_pubkey)
///     .with_repo_path(repo_path);
/// ```
pub struct CommitSigningParams {
    /// Keychain alias for the signing key.
    pub key_alias: String,
    /// SSHSIG namespace (e.g. `"git"`).
    pub namespace: String,
    /// Raw bytes to sign.
    pub data: Vec<u8>,
    /// Cached Ed25519 public key bytes for agent signing.
    pub pubkey: Vec<u8>,
    /// Optional auths repository path for freeze validation.
    pub repo_path: Option<PathBuf>,
    /// Maximum number of passphrase attempts before returning `PassphraseExhausted`.
    pub max_passphrase_attempts: usize,
}

impl CommitSigningParams {
    /// Create signing params with required fields.
    ///
    /// Args:
    /// * `key_alias`: The keychain alias for the signing key.
    /// * `namespace`: The SSHSIG namespace.
    /// * `data`: The raw bytes to sign.
    pub fn new(key_alias: impl Into<String>, namespace: impl Into<String>, data: Vec<u8>) -> Self {
        Self {
            key_alias: key_alias.into(),
            namespace: namespace.into(),
            data,
            pubkey: Vec::new(),
            repo_path: None,
            max_passphrase_attempts: DEFAULT_MAX_PASSPHRASE_ATTEMPTS,
        }
    }

    /// Set the cached public key for agent signing.
    pub fn with_pubkey(mut self, pubkey: Vec<u8>) -> Self {
        self.pubkey = pubkey;
        self
    }

    /// Set the auths repository path for freeze validation.
    pub fn with_repo_path(mut self, path: PathBuf) -> Self {
        self.repo_path = Some(path);
        self
    }

    /// Set the maximum number of passphrase attempts.
    pub fn with_max_passphrase_attempts(mut self, max: usize) -> Self {
        self.max_passphrase_attempts = max;
        self
    }
}

/// Commit signing workflow with three-tier fallback.
///
/// Tier 1: Agent signing (no passphrase needed).
/// Tier 2: Auto-start agent, decrypt key, load into agent, then direct sign.
/// Tier 3: Direct signing with decrypted seed.
///
/// Args:
/// * `ctx`: Runtime context with injected ports.
/// * `params`: Signing parameters.
/// * `now`: Wall-clock time for freeze validation.
///
/// Usage:
/// ```ignore
/// let params = CommitSigningParams::new("my-key", "git", data);
/// let pem = CommitSigningWorkflow::execute(&ctx, params, Utc::now())?;
/// ```
pub struct CommitSigningWorkflow;

impl CommitSigningWorkflow {
    /// Execute the three-tier commit signing flow.
    ///
    /// Args:
    /// * `ctx`: Runtime context providing keychain, passphrase provider, and agent port.
    /// * `params`: Commit signing parameters.
    /// * `now`: Current wall-clock time for freeze validation.
    pub fn execute(
        ctx: &AuthsContext,
        params: CommitSigningParams,
        now: DateTime<Utc>,
    ) -> Result<String, SigningError> {
        // Tier 1: try agent signing
        match try_agent_sign(ctx, &params) {
            Ok(pem) => return Ok(pem),
            Err(SigningError::AgentUnavailable(_)) => {}
            Err(e) => return Err(e),
        }

        // Tier 2: auto-start agent + decrypt key + load into agent + direct sign
        let _ = ctx.agent_signing.ensure_running();

        let pkcs8_der = load_key_with_passphrase_retry(ctx, &params)?;
        let seed = extract_seed_from_pkcs8(&pkcs8_der)
            .map_err(|e| SigningError::KeyDecryptionFailed(e.to_string()))?;

        // Best-effort: load identity into agent for future Tier 1 hits
        let _ = ctx
            .agent_signing
            .add_identity(&params.namespace, &pkcs8_der);

        // Tier 3: direct sign
        direct_sign(&params, &seed, now)
    }
}

fn try_agent_sign(
    ctx: &AuthsContext,
    params: &CommitSigningParams,
) -> Result<String, SigningError> {
    ctx.agent_signing
        .try_sign(&params.namespace, &params.pubkey, &params.data)
        .map_err(|e| match e {
            AgentSigningError::Unavailable(msg) | AgentSigningError::ConnectionFailed(msg) => {
                SigningError::AgentUnavailable(msg)
            }
            other => SigningError::AgentSigningFailed(other),
        })
}

fn load_key_with_passphrase_retry(
    ctx: &AuthsContext,
    params: &CommitSigningParams,
) -> Result<Zeroizing<Vec<u8>>, SigningError> {
    let alias = KeyAlias::new_unchecked(&params.key_alias);
    let (_identity_did, encrypted_data) = ctx
        .key_storage
        .load_key(&alias)
        .map_err(|e| SigningError::KeychainUnavailable(e.to_string()))?;

    let prompt = format!("Enter passphrase for '{}':", params.key_alias);

    for attempt in 1..=params.max_passphrase_attempts {
        let passphrase = ctx
            .passphrase_provider
            .get_passphrase(&prompt)
            .map_err(|e| SigningError::KeyDecryptionFailed(e.to_string()))?;

        match decrypt_keypair(&encrypted_data, &passphrase) {
            Ok(decrypted) => return Ok(decrypted),
            Err(AgentError::IncorrectPassphrase) => {
                if attempt < params.max_passphrase_attempts {
                    ctx.passphrase_provider.on_incorrect_passphrase(&prompt);
                }
            }
            Err(e) => return Err(SigningError::KeyDecryptionFailed(e.to_string())),
        }
    }

    Err(SigningError::PassphraseExhausted {
        attempts: params.max_passphrase_attempts,
    })
}

fn direct_sign(
    params: &CommitSigningParams,
    seed: &SecureSeed,
    now: DateTime<Utc>,
) -> Result<String, SigningError> {
    if let Some(ref repo_path) = params.repo_path {
        signing::validate_freeze_state(repo_path, now)?;
    }

    signing::sign_with_seed(seed, &params.data, &params.namespace)
}
