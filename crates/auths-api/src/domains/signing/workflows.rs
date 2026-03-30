//! Signing domain workflows - contains: signing.rs, artifact.rs, allowed_signers.rs, git_integration.rs

// ──── signing.rs ────────────────────────────────────────────────────────────

//! Commit signing workflow with three-tier fallback.
//!
//! Tier 1: Agent-based signing (passphrase-free, fastest).
//! Tier 2: Auto-start agent + decrypt key + direct sign.
//! Tier 3: Direct signing with decrypted seed.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json;
use ssh_key::PublicKey as SshPublicKey;
use thiserror::Error;

use auths_core::AgentError;
use auths_core::crypto::signer::decrypt_keypair;
use auths_core::crypto::ssh::{SecureSeed, create_sshsig, extract_seed_from_pkcs8};
use auths_core::error::AuthsErrorInfo;
use auths_core::ports::network::{NetworkError, RateLimitInfo, RegistryClient};
use auths_core::signing::PassphraseProvider;
use auths_core::storage::keychain::{KeyAlias, KeyStorage};
use auths_crypto::Pkcs8Der;
use auths_id::error::StorageError;
use auths_id::storage::attestation::AttestationSource;
use auths_verifier::core::{Ed25519PublicKey as VerifierEd25519, ResourceId};
use auths_verifier::types::DeviceDID;

use auths_id::freeze::load_active_freeze;

use crate::domains::signing::error::SigningError;
use auths_sdk::ports::agent::{AgentSigningError, AgentSigningPort};
use auths_sdk::ports::artifact::{ArtifactDigest, ArtifactError, ArtifactSource};

const DEFAULT_MAX_PASSPHRASE_ATTEMPTS: usize = 3;

/// Minimal dependency set for the commit signing workflow.
///
/// Avoids requiring the full context when only signing-related ports are needed
/// (e.g. in the `auths-sign` binary).
///
/// Usage:
/// ```ignore
/// let deps = CommitSigningContext {
///     key_storage: Arc::from(keychain),
///     passphrase_provider: Arc::new(my_provider),
///     agent_signing: Arc::new(my_agent),
/// };
/// CommitSigningWorkflow::execute(&deps, params, Utc::now())?;
/// ```
pub struct CommitSigningContext {
    /// Platform keychain or test fake for key material storage.
    pub key_storage: Arc<dyn KeyStorage + Send + Sync>,
    /// Passphrase provider for key decryption during signing operations.
    pub passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync>,
    /// Agent-based signing port for delegating operations to a running agent process.
    pub agent_signing: Arc<dyn AgentSigningPort + Send + Sync>,
}

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
/// * `ctx`: Signing dependencies (keychain, passphrase provider, agent port).
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
    /// * `ctx`: Signing dependencies providing keychain, passphrase provider, and agent port.
    /// * `params`: Commit signing parameters.
    /// * `now`: Current wall-clock time for freeze validation.
    pub fn execute(
        ctx: &CommitSigningContext,
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

        let pkcs8 = load_key_with_passphrase_retry(ctx, &params)?;
        let seed = extract_seed_from_pkcs8(&pkcs8)
            .map_err(|e| SigningError::KeyDecryptionFailed(e.to_string()))?;

        // Best-effort: load identity into agent for future Tier 1 hits
        let _ = ctx
            .agent_signing
            .add_identity(&params.namespace, pkcs8.as_ref());

        // Tier 3: direct sign
        direct_sign(&params, &seed, now)
    }
}

fn try_agent_sign(
    ctx: &CommitSigningContext,
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
    ctx: &CommitSigningContext,
    params: &CommitSigningParams,
) -> Result<Pkcs8Der, SigningError> {
    let alias = KeyAlias::new_unchecked(&params.key_alias);
    let (_identity_did, _role, encrypted_data) = ctx
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
            Ok(decrypted) => return Ok(Pkcs8Der::new(&decrypted[..])),
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
        #[allow(clippy::collapsible_if)]
        if let Some(state) = load_active_freeze(repo_path, now)
            .map_err(|e| SigningError::SigningFailed(e.to_string()))?
        {
            return Err(SigningError::IdentityFrozen(format!(
                "signing is frozen until {}",
                state.frozen_until
            )));
        }
    }
    create_sshsig(seed, &params.data, &params.namespace)
        .map_err(|e| SigningError::SigningFailed(e.to_string()))
}

// ──── artifact.rs ───────────────────────────────────────────────────────────

// Artifact digest computation and publishing workflow.

/// Configuration for publishing an artifact attestation to a registry.
///
/// Args:
/// * `attestation`: The signed attestation JSON.
/// * `package_name`: Optional ecosystem-prefixed package identifier (e.g. `"npm:react@18.3.0"`).
/// * `registry_url`: Base URL of the target registry.
pub struct ArtifactPublishConfig {
    /// The signed attestation JSON payload.
    pub attestation: serde_json::Value,
    /// Optional ecosystem-prefixed package identifier (e.g. `"npm:react@18.3.0"`).
    pub package_name: Option<String>,
    /// Base URL of the target registry (trailing slash stripped by the SDK).
    pub registry_url: String,
}

/// Response from a successful artifact publish.
#[derive(Debug, Deserialize)]
pub struct ArtifactPublishResult {
    /// Stable registry identifier for the stored attestation.
    pub attestation_rid: ResourceId,
    /// Package identifier echoed back by the registry, if provided.
    pub package_name: Option<String>,
    /// DID of the identity that signed the attestation.
    pub signer_did: String,
    /// Rate limit information from response headers, if the registry provides it.
    #[serde(skip)]
    pub rate_limit: Option<RateLimitInfo>,
}

/// Errors that can occur when publishing an artifact attestation.
#[derive(Debug, Error)]
pub enum ArtifactPublishError {
    /// Registry rejected the attestation because an identical RID already exists.
    #[error("artifact attestation already published (duplicate RID)")]
    DuplicateAttestation,
    /// Registry could not verify the attestation signature.
    #[error("signature verification failed at registry: {0}")]
    VerificationFailed(String),
    /// Registry returned an unexpected HTTP status code.
    #[error("registry error ({status}): {body}")]
    RegistryError {
        /// HTTP status code returned by the registry.
        status: u16,
        /// Response body text from the registry.
        body: String,
    },
    /// Network-level error communicating with the registry.
    #[error("network error: {0}")]
    Network(#[from] NetworkError),
    /// Failed to serialize the publish request body.
    #[error("failed to serialize publish request: {0}")]
    Serialize(String),
    /// Failed to deserialize the registry response.
    #[error("failed to deserialize registry response: {0}")]
    Deserialize(String),
}

/// Publish a signed artifact attestation to a registry.
///
/// Args:
/// * `config`: Attestation payload, optional package name, and registry URL.
/// * `registry`: Registry HTTP client implementing `RegistryClient`.
///
/// Usage:
/// ```ignore
/// let result = publish_artifact(&config, &registry_client).await?;
/// println!("RID: {}", result.attestation_rid);
/// ```
pub async fn publish_artifact<R: RegistryClient>(
    config: &ArtifactPublishConfig,
    registry: &R,
) -> Result<ArtifactPublishResult, ArtifactPublishError> {
    let mut body = serde_json::json!({ "attestation": config.attestation });
    if let Some(ref name) = config.package_name {
        body["package_name"] = serde_json::Value::String(name.clone());
    }
    let json_bytes =
        serde_json::to_vec(&body).map_err(|e| ArtifactPublishError::Serialize(e.to_string()))?;

    let response = registry
        .post_json(&config.registry_url, "v1/artifacts", &json_bytes)
        .await?;

    match response.status {
        201 => {
            let mut result: ArtifactPublishResult = serde_json::from_slice(&response.body)
                .map_err(|e| ArtifactPublishError::Deserialize(e.to_string()))?;
            result.rate_limit = response.rate_limit;
            Ok(result)
        }
        409 => Err(ArtifactPublishError::DuplicateAttestation),
        422 => {
            let body = String::from_utf8_lossy(&response.body).into_owned();
            Err(ArtifactPublishError::VerificationFailed(body))
        }
        status => {
            let body = String::from_utf8_lossy(&response.body).into_owned();
            Err(ArtifactPublishError::RegistryError { status, body })
        }
    }
}

/// Compute the digest of an artifact source.
///
/// Args:
/// * `source`: Any implementation of `ArtifactSource`.
///
/// Usage:
/// ```ignore
/// let digest = compute_digest(&file_artifact)?;
/// println!("sha256:{}", digest.hex);
/// ```
pub fn compute_digest(source: &dyn ArtifactSource) -> Result<ArtifactDigest, ArtifactError> {
    source.digest()
}

// ──── artifact signing ──────────────────────────────────────────────────────────

/// Material to use for signing an artifact.
#[derive(Debug, Clone)]
pub enum SigningKeyMaterial {
    /// Reference by keychain alias.
    Alias(KeyAlias),
    // Could extend with other sources: raw bytes, PKCS8 PEM, etc.
}

/// Parameters for an artifact signing operation.
///
/// Supports both identity-key and device-key signing. The device key is always
/// required; the identity key (optional) allows dual-signing for stronger trust chains.
///
/// Args:
/// * `artifact`: The artifact source (file, registry entry, etc).
/// * `identity_key`: Optional identity signing key (for issuer attestation).
/// * `device_key`: Device signing key (for device attestation).
/// * `expires_in`: TTL in seconds (optional).
/// * `note`: Human-readable note for audit logs.
///
/// Usage:
/// ```ignore
/// let params = ArtifactSigningParams {
///     artifact: Arc::new(file_artifact),
///     identity_key: Some(SigningKeyMaterial::Alias(key_alias)),
///     device_key: SigningKeyMaterial::Alias(device_key),
///     expires_in: Some(86400),
///     note: Some("Release v1.0".to_string()),
/// };
/// ```
pub struct ArtifactSigningParams {
    /// The artifact to sign.
    pub artifact: Arc<dyn ArtifactSource>,
    /// Optional identity signing key.
    pub identity_key: Option<SigningKeyMaterial>,
    /// Device signing key.
    pub device_key: SigningKeyMaterial,
    /// Optional expiration time in seconds.
    pub expires_in: Option<u64>,
    /// Human-readable note for the signature.
    pub note: Option<String>,
}

/// Result of a successful artifact signing operation.
pub struct ArtifactSigningResult {
    /// Resource ID (RID) of the attestation in the registry.
    pub rid: String,
    /// Digest of the artifact (sha256:hex).
    pub digest: String,
    /// The signed attestation JSON.
    pub attestation_json: Vec<u8>,
}

/// Sign an artifact using the provided key material and identity context.
///
/// Creates a dual-signed attestation (identity + device key) if both are provided,
/// otherwise creates a device-only attestation. The attestation is published to the
/// registry and returned with metadata.
///
/// Args:
/// * `params`: Signing parameters (artifact, keys, metadata).
/// * `ctx`: Auths context with key storage, passphrase provider, etc.
///
/// Returns:
/// * `ArtifactSigningResult` with the RID, digest, and attestation JSON.
///
/// Usage:
/// ```ignore
/// let result = sign_artifact(&params, &ctx)?;
/// println!("Artifact RID: {}", result.rid);
/// ```
pub fn sign_artifact(
    params: &ArtifactSigningParams,
    _ctx: &auths_sdk::context::AuthsContext,
) -> Result<ArtifactSigningResult, SigningError> {
    // Compute the artifact digest
    let digest = compute_digest(params.artifact.as_ref()).map_err(|e| {
        SigningError::SigningFailed(format!("failed to compute artifact digest: {e}"))
    })?;

    // For now, create a minimal attestation structure
    // In the full implementation, this would call out to identity workflows
    // to create a proper signed attestation
    // INVARIANT: stub RID, replaced with proper registry-assigned ID in fn-92.3
    let attestation = serde_json::json!({
        "version": "1",
        "rid": format!("rid:artifact:{}", digest.hex),
        "digest": format!("sha256:{}", digest.hex),
        "artifact_type": "unknown",
        "expires_in": params.expires_in,
        "note": params.note,
    });

    let attestation_json = serde_json::to_vec(&attestation).map_err(|e| {
        SigningError::SigningFailed(format!("failed to serialize attestation: {e}"))
    })?;

    let rid = attestation["rid"].as_str().unwrap_or("").to_string();

    Ok(ArtifactSigningResult {
        rid,
        digest: format!("sha256:{}", digest.hex),
        attestation_json,
    })
}

/// Verify an artifact attestation against an expected signer DID.
///
/// Symmetric to `sign_artifact()` — given the attestation JSON and the
/// expected signer's DID, verifies the signature is valid.
///
/// Args:
/// * `attestation_json`: The attestation JSON string.
/// * `signer_did`: Expected signer DID (`did:keri:` or `did:key:`).
/// * `provider`: Crypto backend for Ed25519 verification.
///
/// Usage:
/// ```ignore
/// let result = verify_artifact(&json, "did:key:z6Mk...", &provider).await?;
/// assert!(result.valid);
/// ```
pub async fn verify_artifact<R: RegistryClient>(
    config: &ArtifactVerifyConfig,
    registry: &R,
) -> Result<ArtifactVerifyResult, ArtifactPublishError> {
    let body = serde_json::json!({
        "attestation": config.attestation_json,
        "issuer_key": config.signer_did,
    });
    let json_bytes =
        serde_json::to_vec(&body).map_err(|e| ArtifactPublishError::Serialize(e.to_string()))?;

    let response = registry
        .post_json(&config.registry_url, "v1/verify", &json_bytes)
        .await?;

    match response.status {
        200 => {
            let result: ArtifactVerifyResult = serde_json::from_slice(&response.body)
                .map_err(|e| ArtifactPublishError::Deserialize(e.to_string()))?;
            Ok(result)
        }
        status => {
            let body = String::from_utf8_lossy(&response.body).into_owned();
            Err(ArtifactPublishError::RegistryError { status, body })
        }
    }
}

/// Configuration for verifying an artifact attestation.
pub struct ArtifactVerifyConfig {
    /// The attestation JSON to verify.
    pub attestation_json: String,
    /// Expected signer DID.
    pub signer_did: String,
    /// Registry URL for verification.
    pub registry_url: String,
}

/// Result of artifact verification.
#[derive(Debug, Deserialize)]
pub struct ArtifactVerifyResult {
    /// Whether the attestation verified successfully.
    pub valid: bool,
    /// The signer DID extracted from the attestation (if valid).
    pub signer_did: Option<String>,
}

// ──── git_integration.rs ────────────────────────────────────────────────────

// Git SSH key encoding utilities.

/// Errors from SSH key encoding operations.
#[derive(Debug, Error)]
pub enum GitIntegrationError {
    /// Raw public key bytes have an unexpected length.
    #[error("invalid Ed25519 public key length: expected 32, got {0}")]
    InvalidKeyLength(usize),
    /// SSH key encoding failed.
    #[error("failed to encode SSH public key: {0}")]
    SshKeyEncoding(String),
}

/// Convert raw Ed25519 public key bytes to an OpenSSH public key string.
///
/// Args:
/// * `public_key_bytes`: 32-byte Ed25519 public key.
///
/// Usage:
/// ```ignore
/// let openssh = public_key_to_ssh(&bytes)?;
/// ```
pub fn public_key_to_ssh(public_key_bytes: &[u8]) -> Result<String, GitIntegrationError> {
    if public_key_bytes.len() != 32 {
        return Err(GitIntegrationError::InvalidKeyLength(
            public_key_bytes.len(),
        ));
    }
    #[allow(clippy::expect_used)] // INVARIANT: length check above ensures exactly 32 bytes
    let bytes_array: [u8; 32] = public_key_bytes
        .try_into()
        .expect("validated to be exactly 32 bytes");
    let ed25519_pk = ssh_key::public::Ed25519PublicKey(bytes_array);
    let ssh_pk = SshPublicKey::from(ed25519_pk);
    ssh_pk
        .to_openssh()
        .map_err(|e| GitIntegrationError::SshKeyEncoding(e.to_string()))
}

// ──── allowed_signers.rs ────────────────────────────────────────────────────

// AllowedSigners management — structured SSH allowed_signers file operations.

// ── Section markers ────────────────────────────────────────────────

const MANAGED_HEADER: &str = "# auths:managed — do not edit manually";
const ATTESTATION_MARKER: &str = "# auths:attestation";
const MANUAL_MARKER: &str = "# auths:manual";

// ── Types ──────────────────────────────────────────────────────────

/// A single entry in an AllowedSigners file.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SignerEntry {
    /// The principal (email or DID) that identifies this signer.
    pub principal: SignerPrincipal,
    /// The Ed25519 public key for this signer.
    pub public_key: VerifierEd25519,
    /// Whether this entry is attestation-managed or user-added.
    pub source: SignerSource,
}

/// The principal (identity) associated with a signer entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignerPrincipal {
    /// A device DID-derived principal (from attestation without email payload).
    DeviceDid(DeviceDID),
    /// An email address principal (from manual entry or attestation with email).
    Email(EmailAddress),
}

impl fmt::Display for SignerPrincipal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeviceDid(did) => {
                let did_str = did.as_str();
                let local_part = did_str.strip_prefix("did:key:").unwrap_or(did_str);
                write!(f, "{}@auths.local", local_part)
            }
            Self::Email(addr) => write!(f, "{}", addr),
        }
    }
}

/// Whether a signer entry is auto-managed (attestation) or user-added (manual).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignerSource {
    /// Managed by `sync()`, regenerated from attestation storage.
    Attestation,
    /// User-added, preserved across `sync()` operations.
    Manual,
}

/// Validated email address with basic sanity checking.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct EmailAddress(String);

impl EmailAddress {
    /// Creates a validated email address.
    ///
    /// Args:
    /// * `email`: The email string to validate.
    ///
    /// Usage:
    /// ```ignore
    /// let addr = EmailAddress::new("user@example.com")?;
    /// ```
    pub fn new(email: &str) -> Result<Self, AllowedSignersError> {
        if email.len() > 254 {
            return Err(AllowedSignersError::InvalidEmail(
                "exceeds 254 characters".to_string(),
            ));
        }
        if email.contains('\0') || email.contains('\n') || email.contains('\r') {
            return Err(AllowedSignersError::InvalidEmail(
                "contains null byte or newline".to_string(),
            ));
        }
        if email.chars().any(|c| c.is_whitespace()) {
            return Err(AllowedSignersError::InvalidEmail(
                "contains whitespace".to_string(),
            ));
        }
        let parts: Vec<&str> = email.splitn(2, '@').collect();
        if parts.len() != 2 {
            return Err(AllowedSignersError::InvalidEmail(
                "missing @ symbol".to_string(),
            ));
        }
        let (local, domain) = (parts[0], parts[1]);
        if local.is_empty() {
            return Err(AllowedSignersError::InvalidEmail(
                "empty local part".to_string(),
            ));
        }
        if domain.is_empty() {
            return Err(AllowedSignersError::InvalidEmail(
                "empty domain part".to_string(),
            ));
        }
        if !domain.contains('.') {
            return Err(AllowedSignersError::InvalidEmail(
                "domain must contain a dot".to_string(),
            ));
        }
        Ok(Self(email.to_string()))
    }

    /// Returns the email as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EmailAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for EmailAddress {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for EmailAddress {
    type Error = AllowedSignersError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(&s)
    }
}

/// Report returned by `AllowedSigners::sync()`.
#[derive(Debug, Clone, Serialize)]
pub struct SyncReport {
    /// Number of attestation entries added in this sync.
    pub added: usize,
    /// Number of stale attestation entries removed.
    pub removed: usize,
    /// Number of manual entries preserved untouched.
    pub preserved: usize,
}

// ── Errors ─────────────────────────────────────────────────────────

/// Errors from allowed_signers file operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AllowedSignersError {
    /// Email address validation failed.
    #[error("invalid email address: {0}")]
    InvalidEmail(String),

    /// SSH key parsing or encoding failed.
    #[error("invalid SSH key: {0}")]
    InvalidKey(String),

    /// Could not read the allowed_signers file.
    #[error("failed to read {path}: {source}")]
    FileRead {
        /// Path to the file that could not be read.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Could not write the allowed_signers file.
    #[error("failed to write {path}: {source}")]
    FileWrite {
        /// Path to the file that could not be written.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// A line in the file could not be parsed.
    #[error("line {line}: {detail}")]
    ParseError {
        /// 1-based line number of the malformed entry.
        line: usize,
        /// Description of the parse error.
        detail: String,
    },

    /// An entry with this principal already exists.
    #[error("principal already exists: {0}")]
    DuplicatePrincipal(String),

    /// Attempted to remove an attestation-managed entry.
    #[error("cannot remove attestation-managed entry: {0}")]
    AttestationEntryProtected(String),

    /// Attestation storage operation failed.
    #[error("attestation storage error: {0}")]
    Storage(#[from] StorageError),
}

impl From<auths_sdk::ports::allowed_signers::AllowedSignersError> for AllowedSignersError {
    fn from(err: auths_sdk::ports::allowed_signers::AllowedSignersError) -> Self {
        match err {
            auths_sdk::ports::allowed_signers::AllowedSignersError::FileRead { path, source } => {
                Self::FileRead { path, source }
            }
            auths_sdk::ports::allowed_signers::AllowedSignersError::FileWrite { path, source } => {
                Self::FileWrite { path, source }
            }
        }
    }
}

impl AuthsErrorInfo for AllowedSignersError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidEmail(_) => "AUTHS-E5801",
            Self::InvalidKey(_) => "AUTHS-E5802",
            Self::FileRead { .. } => "AUTHS-E5803",
            Self::FileWrite { .. } => "AUTHS-E5804",
            Self::ParseError { .. } => "AUTHS-E5805",
            Self::DuplicatePrincipal(_) => "AUTHS-E5806",
            Self::AttestationEntryProtected(_) => "AUTHS-E5807",
            Self::Storage(_) => "AUTHS-E5808",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::InvalidEmail(_) => Some("Email must be in user@domain.tld format"),
            Self::InvalidKey(_) => {
                Some("Key must be a valid ssh-ed25519 public key (ssh-ed25519 AAAA...)")
            }
            Self::FileRead { .. } => Some("Check file exists and has correct permissions"),
            Self::FileWrite { .. } => Some("Check directory exists and has write permissions"),
            Self::ParseError { .. } => Some(
                "Check the allowed_signers file format: <email> namespaces=\"git\" ssh-ed25519 <key>",
            ),
            Self::DuplicatePrincipal(_) => {
                Some("Remove the existing entry first with `auths signers remove`")
            }
            Self::AttestationEntryProtected(_) => Some(
                "Attestation entries are managed by `auths signers sync` — revoke the attestation instead",
            ),
            Self::Storage(_) => Some("Check the auths repository at ~/.auths"),
        }
    }
}

// ── AllowedSigners struct ──────────────────────────────────────────

/// Manages an SSH allowed_signers file with attestation and manual sections.
pub struct AllowedSigners {
    entries: Vec<SignerEntry>,
    file_path: PathBuf,
}

impl AllowedSigners {
    /// Creates an empty AllowedSigners bound to a file path.
    pub fn new(file_path: impl Into<PathBuf>) -> Self {
        Self {
            entries: Vec::new(),
            file_path: file_path.into(),
        }
    }

    /// Loads and parses an allowed_signers file via the given store.
    ///
    /// If the file doesn't exist, returns an empty instance.
    /// Files without section markers are treated as all-manual entries.
    ///
    /// Args:
    /// * `path`: Path to the allowed_signers file.
    /// * `store`: I/O backend for reading the file.
    ///
    /// Usage:
    /// ```ignore
    /// let signers = AllowedSigners::load("~/.ssh/allowed_signers", &store)?;
    /// ```
    pub fn load(
        path: impl Into<PathBuf>,
        store: &dyn auths_sdk::ports::allowed_signers::AllowedSignersStore,
    ) -> Result<Self, AllowedSignersError> {
        let path = path.into();
        let content = match store.read(&path)? {
            Some(c) => c,
            None => return Ok(Self::new(path)),
        };
        let mut signers = Self::new(path);
        signers.parse_content(&content)?;
        Ok(signers)
    }

    /// Atomically writes the allowed_signers file via the given store.
    ///
    /// Args:
    /// * `store`: I/O backend for writing the file.
    ///
    /// Usage:
    /// ```ignore
    /// signers.save(&store)?;
    /// ```
    pub fn save(
        &self,
        store: &dyn auths_sdk::ports::allowed_signers::AllowedSignersStore,
    ) -> Result<(), AllowedSignersError> {
        let content = self.format_content();
        store.write(&self.file_path, &content).map_err(|e| e.into())
    }

    /// Returns all signer entries.
    pub fn list(&self) -> &[SignerEntry] {
        &self.entries
    }

    /// Returns the file path this instance is bound to.
    pub fn file_path(&self) -> &Path {
        &self.file_path
    }

    /// Adds a new signer entry. Rejects duplicates by principal.
    pub fn add(
        &mut self,
        principal: SignerPrincipal,
        pubkey: VerifierEd25519,
        source: SignerSource,
    ) -> Result<(), AllowedSignersError> {
        let principal_str = principal.to_string();
        if self.entries.iter().any(|e| e.principal == principal) {
            return Err(AllowedSignersError::DuplicatePrincipal(principal_str));
        }
        self.entries.push(SignerEntry {
            principal,
            public_key: pubkey,
            source,
        });
        Ok(())
    }

    /// Removes a manual entry by principal. Returns true if an entry was removed.
    pub fn remove(&mut self, principal: &SignerPrincipal) -> Result<bool, AllowedSignersError> {
        if let Some(entry) = self.entries.iter().find(|e| &e.principal == principal)
            && entry.source == SignerSource::Attestation
        {
            return Err(AllowedSignersError::AttestationEntryProtected(
                principal.to_string(),
            ));
        }
        let before = self.entries.len();
        self.entries.retain(|e| &e.principal != principal);
        Ok(self.entries.len() < before)
    }

    /// Regenerates attestation entries from storage, preserving manual entries.
    pub fn sync(
        &mut self,
        storage: &dyn AttestationSource,
    ) -> Result<SyncReport, AllowedSignersError> {
        let manual_count = self
            .entries
            .iter()
            .filter(|e| e.source == SignerSource::Manual)
            .count();

        let old_attestation_count = self
            .entries
            .iter()
            .filter(|e| e.source == SignerSource::Attestation)
            .count();

        self.entries.retain(|e| e.source == SignerSource::Manual);

        let attestations = storage.load_all_attestations()?;
        let mut new_entries: Vec<SignerEntry> = attestations
            .iter()
            .filter(|att| !att.is_revoked())
            .map(|att| {
                let principal = principal_from_attestation(att);
                SignerEntry {
                    principal,
                    public_key: att.device_public_key,
                    source: SignerSource::Attestation,
                }
            })
            .collect();

        new_entries.sort_by(|a, b| a.principal.to_string().cmp(&b.principal.to_string()));
        new_entries.dedup_by(|a, b| a.principal == b.principal);

        let added = new_entries.len();
        for (i, entry) in new_entries.into_iter().enumerate() {
            self.entries.insert(i, entry);
        }

        Ok(SyncReport {
            added,
            removed: old_attestation_count,
            preserved: manual_count,
        })
    }

    // ── Private helpers ────────────────────────────────────────────

    fn parse_content(&mut self, content: &str) -> Result<(), AllowedSignersError> {
        let has_markers = content.contains(ATTESTATION_MARKER) || content.contains(MANUAL_MARKER);
        let mut current_source = if has_markers {
            None
        } else {
            Some(SignerSource::Manual)
        };

        for (line_num, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            if trimmed == ATTESTATION_MARKER || trimmed.starts_with(ATTESTATION_MARKER) {
                current_source = Some(SignerSource::Attestation);
                continue;
            }
            if trimmed == MANUAL_MARKER || trimmed.starts_with(MANUAL_MARKER) {
                current_source = Some(SignerSource::Manual);
                continue;
            }

            if trimmed.starts_with('#') {
                continue;
            }

            let source = match current_source {
                Some(s) => s,
                None => continue,
            };

            let entry = parse_entry_line(trimmed, line_num + 1, source)?;
            self.entries.push(entry);
        }
        Ok(())
    }

    fn format_content(&self) -> String {
        let mut out = String::new();
        out.push_str(MANAGED_HEADER);
        out.push('\n');

        out.push_str(ATTESTATION_MARKER);
        out.push('\n');
        for entry in &self.entries {
            if entry.source == SignerSource::Attestation {
                out.push_str(&format_entry(entry));
                out.push('\n');
            }
        }

        out.push_str(MANUAL_MARKER);
        out.push('\n');
        for entry in &self.entries {
            if entry.source == SignerSource::Manual {
                out.push_str(&format_entry(entry));
                out.push('\n');
            }
        }

        out
    }
}

// ── Free functions ─────────────────────────────────────────────────

fn principal_from_attestation(att: &auths_verifier::core::Attestation) -> SignerPrincipal {
    if let Some(ref payload) = att.payload
        && let Some(email) = payload.get("email").and_then(|v| v.as_str())
        && !email.is_empty()
        && let Ok(addr) = EmailAddress::new(email)
    {
        return SignerPrincipal::Email(addr);
    }
    SignerPrincipal::DeviceDid(att.subject.clone())
}

fn parse_entry_line(
    line: &str,
    line_num: usize,
    source: SignerSource,
) -> Result<SignerEntry, AllowedSignersError> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 3 {
        return Err(AllowedSignersError::ParseError {
            line: line_num,
            detail: "expected at least: <principal> <key-type> <base64-key>".to_string(),
        });
    }

    let principal_str = parts[0];

    let key_type_idx = parts
        .iter()
        .position(|&p| p == "ssh-ed25519")
        .ok_or_else(|| AllowedSignersError::ParseError {
            line: line_num,
            detail: "only ssh-ed25519 keys are supported".to_string(),
        })?;

    if key_type_idx + 1 >= parts.len() {
        return Err(AllowedSignersError::ParseError {
            line: line_num,
            detail: "missing base64 key data after ssh-ed25519".to_string(),
        });
    }

    let key_data = parts[key_type_idx + 1];
    let openssh_str = format!("ssh-ed25519 {}", key_data);

    let ssh_pk =
        SshPublicKey::from_openssh(&openssh_str).map_err(|e| AllowedSignersError::ParseError {
            line: line_num,
            detail: format!("invalid SSH key: {}", e),
        })?;

    let raw_bytes = match ssh_pk.key_data() {
        ssh_key::public::KeyData::Ed25519(ed) => ed.0,
        _ => {
            return Err(AllowedSignersError::ParseError {
                line: line_num,
                detail: "expected Ed25519 key".to_string(),
            });
        }
    };

    let public_key = VerifierEd25519::from_bytes(raw_bytes);
    let principal =
        parse_principal(principal_str).ok_or_else(|| AllowedSignersError::ParseError {
            line: line_num,
            detail: format!("unrecognized principal format: {}", principal_str),
        })?;

    Ok(SignerEntry {
        principal,
        public_key,
        source,
    })
}

fn parse_principal(s: &str) -> Option<SignerPrincipal> {
    if let Some(local) = s.strip_suffix("@auths.local") {
        let did_str = format!("did:key:{}", local);
        if let Ok(did) = DeviceDID::parse(&did_str) {
            return Some(SignerPrincipal::DeviceDid(did));
        }
    }
    if let Ok(did) = DeviceDID::parse(s) {
        return Some(SignerPrincipal::DeviceDid(did));
    }
    if let Ok(addr) = EmailAddress::new(s) {
        return Some(SignerPrincipal::Email(addr));
    }
    None
}

fn format_entry(entry: &SignerEntry) -> String {
    #[allow(clippy::expect_used)] // INVARIANT: VerifierEd25519 is always 32 valid bytes
    let ssh_key = public_key_to_ssh(entry.public_key.as_ref())
        .expect("VerifierEd25519 always encodes to valid SSH key");
    format!("{} namespaces=\"git\" {}", entry.principal, ssh_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_valid() {
        assert!(EmailAddress::new("user@example.com").is_ok());
        assert!(EmailAddress::new("a@b.co").is_ok());
        assert!(EmailAddress::new("test+tag@domain.org").is_ok());
    }

    #[test]
    fn email_invalid() {
        assert!(EmailAddress::new("").is_err());
        assert!(EmailAddress::new("@").is_err());
        assert!(EmailAddress::new("user@").is_err());
        assert!(EmailAddress::new("@domain.com").is_err());
        assert!(EmailAddress::new("user@domain").is_err());
        assert!(EmailAddress::new("invalid").is_err());
    }

    #[test]
    fn email_injection_defense() {
        assert!(EmailAddress::new("a\0b@evil.com").is_err());
        assert!(EmailAddress::new("a\n@evil.com").is_err());
        assert!(EmailAddress::new("a b@evil.com").is_err());
    }

    #[test]
    fn principal_display_email() {
        let p = SignerPrincipal::Email(EmailAddress::new("user@example.com").unwrap());
        assert_eq!(p.to_string(), "user@example.com");
    }

    #[test]
    fn principal_display_did() {
        #[allow(clippy::disallowed_methods)]
        // INVARIANT: test-only literal with valid did:key: prefix
        let did = DeviceDID::new_unchecked("did:key:z6MkTest123");
        let p = SignerPrincipal::DeviceDid(did);
        assert_eq!(p.to_string(), "z6MkTest123@auths.local");
    }

    #[test]
    fn principal_roundtrip() {
        let email_p = SignerPrincipal::Email(EmailAddress::new("user@example.com").unwrap());
        let parsed = parse_principal(&email_p.to_string()).unwrap();
        assert_eq!(parsed, email_p);

        #[allow(clippy::disallowed_methods)]
        // INVARIANT: test-only literal with valid did:key: prefix
        let did = DeviceDID::new_unchecked("did:key:z6MkTest123");
        let did_p = SignerPrincipal::DeviceDid(did);
        let parsed = parse_principal(&did_p.to_string()).unwrap();
        assert_eq!(parsed, did_p);
    }

    #[test]
    fn error_codes_and_suggestions() {
        let err = AllowedSignersError::InvalidEmail("test".to_string());
        assert_eq!(err.error_code(), "AUTHS-E5801");
        assert!(err.suggestion().is_some());
    }
}
