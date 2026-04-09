//! Signing pipeline orchestration.
//!
//! Composed pipeline: validate freeze → sign data → format SSHSIG.
//! Agent communication and passphrase prompting remain in the CLI.

use crate::context::AuthsContext;
use crate::ports::artifact::{ArtifactDigest, ArtifactMetadata, ArtifactSource};
use auths_core::crypto::ssh::{self, SecureSeed};
use auths_core::crypto::{provider_bridge, signer as core_signer};
use auths_core::signing::{PassphraseProvider, SecureSigner};
use auths_core::storage::keychain::{IdentityDID, KeyAlias, KeyStorage};
use auths_id::attestation::core::resign_attestation;
use auths_id::attestation::create::create_signed_attestation;
use auths_id::storage::git_refs::AttestationMetadata;
use auths_verifier::core::{Capability, ResourceId, SignerType};
use auths_verifier::types::DeviceDID;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Errors from the signing pipeline.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SigningError {
    /// The identity is in a freeze state and signing is not permitted.
    #[error("identity is frozen: {0}")]
    IdentityFrozen(String),
    /// The requested key alias could not be resolved from the keychain.
    #[error("key resolution failed: {0}")]
    KeyResolution(String),
    /// The cryptographic signing operation failed.
    #[error("signing operation failed: {0}")]
    SigningFailed(String),
    /// The supplied passphrase was incorrect.
    #[error("invalid passphrase")]
    InvalidPassphrase,
    /// SSHSIG PEM encoding failed after signing.
    #[error("PEM encoding failed: {0}")]
    PemEncoding(String),
    /// The agent is not available (platform unsupported, not installed, or not reachable).
    #[error("agent unavailable: {0}")]
    AgentUnavailable(String),
    /// The agent accepted the signing request but it failed.
    #[error("agent signing failed")]
    AgentSigningFailed(#[source] crate::ports::agent::AgentSigningError),
    /// All passphrase attempts were exhausted without a successful decryption.
    #[error("passphrase exhausted after {attempts} attempt(s)")]
    PassphraseExhausted {
        /// Number of failed attempts before giving up.
        attempts: usize,
    },
    /// The platform keychain could not be accessed.
    #[error("keychain unavailable: {0}")]
    KeychainUnavailable(String),
    /// The encrypted key material could not be decrypted.
    #[error("key decryption failed: {0}")]
    KeyDecryptionFailed(String),
}

impl auths_core::error::AuthsErrorInfo for SigningError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::IdentityFrozen(_) => "AUTHS-E5901",
            Self::KeyResolution(_) => "AUTHS-E5902",
            Self::SigningFailed(_) => "AUTHS-E5903",
            Self::InvalidPassphrase => "AUTHS-E5904",
            Self::PemEncoding(_) => "AUTHS-E5905",
            Self::AgentUnavailable(_) => "AUTHS-E5906",
            Self::AgentSigningFailed(_) => "AUTHS-E5907",
            Self::PassphraseExhausted { .. } => "AUTHS-E5908",
            Self::KeychainUnavailable(_) => "AUTHS-E5909",
            Self::KeyDecryptionFailed(_) => "AUTHS-E5910",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::IdentityFrozen(_) => Some("To unfreeze: auths emergency unfreeze"),
            Self::KeyResolution(_) => Some("Run `auths key list` to check available keys"),
            Self::SigningFailed(_) => Some(
                "The signing operation failed; verify your key is accessible with `auths key list`",
            ),
            Self::InvalidPassphrase => Some("Check your passphrase and try again"),
            Self::PemEncoding(_) => {
                Some("Failed to encode the key in PEM format; the key material may be corrupted")
            }
            Self::AgentUnavailable(_) => Some("Start the agent with `auths agent start`"),
            Self::AgentSigningFailed(_) => Some("Check agent logs with `auths agent status`"),
            Self::PassphraseExhausted { .. } => Some(
                "The passphrase you entered is incorrect (tried 3 times). Verify it matches what you set during init, or try: auths key export --key-alias <alias> --format pub",
            ),
            Self::KeychainUnavailable(_) => Some("Run `auths doctor` to diagnose keychain issues"),
            Self::KeyDecryptionFailed(_) => Some("Check your passphrase and try again"),
        }
    }
}

/// Configuration for a signing operation.
///
/// Args:
/// * `namespace`: The SSHSIG namespace (typically "git").
///
/// Usage:
/// ```ignore
/// let config = SigningConfig {
///     namespace: "git".to_string(),
/// };
/// ```
pub struct SigningConfig {
    /// SSHSIG namespace string (e.g. `"git"` for commit signing).
    pub namespace: String,
}

/// Validate that the identity is not frozen.
///
/// Args:
/// * `repo_path`: Path to the auths repository (typically `~/.auths`).
/// * `now`: The reference time used to check if the freeze is active.
///
/// Usage:
/// ```ignore
/// validate_freeze_state(&repo_path, clock.now())?;
/// ```
pub fn validate_freeze_state(
    repo_path: &Path,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), SigningError> {
    use auths_id::freeze::load_active_freeze;

    if let Some(state) = load_active_freeze(repo_path, now)
        .map_err(|e| SigningError::IdentityFrozen(e.to_string()))?
    {
        return Err(SigningError::IdentityFrozen(format!(
            "frozen until {}. Remaining: {}. To unfreeze: auths emergency unfreeze",
            state.frozen_until.format("%Y-%m-%d %H:%M UTC"),
            state.expires_description(now),
        )));
    }

    Ok(())
}

/// Construct the SSHSIG signed-data payload for the given data and namespace.
///
/// Args:
/// * `data`: The raw bytes to sign.
/// * `namespace`: The SSHSIG namespace (e.g. "git").
///
/// Usage:
/// ```ignore
/// let payload = construct_signature_payload(b"data", "git")?;
/// ```
pub fn construct_signature_payload(data: &[u8], namespace: &str) -> Result<Vec<u8>, SigningError> {
    ssh::construct_sshsig_signed_data(data, namespace)
        .map_err(|e| SigningError::SigningFailed(e.to_string()))
}

/// Create a complete SSHSIG PEM signature from a seed and data.
///
/// Args:
/// * `seed`: The Ed25519 signing seed.
/// * `data`: The raw bytes to sign.
/// * `namespace`: The SSHSIG namespace.
///
/// Usage:
/// ```ignore
/// let pem = sign_with_seed(&seed, b"data to sign", "git")?;
/// ```
pub fn sign_with_seed(
    seed: &SecureSeed,
    data: &[u8],
    namespace: &str,
) -> Result<String, SigningError> {
    ssh::create_sshsig(seed, data, namespace).map_err(|e| SigningError::PemEncoding(e.to_string()))
}

// ---------------------------------------------------------------------------
// Artifact attestation signing
// ---------------------------------------------------------------------------

/// Selects how a signing key is supplied to `sign_artifact`.
///
/// `Alias` resolves the key from the platform keychain at call time.
/// `Direct` injects a raw seed, bypassing the keychain — intended for headless
/// CI/CD runners that have no platform keychain available.
pub enum SigningKeyMaterial {
    /// Resolve by alias from the platform keychain.
    Alias(KeyAlias),
    /// Inject a raw Ed25519 seed directly. The passphrase provider is not called.
    Direct(SecureSeed),
}

/// Parameters for the artifact attestation signing workflow.
///
/// Usage:
/// ```ignore
/// let params = ArtifactSigningParams {
///     artifact: Arc::new(my_artifact),
///     identity_key: Some(SigningKeyMaterial::Alias("my-identity".into())),
///     device_key: SigningKeyMaterial::Direct(my_seed),
///     expires_in: Some(31_536_000),
///     note: None,
///     commit_sha: None,
/// };
/// ```
pub struct ArtifactSigningParams {
    /// The artifact to attest. Provides the canonical digest and metadata.
    pub artifact: Arc<dyn ArtifactSource>,
    /// Identity key source. `None` skips the identity signature.
    pub identity_key: Option<SigningKeyMaterial>,
    /// Device key source. Required to produce a dual-signed attestation.
    pub device_key: SigningKeyMaterial,
    /// Duration in seconds until expiration (per RFC 6749).
    pub expires_in: Option<u64>,
    /// Optional human-readable annotation embedded in the attestation.
    pub note: Option<String>,
    /// Git commit SHA for provenance binding (included in signed canonical data).
    pub commit_sha: Option<String>,
}

/// Result of a successful artifact attestation signing operation.
///
/// Usage:
/// ```ignore
/// let result = sign_artifact(params, &ctx)?;
/// std::fs::write(&output_path, &result.attestation_json)?;
/// println!("Signed {} (sha256:{})", result.rid, result.digest);
/// ```
#[derive(Debug)]
pub struct ArtifactSigningResult {
    /// Canonical JSON of the signed attestation.
    pub attestation_json: String,
    /// Resource identifier assigned to the attestation in the identity store.
    pub rid: ResourceId,
    /// Hex-encoded SHA-256 digest of the attested artifact.
    pub digest: String,
}

/// Errors from the artifact attestation signing workflow.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ArtifactSigningError {
    /// No auths identity was found in the configured identity storage.
    #[error("identity not found in configured identity storage")]
    IdentityNotFound,

    /// The key alias could not be resolved to usable key material.
    #[error("key resolution failed: {0}")]
    KeyResolutionFailed(String),

    /// The encrypted key material could not be decrypted (e.g. wrong passphrase).
    #[error("key decryption failed: {0}")]
    KeyDecryptionFailed(String),

    /// Computing the artifact digest failed.
    #[error("digest computation failed: {0}")]
    DigestFailed(String),

    /// Building or serializing the attestation failed.
    #[error("attestation creation failed: {0}")]
    AttestationFailed(String),

    /// Adding the device signature to a partially-signed attestation failed.
    #[error("attestation re-signing failed: {0}")]
    ResignFailed(String),

    /// The provided commit SHA has an invalid format.
    #[error("invalid commit SHA: {0} (expected 40 or 64 hex characters)")]
    InvalidCommitSha(String),
}

impl auths_core::error::AuthsErrorInfo for ArtifactSigningError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::IdentityNotFound => "AUTHS-E5850",
            Self::KeyResolutionFailed(_) => "AUTHS-E5851",
            Self::KeyDecryptionFailed(_) => "AUTHS-E5852",
            Self::DigestFailed(_) => "AUTHS-E5853",
            Self::AttestationFailed(_) => "AUTHS-E5854",
            Self::ResignFailed(_) => "AUTHS-E5855",
            Self::InvalidCommitSha(_) => "AUTHS-E5856",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::IdentityNotFound => {
                Some("Run `auths init` to create an identity, or `auths key import` to restore one")
            }
            Self::KeyResolutionFailed(_) => {
                Some("Run `auths status` to see available device aliases")
            }
            Self::KeyDecryptionFailed(_) => Some("Check your passphrase and try again"),
            Self::DigestFailed(_) => Some("Verify the file exists and is readable"),
            Self::AttestationFailed(_) => Some("Check identity storage with `auths status`"),
            Self::ResignFailed(_) => {
                Some("Verify your device key is accessible with `auths status`")
            }
            Self::InvalidCommitSha(_) => {
                Some("Provide a full SHA-1 (40 hex chars) or SHA-256 (64 hex chars) commit hash")
            }
        }
    }
}

/// A `SecureSigner` backed by pre-resolved in-memory seeds.
///
/// Seeds are keyed by alias. The passphrase provider is never called because
/// all key material was resolved before construction.
struct SeedMapSigner {
    seeds: HashMap<String, SecureSeed>,
}

impl SecureSigner for SeedMapSigner {
    fn sign_with_alias(
        &self,
        alias: &auths_core::storage::keychain::KeyAlias,
        _passphrase_provider: &dyn PassphraseProvider,
        message: &[u8],
    ) -> Result<Vec<u8>, auths_core::AgentError> {
        let seed = self
            .seeds
            .get(alias.as_str())
            .ok_or(auths_core::AgentError::KeyNotFound)?;
        provider_bridge::sign_ed25519_sync(seed, message)
            .map_err(|e| auths_core::AgentError::CryptoError(e.to_string()))
    }

    fn sign_for_identity(
        &self,
        _identity_did: &IdentityDID,
        _passphrase_provider: &dyn PassphraseProvider,
        _message: &[u8],
    ) -> Result<Vec<u8>, auths_core::AgentError> {
        Err(auths_core::AgentError::KeyNotFound)
    }
}

struct ResolvedKey {
    alias: KeyAlias,
    seed: SecureSeed,
    public_key_bytes: Vec<u8>,
}

fn resolve_optional_key(
    material: Option<&SigningKeyMaterial>,
    synthetic_alias: &'static str,
    keychain: &(dyn KeyStorage + Send + Sync),
    passphrase_provider: &dyn PassphraseProvider,
    passphrase_prompt: &str,
) -> Result<Option<ResolvedKey>, ArtifactSigningError> {
    match material {
        None => Ok(None),
        Some(SigningKeyMaterial::Alias(alias)) => {
            let (_, _role, encrypted) = keychain
                .load_key(alias)
                .map_err(|e| ArtifactSigningError::KeyResolutionFailed(e.to_string()))?;
            let passphrase = passphrase_provider
                .get_passphrase(passphrase_prompt)
                .map_err(|e| ArtifactSigningError::KeyDecryptionFailed(e.to_string()))?;
            let pkcs8 = core_signer::decrypt_keypair(&encrypted, &passphrase)
                .map_err(|e| ArtifactSigningError::KeyDecryptionFailed(e.to_string()))?;
            let (seed, pubkey) = core_signer::load_seed_and_pubkey(&pkcs8)
                .map_err(|e| ArtifactSigningError::KeyDecryptionFailed(e.to_string()))?;
            Ok(Some(ResolvedKey {
                alias: alias.clone(),
                seed,
                public_key_bytes: pubkey.to_vec(),
            }))
        }
        Some(SigningKeyMaterial::Direct(seed)) => {
            let pubkey = provider_bridge::ed25519_public_key_from_seed_sync(seed)
                .map_err(|e| ArtifactSigningError::KeyDecryptionFailed(e.to_string()))?;
            Ok(Some(ResolvedKey {
                alias: KeyAlias::new_unchecked(synthetic_alias),
                seed: SecureSeed::new(*seed.as_bytes()),
                public_key_bytes: pubkey.to_vec(),
            }))
        }
    }
}

fn resolve_required_key(
    material: &SigningKeyMaterial,
    synthetic_alias: &'static str,
    keychain: &(dyn KeyStorage + Send + Sync),
    passphrase_provider: &dyn PassphraseProvider,
    passphrase_prompt: &str,
) -> Result<ResolvedKey, ArtifactSigningError> {
    resolve_optional_key(
        Some(material),
        synthetic_alias,
        keychain,
        passphrase_provider,
        passphrase_prompt,
    )
    .map(|opt| {
        opt.ok_or(ArtifactSigningError::KeyDecryptionFailed(
            "expected key material but got None".into(),
        ))
    })?
}

/// Validate and normalize a commit SHA (40-char SHA-1 or 64-char SHA-256).
///
/// Args:
/// * `sha`: The raw commit SHA string to validate.
///
/// Usage:
/// ```ignore
/// let normalized = validate_commit_sha("AbCd1234...")?;
/// ```
pub fn validate_commit_sha(sha: &str) -> Result<String, ArtifactSigningError> {
    let normalized = sha.to_ascii_lowercase();
    let len = normalized.len();
    if (len != 40 && len != 64) || !normalized.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ArtifactSigningError::InvalidCommitSha(sha.to_string()));
    }
    Ok(normalized)
}

/// Full artifact attestation signing pipeline.
///
/// Loads the identity, resolves key material (supporting both keychain aliases
/// and direct in-memory seed injection), computes the artifact digest, and
/// produces a dual-signed attestation JSON.
///
/// Args:
/// * `params`: All inputs required for signing, including key material and artifact source.
/// * `ctx`: Runtime context providing identity storage, key storage, passphrase provider, and clock.
///
/// Usage:
/// ```ignore
/// let params = ArtifactSigningParams {
///     artifact: Arc::new(FileArtifact::new(Path::new("release.tar.gz"))),
///     identity_key: Some(SigningKeyMaterial::Alias("my-key".into())),
///     device_key: SigningKeyMaterial::Direct(seed),
///     expires_in: Some(31_536_000),
///     note: None,
///     commit_sha: None,
/// };
/// let result = sign_artifact(params, &ctx)?;
/// ```
pub fn sign_artifact(
    params: ArtifactSigningParams,
    ctx: &AuthsContext,
) -> Result<ArtifactSigningResult, ArtifactSigningError> {
    let managed = ctx
        .identity_storage
        .load_identity()
        .map_err(|_| ArtifactSigningError::IdentityNotFound)?;

    let keychain = ctx.key_storage.as_ref();
    let passphrase_provider = ctx.passphrase_provider.as_ref();

    let identity_resolved = resolve_optional_key(
        params.identity_key.as_ref(),
        "__artifact_identity__",
        keychain,
        passphrase_provider,
        "Enter passphrase for identity key:",
    )?;

    let device_resolved = resolve_required_key(
        &params.device_key,
        "__artifact_device__",
        keychain,
        passphrase_provider,
        "Enter passphrase for device key:",
    )?;

    let mut seeds: HashMap<String, SecureSeed> = HashMap::new();
    let identity_alias: Option<KeyAlias> = identity_resolved.map(|r| {
        let alias = r.alias.clone();
        seeds.insert(r.alias.into_inner(), r.seed);
        alias
    });
    let device_alias = device_resolved.alias.clone();
    seeds.insert(device_resolved.alias.into_inner(), device_resolved.seed);
    let device_pk_bytes = device_resolved.public_key_bytes;

    let device_did =
        DeviceDID::from_ed25519(device_pk_bytes.as_slice().try_into().map_err(|_| {
            ArtifactSigningError::AttestationFailed("device public key must be 32 bytes".into())
        })?);

    let artifact_meta = params
        .artifact
        .metadata()
        .map_err(|e| ArtifactSigningError::DigestFailed(e.to_string()))?;

    let rid = ResourceId::new(format!("sha256:{}", artifact_meta.digest.hex));
    let now = ctx.clock.now();
    let meta = AttestationMetadata {
        timestamp: Some(now),
        expires_at: params
            .expires_in
            .map(|s| now + chrono::Duration::seconds(s as i64)),
        note: params.note,
    };

    let payload = serde_json::to_value(&artifact_meta)
        .map_err(|e| ArtifactSigningError::AttestationFailed(e.to_string()))?;

    let validated_commit_sha = params
        .commit_sha
        .map(|sha| validate_commit_sha(&sha))
        .transpose()?;

    let signer = SeedMapSigner { seeds };
    // Seeds are already resolved — passphrase provider will not be called.
    let noop_provider = auths_core::PrefilledPassphraseProvider::new("");

    let mut attestation = create_signed_attestation(
        now,
        &rid,
        &managed.controller_did,
        &device_did,
        &device_pk_bytes,
        Some(payload),
        &meta,
        &signer,
        &noop_provider,
        identity_alias.as_ref(),
        Some(&device_alias),
        vec![Capability::sign_release()],
        None,
        None,
        validated_commit_sha,
        None,
    )
    .map_err(|e| ArtifactSigningError::AttestationFailed(e.to_string()))?;

    resign_attestation(
        &mut attestation,
        &signer,
        &noop_provider,
        identity_alias.as_ref(),
        &device_alias,
    )
    .map_err(|e| ArtifactSigningError::ResignFailed(e.to_string()))?;

    let attestation_json = serde_json::to_string_pretty(&attestation)
        .map_err(|e| ArtifactSigningError::AttestationFailed(e.to_string()))?;

    Ok(ArtifactSigningResult {
        attestation_json,
        rid,
        digest: artifact_meta.digest.hex,
    })
}

/// Signs artifact bytes with a one-time ephemeral Ed25519 key. No keychain, no
/// identity storage, no passphrase — the key is generated, used, and zeroized
/// within this function call.
///
/// The ephemeral key signs "this artifact was built from this commit." Trust
/// derives transitively: consumers verify the commit is signed by a maintainer,
/// then verify this attestation's ephemeral signature covers the artifact hash
/// and commit SHA.
///
/// Args:
/// * `now` - Current UTC time (injected per clock pattern).
/// * `data` - Raw artifact bytes to sign.
/// * `artifact_name` - Optional human-readable name for the artifact.
/// * `commit_sha` - Git commit SHA this artifact was built from (required, 40 or 64 hex chars).
/// * `expires_in` - Optional TTL in seconds.
/// * `note` - Optional attestation note.
/// * `ci_env` - Optional CI environment metadata (serialized into payload, covered by signature).
///
/// Usage:
/// ```ignore
/// let result = sign_artifact_ephemeral(
///     Utc::now(), b"artifact bytes", Some("release.tar.gz".into()),
///     "abc123def456abc123def456abc123def456abc1".into(), None, None, None,
/// )?;
/// ```
pub fn sign_artifact_ephemeral(
    now: DateTime<Utc>,
    data: &[u8],
    artifact_name: Option<String>,
    commit_sha: String,
    expires_in: Option<u64>,
    note: Option<String>,
    ci_env: Option<serde_json::Value>,
) -> Result<ArtifactSigningResult, ArtifactSigningError> {
    // 1. Generate ephemeral seed and zeroize on drop
    let mut seed_bytes = Zeroizing::new([0u8; 32]);
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), seed_bytes.as_mut())
        .map_err(|_| ArtifactSigningError::AttestationFailed("RNG failure".into()))?;

    let seed = SecureSeed::new(*seed_bytes);

    // 2. Derive pubkey and DIDs
    let pubkey = provider_bridge::ed25519_public_key_from_seed_sync(&seed)
        .map_err(|e| ArtifactSigningError::AttestationFailed(e.to_string()))?;

    let device_did = DeviceDID::from_ed25519(&pubkey);
    #[allow(clippy::disallowed_methods)]
    let identity_did = IdentityDID::new_unchecked(device_did.as_str());

    // 3. Build artifact metadata with optional CI environment in payload
    let digest_hex = hex::encode(Sha256::digest(data));
    let artifact_meta = ArtifactMetadata {
        artifact_type: "file".to_string(),
        digest: ArtifactDigest {
            algorithm: "sha256".to_string(),
            hex: digest_hex,
        },
        name: artifact_name,
        size: Some(data.len() as u64),
    };

    let mut payload_value = serde_json::to_value(&artifact_meta)
        .map_err(|e| ArtifactSigningError::AttestationFailed(e.to_string()))?;

    if let Some(env) = ci_env
        && let serde_json::Value::Object(ref mut map) = payload_value
    {
        map.insert("ci_environment".to_string(), env);
    }

    let rid = ResourceId::new(format!("sha256:{}", artifact_meta.digest.hex));
    let meta = AttestationMetadata {
        timestamp: Some(now),
        expires_at: expires_in.map(|s| now + chrono::Duration::seconds(s as i64)),
        note,
    };

    // 4. Validate commit SHA
    let validated_sha = validate_commit_sha(&commit_sha)?;

    // 5. Set up ephemeral signer
    let identity_alias = KeyAlias::new_unchecked("__ephemeral_identity__");
    let device_alias = KeyAlias::new_unchecked("__ephemeral_device__");

    let mut seeds: HashMap<String, SecureSeed> = HashMap::new();
    seeds.insert(
        identity_alias.as_str().to_string(),
        SecureSeed::new(*seed_bytes),
    );
    seeds.insert(
        device_alias.as_str().to_string(),
        SecureSeed::new(*seed_bytes),
    );
    let signer = SeedMapSigner { seeds };
    let noop_provider = auths_core::PrefilledPassphraseProvider::new("");

    // 6. Create signed attestation with Workload signer type
    let attestation = create_signed_attestation(
        now,
        &rid,
        &identity_did,
        &device_did,
        &pubkey,
        Some(payload_value),
        &meta,
        &signer,
        &noop_provider,
        Some(&identity_alias),
        Some(&device_alias),
        vec![Capability::sign_release()],
        None,
        None,
        Some(validated_sha),
        Some(SignerType::Workload),
    )
    .map_err(|e| ArtifactSigningError::AttestationFailed(e.to_string()))?;

    let attestation_json = serde_json::to_string_pretty(&attestation)
        .map_err(|e| ArtifactSigningError::AttestationFailed(e.to_string()))?;

    Ok(ArtifactSigningResult {
        attestation_json,
        rid,
        digest: artifact_meta.digest.hex,
    })
}

/// Signs artifact bytes with a raw Ed25519 seed, bypassing keychain and identity storage.
///
/// This is the raw-key equivalent of [`sign_artifact`]. It does not require an
/// [`AuthsContext`] or any filesystem/keychain access. The same seed is used for
/// both identity and device signing roles.
///
/// Args:
/// * `now` - Current UTC time (injected per clock pattern).
/// * `seed` - Ed25519 32-byte seed.
/// * `identity_did` - Parsed identity DID (must be `did:keri:` — caller validates via `IdentityDID::parse()`).
/// * `data` - Raw artifact bytes to sign.
/// * `expires_in` - Optional TTL in seconds.
/// * `note` - Optional attestation note.
/// * `commit_sha` - Optional git commit SHA for provenance binding (40 or 64 hex chars).
///
/// Usage:
/// ```ignore
/// let did = IdentityDID::parse("did:keri:E...")?;
/// let result = sign_artifact_raw(Utc::now(), &seed, &did, b"payload", None, None, None)?;
/// ```
pub fn sign_artifact_raw(
    now: DateTime<Utc>,
    seed: &SecureSeed,
    identity_did: &IdentityDID,
    data: &[u8],
    expires_in: Option<u64>,
    note: Option<String>,
    commit_sha: Option<String>,
) -> Result<ArtifactSigningResult, ArtifactSigningError> {
    let pubkey = provider_bridge::ed25519_public_key_from_seed_sync(seed)
        .map_err(|e| ArtifactSigningError::AttestationFailed(e.to_string()))?;

    let device_did = DeviceDID::from_ed25519(&pubkey);

    let digest_hex = hex::encode(Sha256::digest(data));
    let artifact_meta = ArtifactMetadata {
        artifact_type: "bytes".to_string(),
        digest: ArtifactDigest {
            algorithm: "sha256".to_string(),
            hex: digest_hex,
        },
        name: None,
        size: Some(data.len() as u64),
    };

    let rid = ResourceId::new(format!("sha256:{}", artifact_meta.digest.hex));
    let meta = AttestationMetadata {
        timestamp: Some(now),
        expires_at: expires_in.map(|s| now + chrono::Duration::seconds(s as i64)),
        note,
    };

    let payload = serde_json::to_value(&artifact_meta)
        .map_err(|e| ArtifactSigningError::AttestationFailed(e.to_string()))?;

    let identity_alias = KeyAlias::new_unchecked("__raw_identity__");
    let device_alias = KeyAlias::new_unchecked("__raw_device__");

    let mut seeds: HashMap<String, SecureSeed> = HashMap::new();
    seeds.insert(
        identity_alias.as_str().to_string(),
        SecureSeed::new(*seed.as_bytes()),
    );
    seeds.insert(
        device_alias.as_str().to_string(),
        SecureSeed::new(*seed.as_bytes()),
    );
    let signer = SeedMapSigner { seeds };
    // Seeds are already resolved — passphrase provider will not be called.
    let noop_provider = auths_core::PrefilledPassphraseProvider::new("");

    let validated_commit_sha = commit_sha
        .map(|sha| validate_commit_sha(&sha))
        .transpose()?;

    let attestation = create_signed_attestation(
        now,
        &rid,
        identity_did,
        &device_did,
        &pubkey,
        Some(payload),
        &meta,
        &signer,
        &noop_provider,
        Some(&identity_alias),
        Some(&device_alias),
        vec![Capability::sign_release()],
        None,
        None,
        validated_commit_sha,
        None,
    )
    .map_err(|e| ArtifactSigningError::AttestationFailed(e.to_string()))?;

    let attestation_json = serde_json::to_string_pretty(&attestation)
        .map_err(|e| ArtifactSigningError::AttestationFailed(e.to_string()))?;

    Ok(ArtifactSigningResult {
        attestation_json,
        rid,
        digest: artifact_meta.digest.hex,
    })
}
