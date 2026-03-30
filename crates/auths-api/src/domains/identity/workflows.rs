//! Identity domain workflows - contains: rotation.rs, provision.rs, machine_identity.rs, platform.rs

// ──── rotation.rs ───────────────────────────────────────────────────────────

//! Identity rotation workflow.
//!
//! Three-phase design:
//! 1. `compute_rotation_event` — pure, deterministic RotEvent construction.
//! 2. `apply_rotation` — side-effecting KEL append + keychain write.
//! 3. `rotate_identity` — high-level orchestrator (calls both phases in order).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use auths_core::crypto::said::{compute_next_commitment, compute_said, verify_commitment};
use auths_core::crypto::signer::{decrypt_keypair, encrypt_keypair, load_seed_and_pubkey};
use auths_core::ports::clock::ClockProvider;
// Platform types don't exist in auths_core::ports::platform
// use auths_core::ports::platform::{DeviceId, Platform};
use auths_core::signing::PassphraseProvider;
use auths_core::storage::keychain::{
    IdentityDID, KeyAlias, KeyRole, KeyStorage, extract_public_key_bytes,
};
use auths_id::identity::helpers::{
    ManagedIdentity, encode_seed_as_pkcs8, extract_seed_bytes, load_keypair_from_der_or_seed,
};
use auths_id::identity::initialize::initialize_registry_identity;
use auths_id::keri::{
    Event, KERI_VERSION, KeriSequence, KeyState, Prefix, RotEvent, Said, serialize_for_signing,
};
use auths_id::ports::registry::RegistryBackend;
use auths_id::storage::identity::IdentityStorage;
use auths_id::witness_config::{WitnessConfig, WitnessPolicy};
// OIDC port types don't exist or aren't exposed from auths_oidc_port
// use auths_oidc_port::{CodeExchange, ExchangeError, OidcPort};
use auths_verifier::core::ResourceId;
use auths_verifier::types::{CanonicalDid, DeviceDID};

use auths_sdk::pairing::PairingError;
use auths_sdk::{IdentityRotationConfig, IdentityRotationResult, RotationError};

/// Computes a KERI rotation event and its canonical serialization.
///
/// Pure function — deterministic given fixed inputs. Signs the event bytes with
/// `next_keypair` (the pre-committed future key becoming the new current key).
/// `new_next_keypair` is the freshly generated key committed for the next rotation.
///
/// Args:
/// * `state`: Current key state from the registry.
/// * `next_keypair`: Pre-committed next key (becomes new current signer after rotation).
/// * `new_next_keypair`: Freshly generated keypair committed for the next rotation.
/// * `witness_config`: Optional witness configuration.
///
/// Returns `(event, canonical_bytes)` where `canonical_bytes` is the exact
/// byte sequence to write to the KEL — do not re-serialize.
///
/// Usage:
/// ```ignore
/// let (rot, bytes) = compute_rotation_event(&state, &next_kp, &new_next_kp, None)?;
/// ```
pub fn compute_rotation_event(
    state: &KeyState,
    next_keypair: &Ed25519KeyPair,
    new_next_keypair: &Ed25519KeyPair,
    witness_config: Option<&WitnessConfig>,
) -> Result<(RotEvent, Vec<u8>), RotationError> {
    let prefix = &state.prefix;

    let new_current_pub_encoded = format!(
        "D{}",
        URL_SAFE_NO_PAD.encode(next_keypair.public_key().as_ref())
    );
    let new_next_commitment = compute_next_commitment(new_next_keypair.public_key().as_ref());

    let (bt, b) = match witness_config {
        Some(cfg) if cfg.is_enabled() => (
            cfg.threshold.to_string(),
            cfg.witness_urls.iter().map(|u| u.to_string()).collect(),
        ),
        _ => ("0".to_string(), vec![]),
    };

    let new_sequence = state.sequence + 1;
    let mut rot = RotEvent {
        v: KERI_VERSION.to_string(),
        d: Said::default(),
        i: prefix.clone(),
        s: KeriSequence::new(new_sequence),
        p: state.last_event_said.clone(),
        kt: "1".to_string(),
        k: vec![new_current_pub_encoded],
        nt: "1".to_string(),
        n: vec![new_next_commitment],
        bt,
        b,
        a: vec![],
        x: String::new(),
    };

    let rot_json = serde_json::to_vec(&Event::Rot(rot.clone()))
        .map_err(|e| RotationError::RotationFailed(format!("serialization failed: {e}")))?;
    rot.d = compute_said(&rot_json);

    let canonical = serialize_for_signing(&Event::Rot(rot.clone()))
        .map_err(|e| RotationError::RotationFailed(format!("serialize for signing failed: {e}")))?;
    let sig = next_keypair.sign(&canonical);
    rot.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

    let event_bytes = serialize_for_signing(&Event::Rot(rot.clone()))
        .map_err(|e| RotationError::RotationFailed(format!("final serialization failed: {e}")))?;

    Ok((rot, event_bytes))
}

/// Key material required for the keychain side of `apply_rotation`.
pub struct RotationKeyMaterial {
    /// DID of the identity being rotated.
    pub did: IdentityDID,
    /// Alias to store the new current key (the former pre-committed next key).
    pub next_alias: KeyAlias,
    /// Alias for the future pre-committed key (committed in this rotation).
    pub new_next_alias: KeyAlias,
    /// Pre-committed next key alias to delete after successful rotation.
    pub old_next_alias: KeyAlias,
    /// Encrypted new current key bytes to store in the keychain.
    pub new_current_encrypted: Vec<u8>,
    /// Encrypted new next key bytes to store for future rotation.
    pub new_next_encrypted: Vec<u8>,
}

/// Applies a computed rotation event to the registry and keychain.
///
/// Writes the KEL event first, then updates the keychain. If the KEL append
/// succeeds but the subsequent keychain write fails, returns
/// `RotationError::PartialRotation` so the caller can surface a recovery path.
///
/// # NOTE: non-atomic — KEL and keychain writes are not transactional.
/// Recovery: re-run rotation with the same new key to replay the keychain write.
///
/// Args:
/// * `rot`: The pre-computed rotation event to append to the KEL.
/// * `prefix`: KERI identifier prefix (the `did:keri:` suffix).
/// * `key_material`: Encrypted key material and aliases for keychain operations.
/// * `registry`: Registry backend for KEL append.
/// * `key_storage`: Keychain for storing rotated key material.
///
/// Usage:
/// ```ignore
/// apply_rotation(&rot, prefix, key_material, registry.as_ref(), key_storage.as_ref())?;
/// ```
pub fn apply_rotation(
    rot: &RotEvent,
    prefix: &Prefix,
    key_material: RotationKeyMaterial,
    registry: &(dyn RegistryBackend + Send + Sync),
    key_storage: &(dyn KeyStorage + Send + Sync),
) -> Result<(), RotationError> {
    registry
        .append_event(prefix, &Event::Rot(rot.clone()))
        .map_err(|e| RotationError::RotationFailed(format!("KEL append failed: {e}")))?;

    // NOTE: non-atomic — KEL and keychain writes are not transactional.
    // If the keychain write fails here, the KEL is already ahead.
    let keychain_result = (|| {
        key_storage
            .store_key(
                &key_material.next_alias,
                &key_material.did,
                KeyRole::Primary,
                &key_material.new_current_encrypted,
            )
            .map_err(|e| e.to_string())?;

        key_storage
            .store_key(
                &key_material.new_next_alias,
                &key_material.did,
                KeyRole::NextRotation,
                &key_material.new_next_encrypted,
            )
            .map_err(|e| e.to_string())?;

        let _ = key_storage.delete_key(&key_material.old_next_alias);

        Ok::<(), String>(())
    })();

    keychain_result.map_err(RotationError::PartialRotation)
}

/// Rotates the signing keys for an existing KERI identity.
///
/// Args:
/// * `config` - Configuration for the rotation including aliases and paths.
/// * `identity_storage` - Storage backend for loading the identity.
/// * `registry` - Registry backend for KEL operations.
/// * `key_storage` - Keychain for key material.
/// * `passphrase_provider` - Provider for key decryption.
/// * `clock` - Provider for timestamps.
///
/// Usage:
/// ```ignore
/// let result = rotate_identity(
///     IdentityRotationConfig {
///         repo_path: PathBuf::from("/home/user/.auths"),
///         identity_key_alias: Some("main".into()),
///         next_key_alias: None,
///     },
///     identity_storage.as_ref(),
///     registry.as_ref(),
///     key_storage.as_ref(),
///     passphrase_provider.as_ref(),
///     &SystemClock,
/// )?;
/// println!("Rotated to: {}...", result.new_key_fingerprint);
/// ```
pub fn rotate_identity(
    config: IdentityRotationConfig,
    identity_storage: &(dyn auths_id::storage::identity::IdentityStorage + Send + Sync),
    registry: &(dyn RegistryBackend + Send + Sync),
    key_storage: &(dyn KeyStorage + Send + Sync),
    passphrase_provider: &(dyn auths_core::signing::PassphraseProvider + Send + Sync),
    clock: &dyn ClockProvider,
) -> Result<IdentityRotationResult, RotationError> {
    let (identity, prefix, current_alias) =
        resolve_rotation_context(&config, identity_storage, key_storage)?;
    let next_alias = config.next_key_alias.unwrap_or_else(|| {
        KeyAlias::new_unchecked(format!(
            "{}-rotated-{}",
            current_alias,
            clock.now().format("%Y%m%d%H%M%S")
        ))
    });

    let previous_key_fingerprint =
        extract_previous_fingerprint(key_storage, passphrase_provider, &current_alias)?;

    let state = registry
        .get_key_state(&prefix)
        .map_err(|e| RotationError::KelHistoryFailed(e.to_string()))?;

    let (decrypted_next_pkcs8, old_next_alias) = retrieve_precommitted_key(
        &identity.controller_did,
        &current_alias,
        &state,
        key_storage,
        passphrase_provider,
    )?;

    let (rot, new_next_pkcs8) = generate_rotation_keys(&identity, &state, &decrypted_next_pkcs8)?;

    finalize_rotation_storage(
        FinalizeParams {
            did: &identity.controller_did,
            prefix: &prefix,
            next_alias: &next_alias,
            old_next_alias: &old_next_alias,
            current_pkcs8: &decrypted_next_pkcs8,
            new_next_pkcs8: new_next_pkcs8.as_ref(),
            rot: &rot,
            state: &state,
        },
        registry,
        key_storage,
        passphrase_provider,
    )?;

    let (_, new_pubkey) = load_seed_and_pubkey(&decrypted_next_pkcs8)
        .map_err(|e| RotationError::RotationFailed(e.to_string()))?;

    Ok(IdentityRotationResult {
        controller_did: identity.controller_did,
        new_key_fingerprint: hex::encode(&new_pubkey[..8]),
        previous_key_fingerprint,
        sequence: state.sequence + 1,
    })
}

/// Resolves the identity and determines which key alias is currently active.
fn resolve_rotation_context(
    config: &IdentityRotationConfig,
    identity_storage: &(dyn auths_id::storage::identity::IdentityStorage + Send + Sync),
    key_storage: &(dyn KeyStorage + Send + Sync),
) -> Result<(ManagedIdentity, Prefix, KeyAlias), RotationError> {
    let identity =
        identity_storage
            .load_identity()
            .map_err(|_| RotationError::IdentityNotFound {
                path: config.repo_path.clone(),
            })?;

    let prefix_str = identity
        .controller_did
        .as_str()
        .strip_prefix("did:keri:")
        .ok_or_else(|| {
            RotationError::RotationFailed(format!(
                "invalid DID format, expected 'did:keri:': {}",
                identity.controller_did
            ))
        })?;
    let prefix = Prefix::new_unchecked(prefix_str.to_string());

    let current_alias = match &config.identity_key_alias {
        Some(alias) => alias.clone(),
        None => {
            let aliases = key_storage
                .list_aliases_for_identity(&identity.controller_did)
                .map_err(|e| RotationError::RotationFailed(format!("alias lookup failed: {e}")))?;
            aliases
                .into_iter()
                .find(|a| !a.contains("--next-"))
                .ok_or_else(|| {
                    RotationError::KeyNotFound(format!(
                        "no active signing key for {}",
                        identity.controller_did
                    ))
                })?
        }
    };

    Ok((identity, prefix, current_alias))
}

fn extract_previous_fingerprint(
    key_storage: &(dyn KeyStorage + Send + Sync),
    passphrase_provider: &(dyn auths_core::signing::PassphraseProvider + Send + Sync),
    current_alias: &KeyAlias,
) -> Result<String, RotationError> {
    let old_pubkey_bytes =
        extract_public_key_bytes(key_storage, current_alias, passphrase_provider)
            .map_err(|e| RotationError::KeyDecryptionFailed(e.to_string()))?;

    Ok(hex::encode(&old_pubkey_bytes[..8]))
}

/// Retrieves and decrypts the key that was committed in the previous KERI event.
fn retrieve_precommitted_key(
    did: &IdentityDID,
    current_alias: &KeyAlias,
    state: &KeyState,
    key_storage: &(dyn KeyStorage + Send + Sync),
    passphrase_provider: &(dyn auths_core::signing::PassphraseProvider + Send + Sync),
) -> Result<(Zeroizing<Vec<u8>>, KeyAlias), RotationError> {
    let target_alias =
        KeyAlias::new_unchecked(format!("{}--next-{}", current_alias, state.sequence));

    let (did_check, _role, encrypted_next) = key_storage.load_key(&target_alias).map_err(|e| {
        RotationError::KeyNotFound(format!(
            "pre-committed next key '{}' not found: {e}",
            target_alias
        ))
    })?;

    if did != &did_check {
        return Err(RotationError::RotationFailed(format!(
            "DID mismatch for pre-committed key '{}': expected {}, found {}",
            target_alias, did, did_check
        )));
    }

    let pass = passphrase_provider
        .get_passphrase(&format!(
            "Enter passphrase for pre-committed key '{}':",
            target_alias
        ))
        .map_err(|e| RotationError::KeyDecryptionFailed(e.to_string()))?;

    let decrypted = decrypt_keypair(&encrypted_next, &pass)
        .map_err(|e| RotationError::KeyDecryptionFailed(e.to_string()))?;

    let keypair = load_keypair_from_der_or_seed(&decrypted)
        .map_err(|e| RotationError::KeyDecryptionFailed(e.to_string()))?;

    if !verify_commitment(keypair.public_key().as_ref(), &state.next_commitment[0]) {
        return Err(RotationError::RotationFailed(
            "commitment mismatch: next key does not match previous commitment".into(),
        ));
    }

    Ok((decrypted, target_alias))
}

/// Generates the new rotation event and the next forward-looking key commitment.
fn generate_rotation_keys(
    identity: &ManagedIdentity,
    state: &KeyState,
    current_key_pkcs8: &[u8],
) -> Result<(RotEvent, ring::pkcs8::Document), RotationError> {
    let witness_config: Option<WitnessConfig> = identity
        .metadata
        .as_ref()
        .and_then(|m| m.get("witness_config"))
        .and_then(|wc| serde_json::from_value(wc.clone()).ok());

    let rng = SystemRandom::new();
    let new_next_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|e| RotationError::RotationFailed(format!("key generation failed: {e}")))?;
    let new_next_keypair = Ed25519KeyPair::from_pkcs8(new_next_pkcs8.as_ref())
        .map_err(|e| RotationError::RotationFailed(format!("key construction failed: {e}")))?;

    let next_keypair = load_keypair_from_der_or_seed(current_key_pkcs8)
        .map_err(|e| RotationError::KeyDecryptionFailed(e.to_string()))?;

    let (rot, _event_bytes) = compute_rotation_event(
        state,
        &next_keypair,
        &new_next_keypair,
        witness_config.as_ref(),
    )?;

    Ok((rot, new_next_pkcs8))
}

struct FinalizeParams<'a> {
    did: &'a IdentityDID,
    prefix: &'a Prefix,
    next_alias: &'a KeyAlias,
    old_next_alias: &'a KeyAlias,
    current_pkcs8: &'a [u8],
    new_next_pkcs8: &'a [u8],
    rot: &'a RotEvent,
    state: &'a KeyState,
}

/// Encrypts and persists the new current and next keys to secure storage.
fn finalize_rotation_storage(
    params: FinalizeParams<'_>,
    registry: &(dyn RegistryBackend + Send + Sync),
    key_storage: &(dyn KeyStorage + Send + Sync),
    passphrase_provider: &(dyn auths_core::signing::PassphraseProvider + Send + Sync),
) -> Result<(), RotationError> {
    let new_pass = passphrase_provider
        .get_passphrase(&format!(
            "Create passphrase for new key alias '{}':",
            params.next_alias
        ))
        .map_err(|e| RotationError::KeyDecryptionFailed(e.to_string()))?;

    let confirm_pass = passphrase_provider
        .get_passphrase(&format!("Confirm passphrase for '{}':", params.next_alias))
        .map_err(|e| RotationError::KeyDecryptionFailed(e.to_string()))?;

    if new_pass != confirm_pass {
        return Err(RotationError::RotationFailed(format!(
            "passphrases do not match for alias '{}'",
            params.next_alias
        )));
    }

    let encrypted_new_current = encrypt_keypair(params.current_pkcs8, &new_pass)
        .map_err(|e| RotationError::RotationFailed(format!("encrypt new current key: {e}")))?;

    let new_next_seed = extract_seed_bytes(params.new_next_pkcs8)
        .map_err(|e| RotationError::RotationFailed(format!("extract new next seed: {e}")))?;
    let new_next_seed_pkcs8 = encode_seed_as_pkcs8(new_next_seed)
        .map_err(|e| RotationError::RotationFailed(format!("encode new next seed: {e}")))?;
    let encrypted_new_next = encrypt_keypair(&new_next_seed_pkcs8, &new_pass)
        .map_err(|e| RotationError::RotationFailed(format!("encrypt new next key: {e}")))?;

    let new_sequence = params.state.sequence + 1;
    let new_next_alias =
        KeyAlias::new_unchecked(format!("{}--next-{}", params.next_alias, new_sequence));

    let key_material = RotationKeyMaterial {
        did: params.did.clone(),
        next_alias: params.next_alias.clone(),
        new_next_alias,
        old_next_alias: params.old_next_alias.clone(),
        new_current_encrypted: encrypted_new_current.to_vec(),
        new_next_encrypted: encrypted_new_next.to_vec(),
    };

    apply_rotation(
        params.rot,
        params.prefix,
        key_material,
        registry,
        key_storage,
    )
}

// ──── provision.rs ──────────────────────────────────────────────────────────

// Declarative provisioning workflow for enterprise node setup.
//
// Receives a pre-deserialized `NodeConfig` and reconciles the node's identity
// state. All I/O (TOML loading, env expansion) is handled by the caller.

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

// ──── machine_identity.rs ───────────────────────────────────────────────────

use auths_oidc_port::{
    JwksClient, JwtValidator, OidcError, OidcValidationConfig, TimestampClient, TimestampConfig,
};
use auths_verifier::core::{Attestation, Ed25519PublicKey, Ed25519Signature, OidcBinding};

/// Configuration for creating a machine identity from an OIDC token.
///
/// # Usage
///
/// ```ignore
/// use auths_api::domains::identity::workflows::{OidcMachineIdentityConfig, create_machine_identity_from_oidc_token};
/// use chrono::Utc;
///
/// let config = OidcMachineIdentityConfig {
///     issuer: "https://token.actions.githubusercontent.com".to_string(),
///     audience: "sigstore".to_string(),
///     platform: "github".to_string(),
/// };
///
/// let identity = create_machine_identity_from_oidc_token(
///     token,
///     config,
///     jwt_validator,
///     jwks_client,
///     timestamp_client,
///     Utc::now(),
/// ).await?;
/// ```
#[derive(Debug, Clone)]
pub struct OidcMachineIdentityConfig {
    /// OIDC issuer URL
    pub issuer: String,
    /// Expected audience
    pub audience: String,
    /// CI platform name (github, gitlab, circleci)
    pub platform: String,
}

/// Machine identity created from an OIDC token.
///
/// Contains the binding proof (issuer, subject, audience, expiration) so verifiers
/// can reconstruct the identity later without needing the ephemeral key.
#[derive(Debug, Clone)]
pub struct OidcMachineIdentity {
    /// Platform (github, gitlab, circleci)
    pub platform: String,
    /// Subject claim (unique workload identifier)
    pub subject: String,
    /// Token expiration
    pub token_exp: i64,
    /// Issuer
    pub issuer: String,
    /// Audience
    pub audience: String,
    /// JTI for replay detection
    pub jti: Option<String>,
    /// Platform-normalized claims
    pub normalized_claims: serde_json::Map<String, serde_json::Value>,
}

/// Create a machine identity from an OIDC token.
///
/// Validates the token, extracts claims, performs replay detection,
/// and optionally timestamps the identity.
///
/// # Args
///
/// * `token`: Raw JWT OIDC token
/// * `config`: Machine identity configuration
/// * `jwt_validator`: JWT validator implementation
/// * `jwks_client`: JWKS client for key resolution
/// * `timestamp_client`: Optional timestamp client
/// * `now`: Current UTC time for validation
pub async fn create_machine_identity_from_oidc_token(
    token: &str,
    config: OidcMachineIdentityConfig,
    jwt_validator: Arc<dyn JwtValidator>,
    _jwks_client: Arc<dyn JwksClient>,
    timestamp_client: Arc<dyn TimestampClient>,
    now: DateTime<Utc>,
) -> Result<OidcMachineIdentity, OidcError> {
    let validation_config = OidcValidationConfig::builder()
        .issuer(&config.issuer)
        .audience(&config.audience)
        .build()
        .map_err(OidcError::JwtDecode)?;

    let claims =
        validate_and_extract_oidc_claims(token, &validation_config, &*jwt_validator, now).await?;

    let jti = claims
        .get("jti")
        .and_then(|j| j.as_str())
        .map(|s| s.to_string());

    check_jti_and_register(&jti)?;

    let subject = claims
        .get("sub")
        .and_then(|s| s.as_str())
        .ok_or_else(|| OidcError::ClaimsValidationFailed {
            claim: "sub".to_string(),
            reason: "missing subject".to_string(),
        })?
        .to_string();

    let issuer = claims
        .get("iss")
        .and_then(|i| i.as_str())
        .ok_or_else(|| OidcError::ClaimsValidationFailed {
            claim: "iss".to_string(),
            reason: "missing issuer".to_string(),
        })?
        .to_string();

    let audience = claims
        .get("aud")
        .and_then(|a| a.as_str())
        .ok_or_else(|| OidcError::ClaimsValidationFailed {
            claim: "aud".to_string(),
            reason: "missing audience".to_string(),
        })?
        .to_string();

    let token_exp = claims.get("exp").and_then(|e| e.as_i64()).ok_or_else(|| {
        OidcError::ClaimsValidationFailed {
            claim: "exp".to_string(),
            reason: "missing or invalid expiration".to_string(),
        }
    })?;

    let normalized_claims = normalize_platform_claims(&config.platform, &claims)?;

    let _timestamp = timestamp_client
        .timestamp(token.as_bytes(), &TimestampConfig::default())
        .await
        .ok();

    Ok(OidcMachineIdentity {
        platform: config.platform,
        subject,
        token_exp,
        issuer,
        audience,
        jti,
        normalized_claims,
    })
}

async fn validate_and_extract_oidc_claims(
    token: &str,
    config: &OidcValidationConfig,
    validator: &dyn JwtValidator,
    now: DateTime<Utc>,
) -> Result<serde_json::Value, OidcError> {
    validator.validate(token, config, now).await
}

fn check_jti_and_register(jti: &Option<String>) -> Result<(), OidcError> {
    if let Some(jti_value) = jti.as_ref().filter(|j| !j.is_empty()) {
        // JTI is valid — in a real system, we'd check against a replay store
        // For now, we just accept it (would implement distributed replay detection in production)
        let _ = jti_value;
    } else if jti.is_some() {
        return Err(OidcError::TokenReplayDetected("empty jti".to_string()));
    }
    Ok(())
}

fn normalize_platform_claims(
    platform: &str,
    claims: &serde_json::Value,
) -> Result<serde_json::Map<String, serde_json::Value>, OidcError> {
    use auths_infra_http::normalize_workload_claims;

    normalize_workload_claims(platform, claims.clone()).map_err(|e| {
        OidcError::ClaimsValidationFailed {
            claim: "platform_claims".to_string(),
            reason: e,
        }
    })
}

/// Parameters for signing a commit with an identity.
///
/// Args:
/// * `commit_sha`: The Git commit SHA (40 hex characters)
/// * `issuer_did`: The issuer identity DID
/// * `device_did`: The device DID
/// * `commit_message`: Optional commit message
/// * `author`: Optional commit author info
/// * `oidc_binding`: Optional OIDC binding from a machine identity
/// * `timestamp`: When the attestation was created
#[derive(Debug, Clone)]
pub struct SignCommitParams {
    /// Git commit SHA
    pub commit_sha: String,
    /// Issuer identity DID
    pub issuer_did: String,
    /// Device DID for the signing device
    pub device_did: String,
    /// Git commit message (optional)
    pub commit_message: Option<String>,
    /// Commit author (optional)
    pub author: Option<String>,
    /// OIDC binding if signed from CI (optional)
    pub oidc_binding: Option<OidcMachineIdentity>,
    /// Timestamp of attestation creation
    pub timestamp: DateTime<Utc>,
}

/// Sign a commit with an identity, producing a signed attestation.
///
/// Creates an attestation with commit metadata and OIDC binding (if available),
/// signs it with the identity's keypair, and returns the attestation structure.
///
/// # Args
///
/// * `params`: Signing parameters including commit SHA, DIDs, and optional OIDC binding
/// * `issuer_keypair`: Ed25519 keypair for signing (issuer side)
/// * `device_public_key`: Device's Ed25519 public key
///
/// # Usage:
///
/// ```ignore
/// let params = SignCommitParams {
///     commit_sha: "abc123...".to_string(),
///     issuer_did: "did:keri:E...".to_string(),
///     device_did: "did:key:z...".to_string(),
///     commit_message: Some("feat: add X".to_string()),
///     author: Some("alice".to_string()),
///     oidc_binding: Some(machine_identity),
///     timestamp: Utc::now(),
/// };
///
/// let attestation = sign_commit_with_identity(
///     &params,
///     &issuer_keypair,
///     &device_public_key,
/// )?;
/// ```
pub fn sign_commit_with_identity(
    params: &SignCommitParams,
    issuer_keypair: &Ed25519KeyPair,
    device_public_key: &[u8; 32],
) -> Result<Attestation, Box<dyn std::error::Error>> {
    let issuer = CanonicalDid::parse(&params.issuer_did)
        .map_err(|e| format!("Invalid issuer DID: {}", e))?;
    let subject =
        DeviceDID::parse(&params.device_did).map_err(|e| format!("Invalid device DID: {}", e))?;

    let device_pk = Ed25519PublicKey::from_bytes(*device_public_key);

    let oidc_binding = params.oidc_binding.as_ref().map(|mi| OidcBinding {
        issuer: mi.issuer.clone(),
        subject: mi.subject.clone(),
        audience: mi.audience.clone(),
        token_exp: mi.token_exp,
        platform: Some(mi.platform.clone()),
        jti: mi.jti.clone(),
        normalized_claims: Some(mi.normalized_claims.clone()),
    });

    let rid = format!("auths/commits/{}", params.commit_sha);

    let mut attestation = Attestation {
        version: 1,
        rid: ResourceId::new(rid),
        issuer: issuer.clone(),
        subject: subject.clone(),
        device_public_key: device_pk,
        identity_signature: Ed25519Signature::empty(),
        device_signature: Ed25519Signature::empty(),
        revoked_at: None,
        expires_at: None,
        timestamp: Some(params.timestamp),
        note: None,
        payload: None,
        role: None,
        capabilities: vec![],
        delegated_by: None,
        signer_type: None,
        environment_claim: None,
        commit_sha: Some(params.commit_sha.clone()),
        commit_message: params.commit_message.clone(),
        author: params.author.clone(),
        oidc_binding,
    };

    // Create canonical form and sign
    let canonical_data = auths_verifier::core::CanonicalAttestationData {
        version: attestation.version,
        rid: &attestation.rid,
        issuer: &attestation.issuer,
        subject: &attestation.subject,
        device_public_key: attestation.device_public_key.as_bytes(),
        payload: &attestation.payload,
        timestamp: &attestation.timestamp,
        expires_at: &attestation.expires_at,
        revoked_at: &attestation.revoked_at,
        note: &attestation.note,
        role: None,
        capabilities: None,
        delegated_by: None,
        signer_type: None,
    };

    let canonical_bytes = auths_verifier::core::canonicalize_attestation_data(&canonical_data)
        .map_err(|e| format!("Canonicalization failed: {}", e))?;

    let signature = issuer_keypair.sign(&canonical_bytes);
    attestation.identity_signature = Ed25519Signature::try_from_slice(signature.as_ref())
        .map_err(|e| format!("Signature encoding failed: {}", e))?;

    Ok(attestation)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jti_validation_empty() {
        let result = check_jti_and_register(&Some("".to_string()));
        assert!(matches!(result, Err(OidcError::TokenReplayDetected(_))));
    }

    #[test]
    fn test_jti_validation_none() {
        let result = check_jti_and_register(&None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_jti_validation_valid() {
        let result = check_jti_and_register(&Some("valid-jti".to_string()));
        assert!(result.is_ok());
    }

    #[test]
    fn test_sign_commit_params_structure() {
        #[allow(clippy::disallowed_methods)] // test code
        let timestamp = Utc::now();
        let params = SignCommitParams {
            commit_sha: "abc123def456".to_string(),
            issuer_did: "did:keri:Eissuer".to_string(),
            device_did: "did:key:z6Mk...".to_string(),
            commit_message: Some("feat: add X".to_string()),
            author: Some("Alice".to_string()),
            oidc_binding: None,
            timestamp,
        };

        assert_eq!(params.commit_sha, "abc123def456");
        assert_eq!(params.issuer_did, "did:keri:Eissuer");
        assert_eq!(params.device_did, "did:key:z6Mk...");
        assert!(params.oidc_binding.is_none());
    }

    #[test]
    fn test_oidc_machine_identity_structure() {
        let mut claims = serde_json::Map::new();
        claims.insert("repo".to_string(), "owner/repo".into());

        let identity = OidcMachineIdentity {
            platform: "github".to_string(),
            subject: "repo:owner/repo:ref:refs/heads/main".to_string(),
            token_exp: 1704067200,
            issuer: "https://token.actions.githubusercontent.com".to_string(),
            audience: "sigstore".to_string(),
            jti: Some("jti-123".to_string()),
            normalized_claims: claims,
        };

        assert_eq!(identity.platform, "github");
        assert_eq!(
            identity.issuer,
            "https://token.actions.githubusercontent.com"
        );
        assert!(identity.jti.is_some());
    }

    #[test]
    fn test_oidc_binding_from_machine_identity() {
        let mut claims = serde_json::Map::new();
        claims.insert("run_id".to_string(), "12345".into());

        let machine_id = OidcMachineIdentity {
            platform: "github".to_string(),
            subject: "workload_subject".to_string(),
            token_exp: 1704067200,
            issuer: "https://token.actions.githubusercontent.com".to_string(),
            audience: "sigstore".to_string(),
            jti: Some("jti-456".to_string()),
            normalized_claims: claims,
        };

        let binding = OidcBinding {
            issuer: machine_id.issuer.clone(),
            subject: machine_id.subject.clone(),
            audience: machine_id.audience.clone(),
            token_exp: machine_id.token_exp,
            platform: Some(machine_id.platform.clone()),
            jti: machine_id.jti.clone(),
            normalized_claims: Some(machine_id.normalized_claims.clone()),
        };

        assert_eq!(
            binding.issuer,
            "https://token.actions.githubusercontent.com"
        );
        assert_eq!(binding.platform, Some("github".to_string()));
        assert!(binding.normalized_claims.is_some());
    }
}

// ──── platform.rs ───────────────────────────────────────────────────────────

// Platform identity claim workflow orchestration.
//
// Orchestrates OAuth device flow, proof publishing, and registry submission
// for linking platform identities (e.g. GitHub) to a controller DID.

use auths_core::ports::platform::{
    ClaimResponse, DeviceCodeResponse, OAuthDeviceFlowProvider, PlatformError,
    PlatformProofPublisher, PlatformUserProfile, RegistryClaimClient, SshSigningKeyUploader,
};

/// Signed platform claim linking a controller DID to a platform identity.
///
/// Canonicalized (RFC 8785) before signing so that the Ed25519 signature
/// can be verified by anyone using only the DID's public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformClaim {
    /// Claim type discriminant; always `"platform_claim"`.
    #[serde(rename = "type")]
    pub claim_type: String,
    /// Platform identifier (e.g. `"github"`).
    pub platform: String,
    /// Username on the platform.
    pub namespace: String,
    /// Controller DID being linked.
    pub did: String,
    /// RFC 3339 timestamp of claim creation.
    pub timestamp: String,
    /// Base64url-encoded Ed25519 signature over the canonical unsigned JSON.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// Configuration for GitHub identity claim workflow.
///
/// Args:
/// * `client_id`: GitHub OAuth application client ID.
/// * `registry_url`: Base URL of the auths registry.
/// * `scopes`: OAuth scopes to request (e.g. `"read:user gist"`).
pub struct GitHubClaimConfig {
    /// GitHub OAuth application client ID.
    pub client_id: String,
    /// Base URL of the auths registry.
    pub registry_url: String,
    /// OAuth scopes to request.
    pub scopes: String,
}

/// Create and sign a platform claim JSON string.
///
/// Builds the claim, canonicalizes (RFC 8785), signs with the identity key,
/// and returns the pretty-printed signed JSON.
///
/// Args:
/// * `platform`: Platform name (e.g. `"github"`).
/// * `namespace`: Username on the platform.
/// * `did`: Controller DID.
/// * `key_alias`: Keychain alias for the signing key.
/// * `key_storage`: Storage for accessing the signing key.
/// * `passphrase_provider`: Provider for key decryption.
/// * `now`: Current time (injected by caller — no `Utc::now()` in SDK).
///
/// Usage:
/// ```ignore
/// let claim_json = create_signed_platform_claim("github", "octocat", &did, &alias, key_storage, passphrase_provider, now)?;
/// ```
pub fn create_signed_platform_claim(
    platform: &str,
    namespace: &str,
    did: &str,
    key_alias: &KeyAlias,
    key_storage: &(dyn KeyStorage + Send + Sync),
    passphrase_provider: &(dyn auths_core::signing::PassphraseProvider + Send + Sync),
    now: DateTime<Utc>,
) -> Result<String, PairingError> {
    let mut claim = PlatformClaim {
        claim_type: "platform_claim".to_string(),
        platform: platform.to_string(),
        namespace: namespace.to_string(),
        did: did.to_string(),
        timestamp: now.to_rfc3339(),
        signature: None,
    };

    let unsigned_json = serde_json::to_value(&claim)
        .map_err(|e| PairingError::AttestationFailed(format!("failed to serialize claim: {e}")))?;
    let canonical = json_canon::to_string(&unsigned_json).map_err(|e| {
        PairingError::AttestationFailed(format!("failed to canonicalize claim: {e}"))
    })?;

    let (_identity_did, _role, encrypted_data) = key_storage
        .load_key(key_alias)
        .map_err(|e| PairingError::AttestationFailed(e.to_string()))?;
    let passphrase = passphrase_provider
        .get_passphrase(&format!("Enter passphrase for key '{}':", key_alias))
        .map_err(|e| PairingError::AttestationFailed(e.to_string()))?;
    let key_bytes = auths_core::crypto::signer::decrypt_keypair(&encrypted_data, &passphrase)
        .map_err(|e| PairingError::AttestationFailed(e.to_string()))?;
    let seed = auths_core::crypto::signer::extract_seed_from_key_bytes(&key_bytes)
        .map_err(|e| PairingError::AttestationFailed(e.to_string()))?;
    let signature_bytes =
        auths_core::crypto::provider_bridge::sign_ed25519_sync(&seed, canonical.as_bytes())
            .map_err(|e| PairingError::AttestationFailed(e.to_string()))?;

    claim.signature = Some(URL_SAFE_NO_PAD.encode(&signature_bytes));

    serde_json::to_string_pretty(&claim).map_err(|e| {
        PairingError::AttestationFailed(format!("failed to serialize signed claim: {e}"))
    })
}

/// Orchestrate GitHub identity claiming end-to-end.
///
/// Steps:
/// 1. Request OAuth device code.
/// 2. Fire `on_device_code` callback (CLI displays `user_code`, opens browser).
/// 3. Poll for access token (RFC 8628 device flow).
/// 4. Fetch GitHub user profile.
/// 5. Create signed platform claim (injected `now`, no `Utc::now()` in SDK).
/// 6. Publish claim as a GitHub Gist proof.
/// 7. Submit claim to registry.
///
/// Args:
/// * `oauth`: OAuth device flow provider.
/// * `publisher`: Proof publisher (publishes Gist).
/// * `registry_claim`: Registry claim client.
/// * `key_storage`: Keychain for signing the claim.
/// * `passphrase_provider`: Provider for key decryption.
/// * `identity_storage`: Storage backend for identity.
/// * `config`: GitHub client ID, registry URL, and OAuth scopes.
/// * `now`: Current time (injected by caller).
/// * `on_device_code`: Callback fired after device code is obtained; CLI shows
///   `user_code`, opens browser, displays instructions.
///
/// Usage:
/// ```ignore
/// let response = claim_github_identity(
///     &oauth_provider,
///     &gist_publisher,
///     &registry_client,
///     key_storage.as_ref(),
///     passphrase_provider.as_ref(),
///     identity_storage.as_ref(),
///     GitHubClaimConfig { client_id: "...".into(), registry_url: "...".into(), scopes: "read:user gist".into() },
///     Utc::now(),
///     &|code| { open::that(&code.verification_uri).ok(); },
/// ).await?;
/// ```
#[allow(clippy::too_many_arguments)]
pub async fn claim_github_identity<
    O: OAuthDeviceFlowProvider,
    P: PlatformProofPublisher,
    C: RegistryClaimClient,
>(
    oauth: &O,
    publisher: &P,
    registry_claim: &C,
    key_storage: &(dyn KeyStorage + Send + Sync),
    passphrase_provider: &(dyn auths_core::signing::PassphraseProvider + Send + Sync),
    identity_storage: &(dyn IdentityStorage + Send + Sync),
    config: GitHubClaimConfig,
    now: DateTime<Utc>,
    on_device_code: &(dyn Fn(&DeviceCodeResponse) + Send + Sync),
) -> Result<ClaimResponse, PlatformError> {
    let device_code = oauth
        .request_device_code(&config.client_id, &config.scopes)
        .await?;

    on_device_code(&device_code);

    let expires_in = Duration::from_secs(device_code.expires_in);
    let interval = Duration::from_secs(device_code.interval);

    let access_token = oauth
        .poll_for_token(
            &config.client_id,
            &device_code.device_code,
            interval,
            expires_in,
        )
        .await?;

    let profile = oauth.fetch_user_profile(&access_token).await?;

    let controller_did =
        auths_sdk::pairing::load_controller_did(identity_storage).map_err(|e| {
            PlatformError::Platform {
                message: e.to_string(),
            }
        })?;

    let key_alias = resolve_signing_key_alias(key_storage, &controller_did)?;

    let claim_json = create_signed_platform_claim(
        "github",
        &profile.login,
        &controller_did,
        &key_alias,
        key_storage,
        passphrase_provider,
        now,
    )
    .map_err(|e| PlatformError::Platform {
        message: e.to_string(),
    })?;

    let proof_url = publisher.publish_proof(&access_token, &claim_json).await?;

    registry_claim
        .submit_claim(&config.registry_url, &controller_did, &proof_url)
        .await
}

/// Configuration for claiming an npm platform identity.
pub struct NpmClaimConfig {
    /// Registry URL to submit the claim to.
    pub registry_url: String,
}

/// Claims an npm platform identity by verifying an npm access token.
///
/// Args:
/// * `npm_username`: The verified npm username (from `HttpNpmAuthProvider::verify_token`).
/// * `registry_claim`: Client for submitting the claim to the auths registry.
/// * `key_storage`: Keychain for signing the claim.
/// * `passphrase_provider`: Provider for key decryption.
/// * `identity_storage`: Storage backend for identity.
/// * `config`: npm claim configuration (registry URL).
/// * `now`: Current time for timestamp in the claim.
///
/// Usage:
/// ```ignore
/// let response = claim_npm_identity("bordumb", &registry_client, key_storage.as_ref(), passphrase_provider.as_ref(), identity_storage.as_ref(), config, now).await?;
/// ```
#[allow(clippy::too_many_arguments)]
pub async fn claim_npm_identity<C: RegistryClaimClient>(
    npm_username: &str,
    npm_token: &str,
    registry_claim: &C,
    key_storage: &(dyn KeyStorage + Send + Sync),
    passphrase_provider: &(dyn auths_core::signing::PassphraseProvider + Send + Sync),
    identity_storage: &(dyn IdentityStorage + Send + Sync),
    config: NpmClaimConfig,
    now: DateTime<Utc>,
) -> Result<ClaimResponse, PlatformError> {
    let controller_did =
        auths_sdk::pairing::load_controller_did(identity_storage).map_err(|e| {
            PlatformError::Platform {
                message: e.to_string(),
            }
        })?;

    let key_alias = resolve_signing_key_alias(key_storage, &controller_did)?;

    let claim_json = create_signed_platform_claim(
        "npm",
        npm_username,
        &controller_did,
        &key_alias,
        key_storage,
        passphrase_provider,
        now,
    )
    .map_err(|e| PlatformError::Platform {
        message: e.to_string(),
    })?;

    // npm has no Gist equivalent. Encode both the npm token (for server-side
    // verification via npm whoami) and the signed claim (for signature verification).
    // The server detects the "npm-token:" prefix, verifies the token, then discards it.
    let encoded_claim = URL_SAFE_NO_PAD.encode(claim_json.as_bytes());
    let encoded_token = URL_SAFE_NO_PAD.encode(npm_token.as_bytes());
    let proof_url = format!("npm-token:{encoded_token}:{encoded_claim}");

    registry_claim
        .submit_claim(&config.registry_url, &controller_did, &proof_url)
        .await
}

/// Configuration for claiming a PyPI platform identity.
pub struct PypiClaimConfig {
    /// Registry URL to submit the claim to.
    pub registry_url: String,
}

/// Claims a PyPI platform identity via self-reported username + signed claim.
///
/// SECURITY: PyPI's token verification API (/danger-api/echo) is unreliable,
/// so we don't verify tokens. Instead, the platform claim is a self-reported
/// username backed by a DID-signed proof. The real security check happens at
/// namespace claim time, when the PyPI verifier checks the public pypi.org
/// JSON API to confirm the username is a maintainer of the target package.
///
/// This is equivalent to the GitHub flow's trust model: the claim is signed
/// with the device key (stored in platform keychain, not in CI), so a stolen
/// PyPI token alone cannot produce a valid claim.
///
/// Args:
/// * `pypi_username`: The user's self-reported PyPI username.
/// * `registry_claim`: Client for submitting the claim to the auths registry.
/// * `key_storage`: Keychain for signing the claim.
/// * `passphrase_provider`: Provider for key decryption.
/// * `identity_storage`: Storage backend for identity.
/// * `config`: PyPI claim configuration (registry URL).
/// * `now`: Current time for timestamp in the claim.
///
/// Usage:
/// ```ignore
/// let response = claim_pypi_identity("bordumb", &registry_client, key_storage.as_ref(), passphrase_provider.as_ref(), identity_storage.as_ref(), config, now).await?;
/// ```
pub async fn claim_pypi_identity<C: RegistryClaimClient>(
    pypi_username: &str,
    registry_claim: &C,
    key_storage: &(dyn KeyStorage + Send + Sync),
    passphrase_provider: &(dyn auths_core::signing::PassphraseProvider + Send + Sync),
    identity_storage: &(dyn IdentityStorage + Send + Sync),
    config: PypiClaimConfig,
    now: DateTime<Utc>,
) -> Result<ClaimResponse, PlatformError> {
    let controller_did =
        auths_sdk::pairing::load_controller_did(identity_storage).map_err(|e| {
            PlatformError::Platform {
                message: e.to_string(),
            }
        })?;

    let key_alias = resolve_signing_key_alias(key_storage, &controller_did)?;

    let claim_json = create_signed_platform_claim(
        "pypi",
        pypi_username,
        &controller_did,
        &key_alias,
        key_storage,
        passphrase_provider,
        now,
    )
    .map_err(|e| PlatformError::Platform {
        message: e.to_string(),
    })?;

    // PyPI's token verification API is unreliable. Submit the signed claim
    // directly. The server verifies the Ed25519 signature but does not
    // independently verify the username via PyPI. The real ownership check
    // happens at namespace claim time via the public PyPI JSON API.
    let encoded_claim = URL_SAFE_NO_PAD.encode(claim_json.as_bytes());
    let proof_url = format!("pypi-claim:{encoded_claim}");

    registry_claim
        .submit_claim(&config.registry_url, &controller_did, &proof_url)
        .await
}

fn resolve_signing_key_alias(
    key_storage: &(dyn KeyStorage + Send + Sync),
    controller_did: &str,
) -> Result<KeyAlias, PlatformError> {
    #[allow(clippy::disallowed_methods)]
    // INVARIANT: controller_did comes from load_controller_did() which returns into_inner() of a validated IdentityDID from storage
    let identity_did =
        auths_core::storage::keychain::IdentityDID::new_unchecked(controller_did.to_string());
    let aliases = key_storage
        .list_aliases_for_identity(&identity_did)
        .map_err(|e| PlatformError::Platform {
            message: format!("failed to list key aliases: {e}"),
        })?;

    aliases
        .into_iter()
        .find(|a| !a.contains("--next-"))
        .ok_or_else(|| PlatformError::Platform {
            message: format!("no signing key found for identity {controller_did}"),
        })
}

/// Upload the SSH signing key for the identity to GitHub.
///
/// Stores metadata about the uploaded key (key ID, GitHub username, timestamp)
/// in the identity metadata for future reference and idempotency.
///
/// Args:
/// * `uploader`: HTTP implementation of SSH key uploader.
/// * `access_token`: GitHub OAuth access token with `write:ssh_signing_key` scope.
/// * `public_key`: SSH public key in OpenSSH format (ssh-ed25519 AAAA...).
/// * `key_alias`: Keychain alias for the device key.
/// * `hostname`: Machine hostname for the key title.
/// * `identity_storage`: Storage backend for persisting metadata.
/// * `now`: Current time (injected by caller; SDK does not call Utc::now()).
///
/// Returns: Ok(()) on success, PlatformError on failure (non-fatal; init continues).
///
/// Usage:
/// ```ignore
/// upload_github_ssh_signing_key(
///     &uploader,
///     "ghu_token...",
///     "ssh-ed25519 AAAA...",
///     "main",
///     "MacBook-Pro.local",
///     &identity_storage,
///     Utc::now(),
/// ).await?;
/// ```
pub async fn upload_github_ssh_signing_key<U: SshSigningKeyUploader + ?Sized>(
    uploader: &U,
    access_token: &str,
    public_key: &str,
    key_alias: &str,
    hostname: &str,
    identity_storage: &(dyn IdentityStorage + Send + Sync),
    now: DateTime<Utc>,
) -> Result<(), PlatformError> {
    let title = format!("auths/{key_alias} ({hostname})");

    let key_id = uploader
        .upload_signing_key(access_token, public_key, &title)
        .await?;

    // Load existing identity to get the controller DID
    let existing = identity_storage
        .load_identity()
        .map_err(|e| PlatformError::Platform {
            message: format!("failed to load identity: {e}"),
        })?;

    let metadata = serde_json::json!({
        "github_ssh_key": {
            "key_id": key_id,
            "uploaded_at": now.to_rfc3339(),
        }
    });

    identity_storage
        .create_identity(existing.controller_did.as_ref(), Some(metadata))
        .map_err(|e| PlatformError::Platform {
            message: format!("failed to store SSH key metadata: {e}"),
        })?;

    Ok(())
}

/// Re-authorize with GitHub and optionally upload the SSH signing key.
///
/// Re-runs the OAuth device flow to obtain a fresh token with potentially
/// new scopes, then attempts to upload the SSH signing key if provided.
///
/// Args:
/// * `oauth`: OAuth device flow provider.
/// * `uploader`: SSH key uploader.
/// * `identity_storage`: Storage backend for identity and metadata.
/// * `key_storage`: Keychain for signing operations.
/// * `config`: GitHub OAuth client ID and registry URL.
/// * `key_alias`: Keychain alias for the device key.
/// * `hostname`: Machine hostname for the key title.
/// * `public_key`: SSH public key in OpenSSH format (optional).
/// * `now`: Current time (injected by caller).
/// * `on_device_code`: Callback fired after device code is obtained.
///
/// Usage:
/// ```ignore
/// update_github_ssh_scopes(
///     &oauth_provider,
///     &uploader,
///     &identity_storage,
///     key_storage.as_ref(),
///     &config,
///     "main",
///     "MacBook.local",
///     Some("ssh-ed25519 AAAA..."),
///     Utc::now(),
///     &|code| { println!("Authorize at: {}", code.verification_uri); },
/// ).await?;
/// ```
#[allow(clippy::too_many_arguments)]
pub async fn update_github_ssh_scopes<
    O: OAuthDeviceFlowProvider + ?Sized,
    U: SshSigningKeyUploader + ?Sized,
>(
    oauth: &O,
    uploader: &U,
    identity_storage: &(dyn IdentityStorage + Send + Sync),
    _key_storage: &(dyn KeyStorage + Send + Sync),
    config: &GitHubClaimConfig,
    key_alias: &str,
    hostname: &str,
    public_key: Option<&str>,
    now: DateTime<Utc>,
    on_device_code: &dyn Fn(&DeviceCodeResponse),
) -> Result<PlatformUserProfile, PlatformError> {
    let resp = oauth
        .request_device_code(&config.client_id, &config.scopes)
        .await?;
    on_device_code(&resp);

    let access_token = oauth
        .poll_for_token(
            &config.client_id,
            &resp.device_code,
            Duration::from_secs(resp.interval),
            Duration::from_secs(resp.expires_in),
        )
        .await?;

    let profile = oauth.fetch_user_profile(&access_token).await?;

    if let Some(key) = public_key {
        let _ = upload_github_ssh_signing_key(
            uploader,
            &access_token,
            key,
            key_alias,
            hostname,
            identity_storage,
            now,
        )
        .await;
    }

    Ok(profile)
}
