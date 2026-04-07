//! KERI key rotation wrapper.
//!
//! This module provides high-level wrappers around the KERI rotation
//! functionality, handling key storage and passphrase management.
//!
//! Two backends are supported:
//! - [`rotate_keri_identity`]: GitKel-based storage (legacy, per-identity refs)
//! - [`rotate_registry_identity`]: Packed registry storage (single `refs/auths/registry` ref)

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use git2::Repository;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::path::Path;

use auths_crypto::Pkcs8Der;

use crate::error::InitError;
use crate::identity::helpers::{
    encode_seed_as_pkcs8, extract_seed_bytes, load_keypair_from_der_or_seed,
};
use crate::keri::{
    Event, GitKel, KERI_VERSION, KeriSequence, Prefix, RotEvent, Said, rotate_keys,
    serialize_for_signing, validate_kel,
};
use std::sync::Arc;

use crate::storage::layout::StorageLayoutConfig;
use crate::storage::registry::RegistryBackend;
use crate::witness_config::WitnessConfig;
use auths_core::crypto::said::{compute_next_commitment, verify_commitment};
use auths_core::crypto::signer::{decrypt_keypair, encrypt_keypair};
use auths_core::signing::PassphraseProvider;
use auths_core::storage::keychain::{IdentityDID, KeyAlias, KeyRole, KeyStorage};
use auths_keri::compute_said;

/// Result of a rotation operation with keychain-specific info.
pub struct RotationKeyInfo {
    /// The sequence number after rotation
    pub sequence: u64,
    /// The new current keypair (PKCS8 DER encoded, zeroed on drop)
    pub new_current_pkcs8: Pkcs8Der,
    /// The new next keypair (PKCS8 DER encoded, zeroed on drop)
    pub new_next_pkcs8: Pkcs8Der,
}

/// Rotates a KERI identity using the GitKel backend.
///
/// Reads and writes the KEL via per-identity Git refs (`refs/did/keri/{prefix}/kel`).
/// Use [`rotate_registry_identity`] for the packed registry backend.
///
/// # Arguments
/// * `repo_path` - Path to the Git repository containing the KEL.
/// * `current_alias` - Keychain alias for the current signing keypair.
/// * `next_alias` - Keychain alias to store the **new** current keypair under (after rotation).
/// * `passphrase_provider` - Service to get passphrases for key decryption/re-encryption.
/// * `_config` - Storage layout configuration (unused but kept for API compatibility).
/// * `keychain` - Keychain storage implementation.
///
/// # Returns
/// * `Result<RotationKeyInfo>` - Information about the rotation if successful.
#[allow(clippy::too_many_arguments)]
pub fn rotate_keri_identity(
    repo_path: &Path,
    current_alias: &KeyAlias,
    next_alias: &KeyAlias,
    passphrase_provider: &dyn PassphraseProvider,
    _config: &StorageLayoutConfig,
    keychain: &(dyn KeyStorage + Send + Sync),
    witness_config: Option<&WitnessConfig>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<RotationKeyInfo, InitError> {
    let repo = Repository::open(repo_path)?;

    let (did, _role, _encrypted_current) = keychain.load_key(current_alias)?;

    let prefix = did.as_str().strip_prefix("did:keri:").ok_or_else(|| {
        InitError::InvalidData(format!("Invalid DID format, expected 'did:keri:': {}", did))
    })?;

    let kel = GitKel::new(&repo, prefix);
    let events = kel
        .get_events()
        .map_err(|e| InitError::Keri(e.to_string()))?;
    let state = validate_kel(&events).map_err(|e| InitError::Keri(e.to_string()))?;

    let derived_next_alias =
        KeyAlias::new_unchecked(format!("{}--next-{}", current_alias, state.sequence));

    let (did_check, _role, encrypted_next) = keychain.load_key(&derived_next_alias)?;

    if did != did_check {
        return Err(InitError::InvalidData(format!(
            "DID mismatch for pre-committed key '{}': expected {}, found {}",
            derived_next_alias, did, did_check
        )));
    }

    let next_pass = passphrase_provider.get_passphrase(&format!(
        "Enter passphrase for pre-committed key '{}':",
        derived_next_alias
    ))?;
    let decrypted_next_pkcs8 =
        Pkcs8Der::new(decrypt_keypair(&encrypted_next, &next_pass)?.to_vec());

    let rotation_result = rotate_keys(
        &repo,
        &Prefix::new_unchecked(prefix.to_string()),
        &decrypted_next_pkcs8,
        witness_config,
        now,
    )
    .map_err(|e| InitError::Keri(e.to_string()))?;

    let new_pass = passphrase_provider.get_passphrase(&format!(
        "Create passphrase for new key alias '{}':",
        next_alias
    ))?;
    let confirm_pass =
        passphrase_provider.get_passphrase(&format!("Confirm passphrase for '{}':", next_alias))?;
    if new_pass != confirm_pass {
        return Err(InitError::InvalidData(format!(
            "Passphrases do not match for alias '{}'",
            next_alias
        )));
    }

    let encrypted_new_current = encrypt_keypair(decrypted_next_pkcs8.as_ref(), &new_pass)?;
    keychain.store_key(next_alias, &did, KeyRole::Primary, &encrypted_new_current)?;

    let new_next_seed = extract_seed_bytes(rotation_result.new_next_keypair_pkcs8.as_ref())?;
    let encrypted_future = encrypt_keypair(&encode_seed_as_pkcs8(new_next_seed)?, &new_pass)?;

    let future_key_alias =
        KeyAlias::new_unchecked(format!("{}--next-{}", next_alias, rotation_result.sequence));
    keychain.store_key(
        &future_key_alias,
        &did,
        KeyRole::NextRotation,
        &encrypted_future,
    )?;

    let _ = keychain.delete_key(&derived_next_alias);
    log::debug!("Cleaned up pre-committed key: {}", derived_next_alias);

    Ok(RotationKeyInfo {
        sequence: rotation_result.sequence,
        new_current_pkcs8: rotation_result.new_current_keypair_pkcs8,
        new_next_pkcs8: rotation_result.new_next_keypair_pkcs8,
    })
}

/// Rotates a KERI identity using the packed registry backend.
///
/// Reads and writes the KEL via `refs/auths/registry` (packed single-ref storage).
/// Use [`rotate_keri_identity`] for the legacy GitKel backend.
///
/// Args:
/// * `backend` - The registry backend holding the identity KEL.
/// * `current_alias` - Keychain alias for the current signing keypair.
/// * `next_alias` - Keychain alias to store the **new** current keypair under (after rotation).
/// * `passphrase_provider` - Service to get passphrases for key decryption/re-encryption.
/// * `_config` - Storage layout configuration (unused but kept for API compatibility).
/// * `keychain` - Keychain storage implementation.
/// * `witness_config` - Optional witness configuration.
///
/// Usage:
/// ```ignore
/// let info = rotate_registry_identity(Arc::new(my_backend), "current", "next", &provider, &config, &keychain, None)?;
/// ```
#[allow(clippy::too_many_lines)]
pub fn rotate_registry_identity(
    backend: Arc<dyn RegistryBackend + Send + Sync>,
    current_alias: &KeyAlias,
    next_alias: &KeyAlias,
    passphrase_provider: &dyn PassphraseProvider,
    _config: &StorageLayoutConfig,
    keychain: &(dyn KeyStorage + Send + Sync),
    witness_config: Option<&WitnessConfig>,
) -> Result<RotationKeyInfo, InitError> {
    let rng = SystemRandom::new();

    let (did, _role, _encrypted_current) = keychain.load_key(current_alias)?;

    let prefix_str = did.as_str().strip_prefix("did:keri:").ok_or_else(|| {
        InitError::InvalidData(format!("Invalid DID format, expected 'did:keri:': {}", did))
    })?;
    let prefix = Prefix::new_unchecked(prefix_str.to_string());

    let state = backend
        .get_key_state(&prefix)
        .map_err(|e| InitError::Registry(e.to_string()))?;

    let derived_next_alias =
        KeyAlias::new_unchecked(format!("{}--next-{}", current_alias, state.sequence));

    let (did_check, _role, encrypted_next) = keychain.load_key(&derived_next_alias)?;

    if did != did_check {
        return Err(InitError::InvalidData(format!(
            "DID mismatch for pre-committed key '{}': expected {}, found {}",
            derived_next_alias, did, did_check
        )));
    }

    let next_pass = passphrase_provider.get_passphrase(&format!(
        "Enter passphrase for pre-committed key '{}':",
        derived_next_alias
    ))?;
    let decrypted_next_pkcs8 =
        Pkcs8Der::new(decrypt_keypair(&encrypted_next, &next_pass)?.to_vec());

    if !state.can_rotate() {
        return Err(InitError::InvalidData(
            "Identity is abandoned (cannot rotate)".into(),
        ));
    }

    let next_keypair = load_keypair_from_der_or_seed(decrypted_next_pkcs8.as_ref())?;

    if !verify_commitment(
        next_keypair.public_key().as_ref(),
        &state.next_commitment[0],
    ) {
        return Err(InitError::InvalidData(
            "Commitment mismatch: next key does not match previous commitment".into(),
        ));
    }

    let new_next_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|e| InitError::Crypto(format!("Key generation failed: {}", e)))?;
    let new_next_keypair = Ed25519KeyPair::from_pkcs8(new_next_pkcs8.as_ref())
        .map_err(|e| InitError::Crypto(format!("Key generation failed: {}", e)))?;

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

    let rot_value = serde_json::to_value(Event::Rot(rot.clone()))
        .map_err(|e| InitError::Keri(format!("Serialization failed: {}", e)))?;
    rot.d = compute_said(&rot_value)
        .map_err(|e| InitError::Keri(format!("SAID computation failed: {}", e)))?;

    let canonical = serialize_for_signing(&Event::Rot(rot.clone()))
        .map_err(|e| InitError::Keri(e.to_string()))?;
    let sig = next_keypair.sign(&canonical);
    rot.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

    backend
        .append_event(&prefix, &Event::Rot(rot))
        .map_err(|e| InitError::Registry(e.to_string()))?;

    store_rotated_keys(
        keychain,
        passphrase_provider,
        &did,
        next_alias,
        &derived_next_alias,
        new_sequence,
        decrypted_next_pkcs8.as_ref(),
        new_next_pkcs8.as_ref(),
    )?;

    Ok(RotationKeyInfo {
        sequence: new_sequence,
        new_current_pkcs8: decrypted_next_pkcs8,
        new_next_pkcs8: Pkcs8Der::new(new_next_pkcs8.as_ref()),
    })
}

#[allow(clippy::too_many_arguments)]
fn store_rotated_keys(
    keychain: &(dyn KeyStorage + Send + Sync),
    passphrase_provider: &dyn PassphraseProvider,
    did: &IdentityDID,
    next_alias: &KeyAlias,
    old_next_alias: &KeyAlias,
    new_sequence: u64,
    current_pkcs8: &[u8],
    new_next_pkcs8: &[u8],
) -> Result<(), InitError> {
    let new_pass = passphrase_provider.get_passphrase(&format!(
        "Create passphrase for new key alias '{}':",
        next_alias
    ))?;
    let confirm_pass =
        passphrase_provider.get_passphrase(&format!("Confirm passphrase for '{}':", next_alias))?;
    if new_pass != confirm_pass {
        return Err(InitError::InvalidData(format!(
            "Passphrases do not match for alias '{}'",
            next_alias
        )));
    }

    let encrypted_new_current = encrypt_keypair(current_pkcs8, &new_pass)?;
    keychain.store_key(next_alias, did, KeyRole::Primary, &encrypted_new_current)?;

    let new_next_seed = extract_seed_bytes(new_next_pkcs8)?;
    let encrypted_future = encrypt_keypair(&encode_seed_as_pkcs8(new_next_seed)?, &new_pass)?;

    let future_key_alias =
        KeyAlias::new_unchecked(format!("{}--next-{}", next_alias, new_sequence));
    keychain.store_key(
        &future_key_alias,
        did,
        KeyRole::NextRotation,
        &encrypted_future,
    )?;

    let _ = keychain.delete_key(old_next_alias);

    Ok(())
}
