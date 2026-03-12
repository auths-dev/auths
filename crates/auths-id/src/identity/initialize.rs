//! KERI identity initialization wrapper.
//!
//! This module provides a high-level wrapper around the KERI inception
//! functionality, handling key storage and identity registration.

use std::sync::Arc;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use git2::Repository;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::path::Path;

use crate::error::InitError;

use crate::identity::helpers::{encode_seed_as_pkcs8, extract_seed_bytes};
use crate::keri::{
    Event, IcpEvent, KERI_VERSION, KeriSequence, Prefix, Said, create_keri_identity,
    finalize_icp_event, serialize_for_signing,
};
use crate::storage::identity::IdentityStorage;
use crate::storage::registry::RegistryBackend;
use crate::witness_config::WitnessConfig;

use auths_core::{
    crypto::said::compute_next_commitment,
    crypto::signer::encrypt_keypair,
    signing::PassphraseProvider,
    storage::keychain::{IdentityDID, KeyAlias, KeyRole, KeyStorage},
};

/// Initializes a new KERI identity and stores the keypairs with committed rotation support.
///
/// Args:
/// * `repo_path` - Path to the Git repository.
/// * `local_key_alias` - Alias for storing the key in the keychain.
/// * `metadata` - Optional metadata to associate with the identity.
/// * `passphrase_provider` - Provider for key encryption passphrase.
/// * `identity_storage` - Storage backend for persisting the identity.
/// * `keychain` - Key storage backend.
///
/// Usage:
/// ```ignore
/// let (did, alias) = initialize_keri_identity(&path, "my-key", None, &provider, &storage, &keychain)?;
/// ```
pub fn initialize_keri_identity(
    repo_path: &Path,
    local_key_alias: &KeyAlias,
    metadata: Option<serde_json::Value>,
    passphrase_provider: &dyn PassphraseProvider,
    identity_storage: &dyn IdentityStorage,
    keychain: &(dyn KeyStorage + Send + Sync),
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(IdentityDID, KeyAlias), InitError> {
    let repo = Repository::open(repo_path)?;
    let result =
        create_keri_identity(&repo, None, now).map_err(|e| InitError::Keri(e.to_string()))?;
    #[allow(clippy::disallowed_methods)]
    // INVARIANT: create_keri_identity returns a valid did:keri: DID
    let controller_did = IdentityDID::new_unchecked(result.did());

    let passphrase = passphrase_provider
        .get_passphrase(&format!("Enter passphrase for key '{}':", local_key_alias))?;

    let current_seed = extract_seed_bytes(result.current_keypair_pkcs8.as_ref())?;
    let next_seed = extract_seed_bytes(result.next_keypair_pkcs8.as_ref())?;

    let encrypted_current = encrypt_keypair(&encode_seed_as_pkcs8(current_seed)?, &passphrase)?;
    let encrypted_next = encrypt_keypair(&encode_seed_as_pkcs8(next_seed)?, &passphrase)?;

    keychain.store_key(
        local_key_alias,
        &controller_did,
        KeyRole::Primary,
        &encrypted_current,
    )?;
    let next_alias = KeyAlias::new_unchecked(format!("{}--next-0", local_key_alias));
    keychain.store_key(
        &next_alias,
        &controller_did,
        KeyRole::NextRotation,
        &encrypted_next,
    )?;

    identity_storage.create_identity(controller_did.as_str(), metadata)?;

    Ok((controller_did, local_key_alias.clone()))
}

/// Initializes a new KERI identity using the packed registry backend.
///
/// Creates a KERI inception event, appends it to the provided backend, and
/// stores the encrypted keypairs in the keychain.
///
/// Args:
/// * `backend` - The registry backend to store the KERI inception event.
/// * `local_key_alias` - Alias for storing the key in the keychain.
/// * `passphrase_provider` - Provider for key encryption passphrase.
/// * `keychain` - Key storage backend.
/// * `witness_config` - Optional witness configuration.
///
/// Usage:
/// ```ignore
/// let (did, alias) = initialize_registry_identity(Arc::new(my_backend), "my-key", &provider, &keychain, None)?;
/// ```
pub fn initialize_registry_identity(
    backend: Arc<dyn RegistryBackend + Send + Sync>,
    local_key_alias: &KeyAlias,
    passphrase_provider: &dyn PassphraseProvider,
    keychain: &(dyn KeyStorage + Send + Sync),
    witness_config: Option<&WitnessConfig>,
) -> Result<(IdentityDID, KeyAlias), InitError> {
    backend
        .init_if_needed()
        .map_err(|e| InitError::Registry(e.to_string()))?;

    let rng = SystemRandom::new();
    let current_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|e| InitError::Crypto(format!("Key generation failed: {}", e)))?;
    let current_keypair = Ed25519KeyPair::from_pkcs8(current_pkcs8.as_ref())
        .map_err(|e| InitError::Crypto(format!("Key generation failed: {}", e)))?;
    let next_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|e| InitError::Crypto(format!("Key generation failed: {}", e)))?;
    let next_keypair = Ed25519KeyPair::from_pkcs8(next_pkcs8.as_ref())
        .map_err(|e| InitError::Crypto(format!("Key generation failed: {}", e)))?;

    let current_pub_encoded = format!(
        "D{}",
        URL_SAFE_NO_PAD.encode(current_keypair.public_key().as_ref())
    );
    let next_commitment = compute_next_commitment(next_keypair.public_key().as_ref());

    let (bt, b) = match witness_config {
        Some(cfg) if cfg.is_enabled() => (
            cfg.threshold.to_string(),
            cfg.witness_urls.iter().map(|u| u.to_string()).collect(),
        ),
        _ => ("0".to_string(), vec![]),
    };

    let icp = IcpEvent {
        v: KERI_VERSION.to_string(),
        d: Said::default(),
        i: Prefix::default(),
        s: KeriSequence::new(0),
        kt: "1".to_string(),
        k: vec![current_pub_encoded],
        nt: "1".to_string(),
        n: vec![next_commitment],
        bt,
        b,
        a: vec![],
        x: String::new(),
    };

    let mut finalized = finalize_icp_event(icp).map_err(|e| InitError::Keri(e.to_string()))?;
    let prefix = finalized.i.clone();

    let canonical = serialize_for_signing(&Event::Icp(finalized.clone()))
        .map_err(|e| InitError::Keri(e.to_string()))?;
    let sig = current_keypair.sign(&canonical);
    finalized.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

    backend
        .append_event(&prefix, &Event::Icp(finalized))
        .map_err(|e| InitError::Registry(e.to_string()))?;

    #[allow(clippy::disallowed_methods)]
    // INVARIANT: prefix is from finalize_icp_event, guaranteed valid did:keri format
    let controller_did = IdentityDID::new_unchecked(format!("did:keri:{}", prefix));

    let passphrase = passphrase_provider
        .get_passphrase(&format!("Enter passphrase for key '{}':", local_key_alias))?;

    let current_seed = extract_seed_bytes(current_pkcs8.as_ref())?;
    let next_seed = extract_seed_bytes(next_pkcs8.as_ref())?;

    let encrypted_current = encrypt_keypair(&encode_seed_as_pkcs8(current_seed)?, &passphrase)?;
    let encrypted_next = encrypt_keypair(&encode_seed_as_pkcs8(next_seed)?, &passphrase)?;

    keychain.store_key(
        local_key_alias,
        &controller_did,
        KeyRole::Primary,
        &encrypted_current,
    )?;
    let next_alias = KeyAlias::new_unchecked(format!("{}--next-0", local_key_alias));
    keychain.store_key(
        &next_alias,
        &controller_did,
        KeyRole::NextRotation,
        &encrypted_next,
    )?;

    Ok((controller_did, local_key_alias.clone()))
}
