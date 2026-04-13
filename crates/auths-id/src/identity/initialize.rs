//! KERI identity initialization wrapper.
//!
//! This module provides a high-level wrapper around the KERI inception
//! functionality, handling key storage and identity registration.

use std::sync::Arc;

use crate::keri::inception::create_keri_identity_with_curve;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use git2::Repository;
use std::path::Path;

use crate::error::InitError;

use crate::keri::{
    CesrKey, Event, IcpEvent, KeriSequence, Prefix, Said, Threshold, VersionString,
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
#[allow(clippy::too_many_arguments)]
pub fn initialize_keri_identity(
    repo_path: &Path,
    local_key_alias: &KeyAlias,
    metadata: Option<serde_json::Value>,
    passphrase_provider: &dyn PassphraseProvider,
    identity_storage: &dyn IdentityStorage,
    keychain: &(dyn KeyStorage + Send + Sync),
    now: chrono::DateTime<chrono::Utc>,
    curve: auths_crypto::CurveType,
) -> Result<(IdentityDID, KeyAlias), InitError> {
    let repo = Repository::open(repo_path)?;
    let result = create_keri_identity_with_curve(&repo, None, now, curve)
        .map_err(|e| InitError::Keri(e.to_string()))?;
    #[allow(clippy::disallowed_methods)]
    // INVARIANT: create_keri_identity returns a valid did:keri: DID
    let controller_did = IdentityDID::new_unchecked(result.did());

    let is_hardware_backend = keychain.is_hardware_backend();

    if is_hardware_backend {
        // Hardware backends generate keys internally — no passphrase needed,
        // Touch ID / HSM PIN replaces the passphrase
        keychain.store_key(
            local_key_alias,
            &controller_did,
            KeyRole::Primary,
            &[], // ignored by hardware backends
        )?;
        let next_alias = KeyAlias::new_unchecked(format!("{}--next-0", local_key_alias));
        keychain.store_key(
            &next_alias,
            &controller_did,
            KeyRole::NextRotation,
            &[], // ignored by hardware backends
        )?;
    } else {
        let passphrase = passphrase_provider
            .get_passphrase(&format!("Enter passphrase for key '{}':", local_key_alias))?;

        // pass the curve-tagged PKCS8 blob through unchanged. The old
        // extract-seed + encode_seed_as_pkcs8 pattern silently wrapped P-256
        // scalars in an Ed25519 OID.
        let encrypted_current =
            encrypt_keypair(result.current_keypair_pkcs8.as_ref(), &passphrase)?;
        let encrypted_next = encrypt_keypair(result.next_keypair_pkcs8.as_ref(), &passphrase)?;

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
    }

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
    curve: auths_crypto::CurveType,
) -> Result<(IdentityDID, KeyAlias), InitError> {
    backend
        .init_if_needed()
        .map_err(|e| InitError::Registry(e.to_string()))?;

    let current = crate::keri::inception::generate_keypair_for_init(curve)
        .map_err(|e| InitError::Crypto(e.to_string()))?;
    let next = crate::keri::inception::generate_keypair_for_init(curve)
        .map_err(|e| InitError::Crypto(e.to_string()))?;

    let current_pub_encoded = current.cesr_encoded.clone();
    let next_commitment = compute_next_commitment(&next.public_key);

    let (bt, b) = match witness_config {
        Some(cfg) if cfg.is_enabled() => (
            Threshold::Simple(cfg.threshold as u64),
            cfg.witness_urls
                .iter()
                .map(|u| Prefix::new_unchecked(u.to_string()))
                .collect(),
        ),
        _ => (Threshold::Simple(0), vec![]),
    };

    let icp = IcpEvent {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: Prefix::default(),
        s: KeriSequence::new(0),
        kt: Threshold::Simple(1),
        k: vec![CesrKey::new_unchecked(current_pub_encoded)],
        nt: Threshold::Simple(1),
        n: vec![next_commitment],
        bt,
        b,
        c: vec![],
        a: vec![],
        x: String::new(),
    };

    let mut finalized = finalize_icp_event(icp).map_err(|e| InitError::Keri(e.to_string()))?;
    let prefix = finalized.i.clone();

    let canonical = serialize_for_signing(&Event::Icp(finalized.clone()))
        .map_err(|e| InitError::Keri(e.to_string()))?;
    let sig_bytes =
        crate::keri::inception::sign_with_pkcs8_for_init(curve, &current.pkcs8, &canonical)
            .map_err(|e| InitError::Crypto(e.to_string()))?;
    finalized.x = URL_SAFE_NO_PAD.encode(&sig_bytes);

    backend
        .append_event(&prefix, &Event::Icp(finalized))
        .map_err(|e| InitError::Registry(e.to_string()))?;

    #[allow(clippy::disallowed_methods)]
    // INVARIANT: prefix is from finalize_icp_event, guaranteed valid did:keri format
    let controller_did = IdentityDID::new_unchecked(format!("did:keri:{}", prefix));

    let is_hardware_backend = keychain.is_hardware_backend();

    if is_hardware_backend {
        keychain.store_key(local_key_alias, &controller_did, KeyRole::Primary, &[])?;
        let next_alias = KeyAlias::new_unchecked(format!("{}--next-0", local_key_alias));
        keychain.store_key(&next_alias, &controller_did, KeyRole::NextRotation, &[])?;
    } else {
        let passphrase = passphrase_provider
            .get_passphrase(&format!("Enter passphrase for key '{}':", local_key_alias))?;

        let encrypted_current = encrypt_keypair(current.pkcs8.as_ref(), &passphrase)?;
        let encrypted_next = encrypt_keypair(next.pkcs8.as_ref(), &passphrase)?;

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
    }

    Ok((controller_did, local_key_alias.clone()))
}
