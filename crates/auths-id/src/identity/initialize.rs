//! KERI identity initialization wrapper.
//!
//! This module provides a high-level wrapper around the KERI inception
//! functionality, handling key storage and identity registration.

use std::sync::Arc;

use crate::keri::inception::create_keri_identity_with_curve;
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
    let is_hardware_backend = keychain.is_hardware_backend();
    // Policy preflight: a weak passphrase must abort before any durable write
    // (the KERI inception below writes git refs that cannot be rolled back).
    let passphrase = if is_hardware_backend {
        // Hardware backends generate keys internally — no passphrase needed,
        // Touch ID / HSM PIN replaces the passphrase.
        None
    } else {
        let pass = passphrase_provider
            .get_passphrase(&format!("Enter passphrase for key '{}':", local_key_alias))?;
        auths_core::crypto::encryption::validate_passphrase(&pass)?;
        Some(pass)
    };

    let repo = Repository::open(repo_path)?;
    let result = create_keri_identity_with_curve(&repo, None, now, curve)
        .map_err(|e| InitError::Keri(e.to_string()))?;
    let controller_did =
        IdentityDID::try_from(&result.prefix).map_err(|e| InitError::Keri(e.to_string()))?;

    // pass the curve-tagged PKCS8 blob through unchanged. The old
    // extract-seed + encode_seed_as_pkcs8 pattern silently wrapped P-256
    // scalars in an Ed25519 OID.
    let (current_data, next_data) = match &passphrase {
        None => (Vec::new(), Vec::new()),
        Some(pass) => (
            encrypt_keypair(result.current_keypair_pkcs8.as_ref(), pass)?,
            encrypt_keypair(result.next_keypair_pkcs8.as_ref(), pass)?,
        ),
    };

    let next_alias = KeyAlias::new_unchecked(format!("{}--next-0", local_key_alias));
    keychain.store_key(
        local_key_alias,
        &controller_did,
        KeyRole::Primary,
        &current_data,
    )?;
    if let Err(e) = keychain.store_key(
        &next_alias,
        &controller_did,
        KeyRole::NextRotation,
        &next_data,
    ) {
        let _ = keychain.delete_key(local_key_alias);
        return Err(e.into());
    }
    if let Err(e) = identity_storage.create_identity(controller_did.as_str(), metadata) {
        let _ = keychain.delete_key(local_key_alias);
        let _ = keychain.delete_key(&next_alias);
        return Err(e.into());
    }

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

    if keychain.is_hardware_backend() {
        return initialize_hardware_registry_identity(
            backend,
            local_key_alias,
            passphrase_provider,
            keychain,
            witness_config,
            curve,
        );
    }

    let current = crate::keri::inception::generate_keypair_for_init(curve)
        .map_err(|e| InitError::Crypto(e.to_string()))?;
    let next = crate::keri::inception::generate_keypair_for_init(curve)
        .map_err(|e| InitError::Crypto(e.to_string()))?;

    // Encrypt BEFORE any durable write: a weak passphrase (or any crypto
    // failure) must abort with zero side effects — never an orphaned identity
    // whose keys were rejected after the registry already recorded it.
    let passphrase = passphrase_provider
        .get_passphrase(&format!("Enter passphrase for key '{}':", local_key_alias))?;
    let encrypted_current = encrypt_keypair(current.pkcs8.as_ref(), &passphrase)?;
    let encrypted_next = encrypt_keypair(next.pkcs8.as_ref(), &passphrase)?;

    let current_pub_encoded = current.cesr_encoded.clone();
    let next_commitment = compute_next_commitment(&next.verkey());

    let (bt, b) = match witness_config {
        Some(cfg) if cfg.is_enabled() => (
            Threshold::Simple(cfg.threshold as u64),
            cfg.aids().cloned().collect(),
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
    };

    let finalized = finalize_icp_event(icp).map_err(|e| InitError::Keri(e.to_string()))?;
    let prefix = finalized.i.clone();

    let canonical = serialize_for_signing(&Event::Icp(finalized.clone()))
        .map_err(|e| InitError::Keri(e.to_string()))?;
    let sig_bytes =
        crate::keri::inception::sign_with_pkcs8_for_init(curve, &current.pkcs8, &canonical)
            .map_err(|e| InitError::Crypto(e.to_string()))?;
    let attachment = auths_keri::serialize_attachment(&[auths_keri::IndexedSignature {
        index: 0,
        prior_index: None,
        sig: sig_bytes,
    }])
    .map_err(|e| InitError::Keri(format!("attachment serialization: {e}")))?;

    let controller_did =
        IdentityDID::try_from(&prefix).map_err(|e| InitError::Keri(e.to_string()))?;

    // Keys land first, then the registry append is the commit point. A failure
    // at any step rolls back the keys already stored, so a failed init leaves
    // the machine exactly as it found it.
    let next_alias = KeyAlias::new_unchecked(format!("{}--next-0", local_key_alias));
    keychain.store_key(
        local_key_alias,
        &controller_did,
        KeyRole::Primary,
        &encrypted_current,
    )?;
    if let Err(e) = keychain.store_key(
        &next_alias,
        &controller_did,
        KeyRole::NextRotation,
        &encrypted_next,
    ) {
        let _ = keychain.delete_key(local_key_alias);
        return Err(e.into());
    }
    if let Err(e) = backend.append_signed_event(&prefix, &Event::Icp(finalized), &attachment) {
        let _ = keychain.delete_key(local_key_alias);
        let _ = keychain.delete_key(&next_alias);
        return Err(InitError::Registry(e.to_string()));
    }

    Ok((controller_did, local_key_alias.clone()))
}

/// Initializes a KERI identity whose keys live in a hardware backend (Secure Enclave).
///
/// Hardware keys cannot be generated in software and imported — the backend
/// generates them internally. The inception therefore runs in the opposite
/// order from the software path: generate the hardware keys first, read their
/// public halves back, incept the KEL with the *hardware* current key, sign
/// the inception event through the hardware, and finally rebind the stored
/// keys to the derived identity prefix.
///
/// Args:
/// * `backend` — The registry backend to store the KERI inception event.
/// * `local_key_alias` — Alias for the primary signing key.
/// * `passphrase_provider` — Unused by hardware signing, threaded for the trait API.
/// * `keychain` — Hardware key storage backend.
/// * `witness_config` — Optional witness configuration.
/// * `curve` — Must be P-256 (the only curve hardware backends support).
///
/// Usage:
/// ```ignore
/// let (did, alias) = initialize_hardware_registry_identity(
///     backend, &alias, &provider, keychain, None, CurveType::P256,
/// )?;
/// ```
fn initialize_hardware_registry_identity(
    backend: Arc<dyn RegistryBackend + Send + Sync>,
    local_key_alias: &KeyAlias,
    passphrase_provider: &dyn PassphraseProvider,
    keychain: &(dyn KeyStorage + Send + Sync),
    witness_config: Option<&WitnessConfig>,
    curve: auths_crypto::CurveType,
) -> Result<(IdentityDID, KeyAlias), InitError> {
    if curve != auths_crypto::CurveType::P256 {
        return Err(InitError::Crypto(format!(
            "hardware-backed inception supports P-256 only, got {curve:?}"
        )));
    }

    #[allow(clippy::expect_used)]
    // INVARIANT: compile-time literal carries the `did:keri:` scheme with a non-empty
    // identifier, so parse cannot fail. The stored value is rebound to the real
    // did:keri prefix before this function returns.
    let placeholder = IdentityDID::parse("did:keri:pending").expect("literal did:keri: is valid");
    let next_alias = KeyAlias::new_unchecked(format!("{}--next-0", local_key_alias));

    keychain.store_key(local_key_alias, &placeholder, KeyRole::Primary, &[])?;
    if let Err(e) = keychain.store_key(&next_alias, &placeholder, KeyRole::NextRotation, &[]) {
        let _ = keychain.delete_key(local_key_alias);
        return Err(e.into());
    }

    // Hardware keys exist from here on. Any later failure must delete them —
    // an orphaned hardware key with a `pending` identity is unusable and blocks
    // re-initialization under the same alias.
    let result = incept_with_hardware_keys(
        &backend,
        local_key_alias,
        &next_alias,
        keychain,
        witness_config,
        curve,
    );
    if result.is_err() {
        let _ = keychain.delete_key(local_key_alias);
        let _ = keychain.delete_key(&next_alias);
    }
    let _ = passphrase_provider;
    result.map(|controller_did| (controller_did, local_key_alias.clone()))
}

/// Incept the KEL over already-stored hardware keys and rebind them to the
/// derived prefix. Split out so the caller can delete the hardware keys when any
/// step fails (the rollback that prevents orphaned Secure Enclave keys).
fn incept_with_hardware_keys(
    backend: &Arc<dyn RegistryBackend + Send + Sync>,
    local_key_alias: &KeyAlias,
    next_alias: &KeyAlias,
    keychain: &(dyn KeyStorage + Send + Sync),
    witness_config: Option<&WitnessConfig>,
    curve: auths_crypto::CurveType,
) -> Result<IdentityDID, InitError> {
    let current_pub = keychain.export_public_key(local_key_alias)?;
    let next_pub = keychain.export_public_key(next_alias)?;

    let current_norm = auths_crypto::normalize_verkey(&current_pub, curve)
        .map_err(|e| InitError::Crypto(format!("hardware current key: {e}")))?;
    let next_norm = auths_crypto::normalize_verkey(&next_pub, curve)
        .map_err(|e| InitError::Crypto(format!("hardware next key: {e}")))?;
    let current_verkey = auths_keri::KeriPublicKey::from_verkey_bytes(&current_norm, curve)
        .map_err(|e| InitError::Crypto(format!("hardware current key: {e}")))?;
    let next_verkey = auths_keri::KeriPublicKey::from_verkey_bytes(&next_norm, curve)
        .map_err(|e| InitError::Crypto(format!("hardware next key: {e}")))?;
    let current_cesr = current_verkey
        .to_qb64()
        .map_err(|e| InitError::Crypto(e.to_string()))?;

    let (bt, b) = match witness_config {
        Some(cfg) if cfg.is_enabled() => (
            Threshold::Simple(cfg.threshold as u64),
            cfg.aids().cloned().collect(),
        ),
        _ => (Threshold::Simple(0), vec![]),
    };

    let icp = IcpEvent {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: Prefix::default(),
        s: KeriSequence::new(0),
        kt: Threshold::Simple(1),
        k: vec![CesrKey::new_unchecked(current_cesr)],
        nt: Threshold::Simple(1),
        n: vec![compute_next_commitment(&next_verkey)],
        bt,
        b,
        c: vec![],
        a: vec![],
    };

    let finalized = finalize_icp_event(icp).map_err(|e| InitError::Keri(e.to_string()))?;
    let prefix = finalized.i.clone();

    let canonical = serialize_for_signing(&Event::Icp(finalized.clone()))
        .map_err(|e| InitError::Keri(e.to_string()))?;
    let sig_bytes = keychain.sign_raw(local_key_alias, &canonical)?;
    let attachment = auths_keri::serialize_attachment(&[auths_keri::IndexedSignature {
        index: 0,
        prior_index: None,
        sig: sig_bytes,
    }])
    .map_err(|e| InitError::Keri(format!("attachment serialization: {e}")))?;

    backend
        .append_signed_event(&prefix, &Event::Icp(finalized), &attachment)
        .map_err(|e| InitError::Registry(e.to_string()))?;

    let controller_did =
        IdentityDID::try_from(&prefix).map_err(|e| InitError::Keri(e.to_string()))?;

    keychain.rebind_identity(local_key_alias, &controller_did)?;
    keychain.rebind_identity(next_alias, &controller_did)?;

    Ok(controller_did)
}

/// Initialize a multi-key KERI identity.
///
/// Stores current keys at `{alias}--{idx}` and next keys at
/// `{alias}--next-0-{idx}` for `idx` in `0..curves.len()`.
///
/// Args:
/// * `backend` — The registry backend to store the KERI inception event.
/// * `local_key_alias` — Base alias for storing keys in the keychain.
/// * `passphrase_provider` — Provider for key encryption passphrase.
/// * `keychain` — Key storage backend.
/// * `witness_config` — Optional witness configuration.
/// * `curves` — Non-empty slice of curve choices, one per device slot.
/// * `kt` — Signing threshold. Validated against `curves.len()`.
/// * `nt` — Rotation threshold. Validated against `curves.len()`.
// INVARIANT: all eight parameters are load-bearing inputs for multi-device
// inception — grouping them into a config struct would trade argument count
// for an additional type that adds no safety (every field would still be
// required). Accept the clippy limit here.
#[allow(clippy::too_many_arguments)]
pub fn initialize_registry_identity_multi(
    backend: Arc<dyn RegistryBackend + Send + Sync>,
    local_key_alias: &KeyAlias,
    passphrase_provider: &dyn PassphraseProvider,
    keychain: &(dyn KeyStorage + Send + Sync),
    witness_config: Option<&WitnessConfig>,
    curves: &[auths_crypto::CurveType],
    kt: Threshold,
    nt: Threshold,
) -> Result<(IdentityDID, KeyAlias), InitError> {
    if curves.is_empty() {
        return Err(InitError::Crypto(
            "initialize_registry_identity_multi requires at least one curve".to_string(),
        ));
    }
    crate::keri::inception::validate_threshold_for_key_count(&kt, curves.len())
        .map_err(|e| InitError::Crypto(e.to_string()))?;
    crate::keri::inception::validate_threshold_for_key_count(&nt, curves.len())
        .map_err(|e| InitError::Crypto(e.to_string()))?;

    backend
        .init_if_needed()
        .map_err(|e| InitError::Registry(e.to_string()))?;

    let current_kps = crate::keri::inception::generate_keypairs_for_init(curves)
        .map_err(|e| InitError::Crypto(e.to_string()))?;
    let next_kps = crate::keri::inception::generate_keypairs_for_init(curves)
        .map_err(|e| InitError::Crypto(e.to_string()))?;

    let k: Vec<CesrKey> = current_kps
        .iter()
        .map(|kp| CesrKey::new_unchecked(kp.cesr_encoded.clone()))
        .collect();
    let n: Vec<Said> = next_kps
        .iter()
        .map(|kp| compute_next_commitment(&kp.verkey()))
        .collect();

    let (bt, b) = match witness_config {
        Some(cfg) if cfg.is_enabled() => (
            Threshold::Simple(cfg.threshold as u64),
            cfg.aids().cloned().collect(),
        ),
        _ => (Threshold::Simple(0), vec![]),
    };

    let icp = IcpEvent {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: Prefix::default(),
        s: KeriSequence::new(0),
        kt,
        k,
        nt,
        n,
        bt,
        b,
        c: vec![],
        a: vec![],
    };

    let finalized = finalize_icp_event(icp).map_err(|e| InitError::Keri(e.to_string()))?;
    let prefix = finalized.i.clone();

    // Sign with index 0's current key — single-slot signature. The
    // aggregation module adds additional sigs when `kt` is multi-slot.
    let canonical = serialize_for_signing(&Event::Icp(finalized.clone()))
        .map_err(|e| InitError::Keri(e.to_string()))?;
    let sig_bytes = crate::keri::inception::sign_with_pkcs8_for_init(
        curves[0],
        &current_kps[0].pkcs8,
        &canonical,
    )
    .map_err(|e| InitError::Crypto(e.to_string()))?;
    let attachment = auths_keri::serialize_attachment(&[auths_keri::IndexedSignature {
        index: 0,
        prior_index: None,
        sig: sig_bytes,
    }])
    .map_err(|e| InitError::Keri(format!("attachment serialization: {e}")))?;

    let controller_did =
        IdentityDID::try_from(&prefix).map_err(|e| InitError::Keri(e.to_string()))?;

    let is_hardware_backend = keychain.is_hardware_backend();
    // One passphrase for every slot — prompt once, not once per device slot.
    let passphrase = if is_hardware_backend {
        None
    } else {
        Some(
            passphrase_provider
                .get_passphrase(&format!("Enter passphrase for key '{}':", local_key_alias))?,
        )
    };

    // Keys land first, then the registry append is the commit point. Any
    // failure rolls back every alias stored so far — a failed init leaves the
    // machine exactly as it found it.
    let mut stored: Vec<KeyAlias> = Vec::with_capacity(current_kps.len() * 2);
    let commit_result = store_multi_slot_keys(
        keychain,
        &controller_did,
        local_key_alias,
        &current_kps,
        &next_kps,
        passphrase.as_ref().map(|p| p.as_str()),
        &mut stored,
    )
    .and_then(|()| {
        backend
            .append_signed_event(&prefix, &Event::Icp(finalized), &attachment)
            .map_err(|e| InitError::Registry(e.to_string()))
    });
    if let Err(e) = commit_result {
        for alias in &stored {
            let _ = keychain.delete_key(alias);
        }
        return Err(e);
    }

    Ok((controller_did, local_key_alias.clone()))
}

/// Store every device slot's current + next keypair under
/// `{alias}--{idx}` / `{alias}--next-0-{idx}`, recording each stored alias in
/// `stored` so the caller can roll all of them back if any later step fails.
fn store_multi_slot_keys(
    keychain: &(dyn KeyStorage + Send + Sync),
    controller_did: &IdentityDID,
    local_key_alias: &KeyAlias,
    current_kps: &[crate::keri::inception::GeneratedKeypair],
    next_kps: &[crate::keri::inception::GeneratedKeypair],
    passphrase: Option<&str>,
    stored: &mut Vec<KeyAlias>,
) -> Result<(), InitError> {
    for (idx, (cur, nxt)) in current_kps.iter().zip(next_kps.iter()).enumerate() {
        let cur_alias = KeyAlias::new_unchecked(format!("{}--{}", local_key_alias, idx));
        let nxt_alias = KeyAlias::new_unchecked(format!("{}--next-0-{}", local_key_alias, idx));
        let (cur_data, nxt_data) = match passphrase {
            None => (Vec::new(), Vec::new()),
            Some(pass) => (
                encrypt_keypair(cur.pkcs8.as_ref(), pass)?,
                encrypt_keypair(nxt.pkcs8.as_ref(), pass)?,
            ),
        };
        keychain.store_key(&cur_alias, controller_did, KeyRole::Primary, &cur_data)?;
        stored.push(cur_alias);
        keychain.store_key(&nxt_alias, controller_did, KeyRole::NextRotation, &nxt_data)?;
        stored.push(nxt_alias);
    }
    Ok(())
}
