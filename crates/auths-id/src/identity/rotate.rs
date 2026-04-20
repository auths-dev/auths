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
use crate::identity::helpers::load_keypair_from_der_or_seed;
use crate::keri::{
    CesrKey, Event, GitKel, KeriSequence, Prefix, RotEvent, Said, Threshold, VersionString,
    rotate_keys, serialize_for_signing, validate_kel,
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
    pub sequence: u128,
    /// The new current keypair (PKCS8 DER encoded, zeroed on drop)
    pub new_current_pkcs8: Pkcs8Der,
    /// The new next keypair (PKCS8 DER encoded, zeroed on drop)
    pub new_next_pkcs8: Pkcs8Der,
}

/// Shape of a rotation request: adds, removes, threshold changes.
///
/// A `RotationShape::default()` is a key-set-preserving rotation: same
/// key count and thresholds, only the pre-committed next keys rotate in.
/// Non-default variants drive multi-device topology changes (new device,
/// removed device, threshold change).
#[derive(Debug, Clone, Default)]
pub struct RotationShape {
    /// Curves for newly-added device slots. One fresh keypair is generated
    /// per entry and appended to the new `k` list.
    pub add_devices: Vec<auths_crypto::CurveType>,
    /// Indices into the prior `n` commitment list to exclude from the new
    /// `k` list. Requires CESR indexed-signature support (tracked for a
    /// future pass); current validator rejects asymmetric rotations.
    pub remove_indices: Vec<u32>,
    /// New signing threshold. `None` keeps the prior `kt`.
    pub new_kt: Option<Threshold>,
    /// New next-rotation threshold. `None` keeps the prior `nt`.
    pub new_nt: Option<Threshold>,
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

    if keychain.is_hardware_backend() {
        return Err(InitError::InvalidData(
            "Rotation requires a software-backed key; current key is hardware-backed \
             (Secure Enclave). Rotate by initializing a new identity."
                .into(),
        ));
    }

    let prefix = did.as_str().strip_prefix("did:keri:").ok_or_else(|| {
        InitError::InvalidData(format!("Invalid DID format, expected 'did:keri:': {}", did))
    })?;

    let kel = GitKel::new(&repo, prefix);
    let events = kel
        .get_events()
        .map_err(|e| InitError::Keri(e.to_string()))?;
    let state = validate_kel(&events).map_err(|e| InitError::Keri(e.to_string()))?;

    let derived_next_alias = KeyAlias::new_unchecked(format!(
        "{}--next-{}",
        current_alias, state.last_establishment_sequence
    ));

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

    // pass through the curve-tagged PKCS8 blob directly.
    let encrypted_future =
        encrypt_keypair(rotation_result.new_next_keypair_pkcs8.as_ref(), &new_pass)?;

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

    if keychain.is_hardware_backend() {
        return Err(InitError::InvalidData(
            "Rotation requires a software-backed key; current key is hardware-backed \
             (Secure Enclave). Rotate by initializing a new identity."
                .into(),
        ));
    }

    let prefix_str = did.as_str().strip_prefix("did:keri:").ok_or_else(|| {
        InitError::InvalidData(format!("Invalid DID format, expected 'did:keri:': {}", did))
    })?;
    let prefix = Prefix::new_unchecked(prefix_str.to_string());

    let state = backend
        .get_key_state(&prefix)
        .map_err(|e| InitError::Registry(e.to_string()))?;

    let derived_next_alias = KeyAlias::new_unchecked(format!(
        "{}--next-{}",
        current_alias, state.last_establishment_sequence
    ));

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

    let bt = match witness_config {
        Some(cfg) if cfg.is_enabled() => Threshold::Simple(cfg.threshold as u64),
        _ => Threshold::Simple(0),
    };

    let new_sequence = state.sequence + 1;
    let mut rot = RotEvent {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: prefix.clone(),
        s: KeriSequence::new(new_sequence),
        p: state.last_event_said.clone(),
        kt: Threshold::Simple(1),
        k: vec![CesrKey::new_unchecked(new_current_pub_encoded)],
        nt: Threshold::Simple(1),
        n: vec![new_next_commitment],
        bt,
        br: vec![],
        ba: vec![],
        c: vec![],
        a: vec![],
        dt: None,
    };

    let rot_value = serde_json::to_value(Event::Rot(rot.clone()))
        .map_err(|e| InitError::Keri(format!("Serialization failed: {}", e)))?;
    rot.d = compute_said(&rot_value)
        .map_err(|e| InitError::Keri(format!("SAID computation failed: {}", e)))?;

    let canonical = serialize_for_signing(&Event::Rot(rot.clone()))
        .map_err(|e| InitError::Keri(e.to_string()))?;
    let sig = next_keypair.sign(&canonical);
    let attachment = auths_keri::serialize_attachment(&[auths_keri::IndexedSignature {
        index: 0,
        sig: sig.as_ref().to_vec(),
    }])
    .map_err(|e| InitError::Keri(format!("attachment serialization: {e}")))?;

    backend
        .append_signed_event(&prefix, &Event::Rot(rot), &attachment)
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

/// Rotate a KERI identity with a multi-device shape (registry backend).
///
/// Reveals each prior-committed next key at the matching new `k[i]` slot,
/// optionally appends newly-generated device keypairs from `shape.add_devices`,
/// and optionally applies new `kt`/`nt` thresholds. Produces a signed `rot`
/// event appended to the registry KEL.
///
/// Keychain convention: prior next keys are loaded from
/// `{current_alias}--next-{prev_seq}-{idx}`; new keys are stored at
/// `{next_alias}--{idx}` (current) and `{next_alias}--next-{new_seq}-{idx}`
/// (next).
///
/// Removing devices (`shape.remove_indices` non-empty) requires CESR
/// indexed-signature support and is rejected here; `validate_signed_event`
/// enforces the same restriction at verification time.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn rotate_registry_identity_multi(
    backend: Arc<dyn RegistryBackend + Send + Sync>,
    current_alias: &KeyAlias,
    next_alias: &KeyAlias,
    passphrase_provider: &dyn PassphraseProvider,
    _config: &StorageLayoutConfig,
    keychain: &(dyn KeyStorage + Send + Sync),
    witness_config: Option<&WitnessConfig>,
    shape: RotationShape,
) -> Result<RotationKeyInfo, InitError> {
    if !shape.remove_indices.is_empty() {
        return Err(InitError::InvalidData(
            "Removing device slots requires CESR indexed-signature support (not yet implemented). \
             Rotate with add-only or threshold-only changes; or use expand for migration."
                .to_string(),
        ));
    }

    // Load the base DID from the first current slot and verify the registry.
    let first_cur = KeyAlias::new_unchecked(format!("{}--{}", current_alias, 0));
    let (did, _role, _encrypted) = keychain
        .load_key(&first_cur)
        .or_else(|_| keychain.load_key(current_alias))?;

    if keychain.is_hardware_backend() {
        return Err(InitError::InvalidData(
            "Rotation requires software-backed keys; current slot is hardware-backed.".to_string(),
        ));
    }

    let prefix_str = did.as_str().strip_prefix("did:keri:").ok_or_else(|| {
        InitError::InvalidData(format!("Invalid DID format, expected 'did:keri:': {}", did))
    })?;
    let prefix = Prefix::new_unchecked(prefix_str.to_string());

    let state = backend
        .get_key_state(&prefix)
        .map_err(|e| InitError::Registry(e.to_string()))?;

    if !state.can_rotate() {
        return Err(InitError::InvalidData(
            "Identity is abandoned (cannot rotate)".to_string(),
        ));
    }

    let prior_key_count = state.current_keys.len();
    let new_key_count = prior_key_count + shape.add_devices.len();

    let new_kt = shape.new_kt.unwrap_or_else(|| state.threshold.clone());
    let new_nt = shape.new_nt.unwrap_or_else(|| state.next_threshold.clone());

    crate::keri::inception::validate_threshold_for_key_count(&new_kt, new_key_count)
        .map_err(|e| InitError::InvalidData(e.to_string()))?;
    crate::keri::inception::validate_threshold_for_key_count(&new_nt, new_key_count)
        .map_err(|e| InitError::InvalidData(e.to_string()))?;

    // Decrypt each prior-committed next key in order. These become the new
    // current keys at indices 0..prior_key_count.
    let mut new_current_pkcs8s: Vec<Pkcs8Der> = Vec::with_capacity(prior_key_count);
    let mut new_current_pubs: Vec<Vec<u8>> = Vec::with_capacity(prior_key_count);
    let mut prior_next_aliases: Vec<KeyAlias> = Vec::with_capacity(prior_key_count);

    let next_pass = passphrase_provider.get_passphrase(&format!(
        "Enter passphrase for pre-committed keys under alias '{}':",
        current_alias
    ))?;

    for idx in 0..prior_key_count {
        let alias = KeyAlias::new_unchecked(format!(
            "{}--next-{}-{}",
            current_alias, state.sequence, idx
        ));
        let (did_check, _role, encrypted) = keychain.load_key(&alias)?;
        if did_check != did {
            return Err(InitError::InvalidData(format!(
                "DID mismatch for pre-committed key '{}'",
                alias
            )));
        }
        let pkcs8 = Pkcs8Der::new(decrypt_keypair(&encrypted, &next_pass)?.to_vec());
        let keypair = load_keypair_from_der_or_seed(pkcs8.as_ref())?;
        if !verify_commitment(keypair.public_key().as_ref(), &state.next_commitment[idx]) {
            return Err(InitError::InvalidData(format!(
                "Commitment mismatch at slot {idx}: next key does not match previous commitment"
            )));
        }
        new_current_pubs.push(keypair.public_key().as_ref().to_vec());
        new_current_pkcs8s.push(pkcs8);
        prior_next_aliases.push(alias);
    }

    // Generate added device keypairs and append to the new current set.
    let added = crate::keri::inception::generate_keypairs_for_init(&shape.add_devices)
        .map_err(|e| InitError::Crypto(e.to_string()))?;
    for kp in &added {
        new_current_pubs.push(kp.public_key.clone());
        new_current_pkcs8s.push(kp.pkcs8.clone());
    }

    // Generate a fresh next keypair per new slot.
    let new_next_curves: Vec<auths_crypto::CurveType> = (0..new_key_count)
        .map(|_| auths_crypto::CurveType::P256)
        .collect();
    let new_next_kps = crate::keri::inception::generate_keypairs_for_init(&new_next_curves)
        .map_err(|e| InitError::Crypto(e.to_string()))?;

    let k: Vec<CesrKey> = new_current_pubs
        .iter()
        .map(|pk| CesrKey::new_unchecked(format!("D{}", URL_SAFE_NO_PAD.encode(pk))))
        .collect();
    let n: Vec<Said> = new_next_kps
        .iter()
        .map(|kp| compute_next_commitment(&kp.public_key))
        .collect();

    let bt = match witness_config {
        Some(cfg) if cfg.is_enabled() => Threshold::Simple(cfg.threshold as u64),
        _ => Threshold::Simple(0),
    };

    let new_sequence = state.sequence + 1;
    let mut rot = RotEvent {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: prefix.clone(),
        s: KeriSequence::new(new_sequence),
        p: state.last_event_said.clone(),
        kt: new_kt,
        k,
        nt: new_nt,
        n,
        bt,
        br: vec![],
        ba: vec![],
        c: vec![],
        a: vec![],
        dt: None,
    };

    let rot_value = serde_json::to_value(Event::Rot(rot.clone()))
        .map_err(|e| InitError::Keri(format!("Serialization failed: {}", e)))?;
    rot.d = compute_said(&rot_value)
        .map_err(|e| InitError::Keri(format!("SAID computation failed: {}", e)))?;

    // Sign with index 0's newly-revealed key. Multi-sig aggregation is the
    // signing-workflow module's job.
    let canonical = serialize_for_signing(&Event::Rot(rot.clone()))
        .map_err(|e| InitError::Keri(e.to_string()))?;
    let signer_keypair = load_keypair_from_der_or_seed(new_current_pkcs8s[0].as_ref())?;
    let sig = signer_keypair.sign(&canonical);
    let attachment = auths_keri::serialize_attachment(&[auths_keri::IndexedSignature {
        index: 0,
        sig: sig.as_ref().to_vec(),
    }])
    .map_err(|e| InitError::Keri(format!("attachment serialization: {e}")))?;

    backend
        .append_signed_event(&prefix, &Event::Rot(rot), &attachment)
        .map_err(|e| InitError::Registry(e.to_string()))?;

    // Persist the new current + next keys under {next_alias}--{idx} and
    // {next_alias}--next-{new_seq}-{idx}. Best-effort cleanup of prior
    // pre-committed slots.
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

    for (idx, cur_pkcs8) in new_current_pkcs8s.iter().enumerate() {
        let slot_alias = KeyAlias::new_unchecked(format!("{}--{}", next_alias, idx));
        let encrypted = encrypt_keypair(cur_pkcs8.as_ref(), &new_pass)?;
        keychain.store_key(&slot_alias, &did, KeyRole::Primary, &encrypted)?;
    }
    for (idx, nxt_kp) in new_next_kps.iter().enumerate() {
        let slot_alias =
            KeyAlias::new_unchecked(format!("{}--next-{}-{}", next_alias, new_sequence, idx));
        let encrypted = encrypt_keypair(nxt_kp.pkcs8.as_ref(), &new_pass)?;
        keychain.store_key(&slot_alias, &did, KeyRole::NextRotation, &encrypted)?;
    }
    for alias in &prior_next_aliases {
        let _ = keychain.delete_key(alias);
    }

    // Return info shaped around slot 0 for API compatibility with single-key
    // callers; callers wanting the full multi-key material can regenerate from
    // the keychain via the slot-indexed aliases above.
    let new_next_pkcs8_bytes = new_next_kps[0].pkcs8.as_ref().to_vec();
    Ok(RotationKeyInfo {
        sequence: new_sequence,
        new_current_pkcs8: new_current_pkcs8s
            .into_iter()
            .next()
            .ok_or_else(|| InitError::Crypto("empty current keyset after rotation".to_string()))?,
        new_next_pkcs8: Pkcs8Der::new(new_next_pkcs8_bytes),
    })
}

#[allow(clippy::too_many_arguments)]
fn store_rotated_keys(
    keychain: &(dyn KeyStorage + Send + Sync),
    passphrase_provider: &dyn PassphraseProvider,
    did: &IdentityDID,
    next_alias: &KeyAlias,
    old_next_alias: &KeyAlias,
    new_sequence: u128,
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

    // pass-through avoids the extract-then-re-encode silent-Ed25519 hazard.
    let encrypted_future = encrypt_keypair(new_next_pkcs8, &new_pass)?;

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
