//! Identity rotation workflow.
//!
//! Three-phase design:
//! 1. `compute_rotation_event` — pure, deterministic RotEvent construction.
//! 2. `apply_rotation` — side-effecting KEL append + keychain write.
//! 3. `rotate_identity` — high-level orchestrator (calls both phases in order).

use zeroize::Zeroizing;

use auths_core::crypto::signer::{decrypt_keypair, encrypt_keypair, load_seed_and_pubkey};
use auths_core::ports::clock::ClockProvider;
use auths_core::storage::keychain::{
    IdentityDID, KeyAlias, KeyRole, KeyStorage, extract_public_key_bytes,
};
use auths_crypto::Pkcs8Der;
use auths_id::identity::helpers::ManagedIdentity;
use auths_id::keri::inception::generate_keypair_for_init;
use auths_id::keri::{
    CesrKey, Event, KeriSequence, KeyState, Prefix, RotEvent, Said, Threshold, VersionString,
    serialize_for_signing,
};
use auths_id::ports::registry::RegistryBackend;
use auths_id::witness_config::WitnessConfig;
use auths_keri::{compute_next_commitment, compute_said, verify_commitment};

use crate::context::AuthsContext;
use crate::domains::identity::error::RotationError;
use crate::domains::identity::types::IdentityRotationConfig;
use crate::domains::identity::types::IdentityRotationResult;

/// Computes a KERI rotation event and its canonical serialization.
///
/// Pure function — deterministic given fixed inputs. Embeds the CESR-encoded
/// public key of `next_signer` (the pre-committed future key becoming the new
/// current key) into the rot event; signature attachment happens at the KEL
/// append boundary in `apply_rotation`. `new_next_public_key` is the raw
/// public key bytes of the freshly generated key committed for the next
/// rotation.
///
/// Args:
/// * `state`: Current key state from the registry.
/// * `next_signer`: Pre-committed next signer (becomes new current signer after rotation).
/// * `new_next_public_key`: Raw public key bytes for the next rotation commitment.
/// * `new_next_curve`: Curve type of the next rotation key (plumbed for future use).
/// * `witness_config`: Optional witness configuration.
///
/// Returns `(event, canonical_bytes)` where `canonical_bytes` is the exact
/// byte sequence to write to the KEL — do not re-serialize.
///
/// Usage:
/// ```ignore
/// let (rot, bytes) = compute_rotation_event(
///     &state,
///     &next_signer,
///     new_next_signer.public_key(),
///     new_next_signer.curve(),
///     None,
/// )?;
/// ```
pub fn compute_rotation_event(
    state: &KeyState,
    next_signer: &auths_crypto::TypedSignerKey,
    new_next_public_key: &[u8],
    new_next_curve: auths_crypto::CurveType,
    witness_config: Option<&WitnessConfig>,
) -> Result<(RotEvent, Vec<u8>), RotationError> {
    let prefix = &state.prefix;

    let new_current_pub_encoded = next_signer.cesr_encoded();
    let new_next_verkey =
        auths_keri::KeriPublicKey::from_verkey_bytes(new_next_public_key, new_next_curve)
            .map_err(|e| RotationError::RotationFailed(format!("next verkey: {e}")))?;
    let new_next_commitment = compute_next_commitment(&new_next_verkey);

    // Witness-set change expressed as br/ba deltas vs the prior backer set
    // (cuts then adds; bt over the resolved new set). Enabled: converge on the
    // configured witnesses. Disabled: cut all prior backers.
    let (bt, br, ba) = match witness_config {
        Some(cfg) if cfg.is_enabled() => {
            let desired: Vec<Prefix> = cfg.aids().cloned().collect();
            let (br, ba) = witness_set_delta(&state.backers, &desired);
            let bt = Threshold::Simple((cfg.threshold as u64).min(desired.len() as u64));
            (bt, br, ba)
        }
        _ => (Threshold::Simple(0), state.backers.clone(), vec![]),
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
        br,
        ba,
        c: vec![],
        a: vec![],
    };

    let rot_value = serde_json::to_value(Event::Rot(rot.clone()))
        .map_err(|e| RotationError::RotationFailed(format!("serialization failed: {e}")))?;
    rot.d = compute_said(&rot_value)
        .map_err(|e| RotationError::RotationFailed(format!("SAID computation failed: {e}")))?;

    let event_bytes = serialize_for_signing(&Event::Rot(rot.clone()))
        .map_err(|e| RotationError::RotationFailed(format!("final serialization failed: {e}")))?;

    Ok((rot, event_bytes))
}

/// Compute the `(cuts, adds)` backer deltas that converge the prior backer set
/// onto `desired`.
///
/// Cuts (`br`) are prior backers no longer desired; adds (`ba`) are desired
/// backers not already present. The two are disjoint, so applying cuts-before-
/// adds to `prior` yields exactly `desired` — the witness-set-change semantics a
/// `rot` event encodes. Avoids re-adding an already-present backer (which the
/// validator's backer-delta rules reject).
///
/// Args:
/// * `prior`: The backer set in force before this rotation.
/// * `desired`: The configured target backer set.
fn witness_set_delta(prior: &[Prefix], desired: &[Prefix]) -> (Vec<Prefix>, Vec<Prefix>) {
    let desired_set: std::collections::HashSet<&str> = desired.iter().map(|p| p.as_str()).collect();
    let prior_set: std::collections::HashSet<&str> = prior.iter().map(|p| p.as_str()).collect();
    let br = prior
        .iter()
        .filter(|p| !desired_set.contains(p.as_str()))
        .cloned()
        .collect();
    let ba = desired
        .iter()
        .filter(|p| !prior_set.contains(p.as_str()))
        .cloned()
        .collect();
    (br, ba)
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
/// * `rot_attachment`: The `rot` event's CESR signature attachment, so a later
///   `export-bundle` can authenticate the rotation (RT-002) rather than fail with
///   "no stored signature attachment".
/// * `key_material`: Encrypted key material and aliases for keychain operations.
/// * `registry`: Registry backend for KEL append.
/// * `key_storage`: Keychain for storing rotated key material.
///
/// Usage:
/// ```ignore
/// apply_rotation(&rot, prefix, &attachment, key_material, registry.as_ref(), key_storage.as_ref())?;
/// ```
pub fn apply_rotation(
    rot: &RotEvent,
    prefix: &Prefix,
    rot_attachment: &[u8],
    key_material: RotationKeyMaterial,
    registry: &(dyn RegistryBackend + Send + Sync),
    key_storage: &(dyn KeyStorage + Send + Sync),
) -> Result<(), RotationError> {
    registry
        .append_signed_event(prefix, &Event::Rot(rot.clone()), rot_attachment)
        .map_err(|e| RotationError::RotationFailed(format!("KEL append failed: {e}")))?;

    // NOTE: non-atomic — KEL and keychain writes are not transactional.
    // If the keychain write fails here, the KEL is already ahead.
    let keychain_result = (|| {
        // Snapshot stale primaries before storing the new one, so the new
        // alias can never be swept by the cleanup below.
        let stale_primaries: Vec<KeyAlias> = key_storage
            .list_aliases_for_identity_with_role(&key_material.did, KeyRole::Primary)
            .unwrap_or_default()
            .into_iter()
            .filter(|alias| *alias != key_material.next_alias)
            .collect();

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

        // Key cleanup is no longer best-effort (RT-014): a swallowed delete
        // failure can leave a rotated-away key in storage, re-introducing the
        // nondeterministic current-key enumeration class (#252/#253) where a
        // stale key signs again. Collect failures and fail the rotation so the
        // caller retries cleanup rather than silently trusting it succeeded.
        let mut cleanup_errors: Vec<String> = Vec::new();

        if let Err(e) = key_storage.delete_key(&key_material.old_next_alias) {
            cleanup_errors.push(format!(
                "old next-rotation key '{}': {e}",
                key_material.old_next_alias.as_str()
            ));
        }

        // Delete the rotated-away primary keys. Leaving them as Primary made
        // current-key resolution and delegation signing pick a stale key when
        // keychain enumeration returned multiple primaries. A rotated-away key
        // must never sign again — verification replays public keys from the KEL,
        // so the old private key serves no further purpose.
        for stale in stale_primaries {
            if let Err(e) = key_storage.delete_key(&stale) {
                cleanup_errors.push(format!("rotated-away primary '{}': {e}", stale.as_str()));
            }
        }

        if !cleanup_errors.is_empty() {
            return Err(format!(
                "rotation advanced the KEL but key cleanup failed for {} key(s) — a \
                 rotated-away key may persist and must be removed: {}",
                cleanup_errors.len(),
                cleanup_errors.join("; ")
            ));
        }

        Ok::<(), String>(())
    })();

    keychain_result.map_err(RotationError::PartialRotation)
}

/// Rotates the signing keys for an existing KERI identity.
///
/// Args:
/// * `config` - Configuration for the rotation including aliases and paths.
/// * `ctx` - The application context containing storage adapters.
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
///     &ctx,
///     &SystemClock,
/// )?;
/// println!("Rotated to: {}...", result.new_key_fingerprint);
/// ```
pub fn rotate_identity(
    config: IdentityRotationConfig,
    ctx: &AuthsContext,
    clock: &dyn ClockProvider,
) -> Result<IdentityRotationResult, RotationError> {
    let (identity, prefix, current_alias) = resolve_rotation_context(&config, ctx)?;
    // Stable alias by default: the rotated-in key lands under the SAME alias the
    // old key held, so everything bound to the alias — git `user.signingkey`,
    // the commit-trailers file, CI env blocks, bundle exports — keeps working
    // across rotations. The rotated-away private key is deleted (it must never
    // sign again; verification replays public keys from the KEL). An explicit
    // `next_key_alias` still overrides for callers that want a new name.
    let next_alias = config
        .next_key_alias
        .unwrap_or_else(|| current_alias.clone());

    let previous_key_fingerprint = extract_previous_fingerprint(ctx, &current_alias)?;

    let state = ctx
        .registry
        .get_key_state(&prefix)
        .map_err(|e| RotationError::KelHistoryFailed(e.to_string()))?;

    let (decrypted_next_pkcs8, old_next_alias) =
        retrieve_precommitted_key(&identity.controller_did, &current_alias, &state, ctx)?;

    let witness_config = witness_config_from_identity(&identity);
    let (rot, new_next_pkcs8) =
        generate_rotation_keys(&state, &decrypted_next_pkcs8, witness_config.as_ref())?;

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
            witness_config: witness_config.as_ref(),
            now: clock.now(),
        },
        ctx,
    )?;

    let (_, new_pubkey, _curve) = load_seed_and_pubkey(&decrypted_next_pkcs8)
        .map_err(|e| RotationError::RotationFailed(e.to_string()))?;

    Ok(IdentityRotationResult {
        controller_did: identity.controller_did,
        new_key_fingerprint: hex::encode(&new_pubkey[..8]),
        previous_key_fingerprint,
        sequence: state.sequence + 1,
        new_key_alias: next_alias.to_string(),
    })
}

/// Resolves the identity and determines which key alias is currently active.
fn resolve_rotation_context(
    config: &IdentityRotationConfig,
    ctx: &AuthsContext,
) -> Result<(ManagedIdentity, Prefix, KeyAlias), RotationError> {
    let identity =
        ctx.identity_storage
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
            let aliases = ctx
                .key_storage
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
    ctx: &AuthsContext,
    current_alias: &KeyAlias,
) -> Result<String, RotationError> {
    let (old_pubkey_bytes, _curve) = extract_public_key_bytes(
        ctx.key_storage.as_ref(),
        current_alias,
        ctx.passphrase_provider.as_ref(),
    )
    .map_err(|e| RotationError::KeyDecryptionFailed(e.to_string()))?;

    Ok(hex::encode(&old_pubkey_bytes[..8]))
}

/// Retrieves and decrypts the key that was committed in the previous KERI event.
fn retrieve_precommitted_key(
    did: &IdentityDID,
    current_alias: &KeyAlias,
    state: &KeyState,
    ctx: &AuthsContext,
) -> Result<(Zeroizing<Vec<u8>>, KeyAlias), RotationError> {
    let target_alias = KeyAlias::new_unchecked(format!(
        "{}--next-{}",
        current_alias, state.last_establishment_sequence
    ));

    let (did_check, _role, encrypted_next) =
        ctx.key_storage.load_key(&target_alias).map_err(|e| {
            RotationError::KeyNotFound(format!(
                "pre-committed next key '{}' not found: {e}",
                target_alias
            ))
        })?;

    if ctx.key_storage.is_hardware_backend() {
        return Err(RotationError::HardwareKeyNotRotatable {
            alias: target_alias.to_string(),
        });
    }

    if did != &did_check {
        return Err(RotationError::RotationFailed(format!(
            "DID mismatch for pre-committed key '{}': expected {}, found {}",
            target_alias, did, did_check
        )));
    }

    let pass = ctx
        .passphrase_provider
        .get_passphrase(&format!(
            "Enter passphrase for pre-committed key '{}':",
            target_alias
        ))
        .map_err(|e| RotationError::KeyDecryptionFailed(e.to_string()))?;

    let decrypted = decrypt_keypair(&encrypted_next, &pass)
        .map_err(|e| RotationError::KeyDecryptionFailed(e.to_string()))?;

    let parsed = auths_crypto::parse_key_material(&decrypted)
        .map_err(|e| RotationError::KeyDecryptionFailed(e.to_string()))?;

    let next_verkey =
        auths_keri::KeriPublicKey::from_verkey_bytes(&parsed.public_key, parsed.seed.curve())
            .map_err(|e| RotationError::RotationFailed(format!("next verkey: {e}")))?;
    if !verify_commitment(&next_verkey, &state.next_commitment[0]) {
        return Err(RotationError::RotationFailed(
            "commitment mismatch: next key does not match previous commitment".into(),
        ));
    }

    Ok((decrypted, target_alias))
}

/// The identity's pinned witness configuration, from its stored metadata.
fn witness_config_from_identity(identity: &ManagedIdentity) -> Option<WitnessConfig> {
    identity
        .metadata
        .as_ref()
        .and_then(|m| m.get("witness_config"))
        .and_then(|wc| serde_json::from_value(wc.clone()).ok())
}

/// Generates the new rotation event and the next forward-looking key commitment.
fn generate_rotation_keys(
    state: &KeyState,
    current_key_pkcs8: &[u8],
    witness_config: Option<&WitnessConfig>,
) -> Result<(RotEvent, Pkcs8Der), RotationError> {
    let next_signer = auths_crypto::TypedSignerKey::from_pkcs8(current_key_pkcs8)
        .map_err(|e| RotationError::KeyDecryptionFailed(e.to_string()))?;

    let generated = generate_keypair_for_init(next_signer.curve())
        .map_err(|e| RotationError::RotationFailed(format!("key generation failed: {e}")))?;

    let (rot, _event_bytes) = compute_rotation_event(
        state,
        &next_signer,
        &generated.public_key,
        next_signer.curve(),
        witness_config,
    )?;

    Ok((rot, generated.pkcs8))
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
    witness_config: Option<&'a WitnessConfig>,
    now: chrono::DateTime<chrono::Utc>,
}

/// Encrypts and persists the new current and next keys to secure storage.
fn finalize_rotation_storage(
    params: FinalizeParams<'_>,
    ctx: &AuthsContext,
) -> Result<(), RotationError> {
    let new_pass = ctx
        .passphrase_provider
        .get_passphrase(&format!(
            "Create passphrase for new key alias '{}':",
            params.next_alias
        ))
        .map_err(|e| RotationError::KeyDecryptionFailed(e.to_string()))?;

    let confirm_pass = ctx
        .passphrase_provider
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

    let encrypted_new_next = encrypt_keypair(params.new_next_pkcs8, &new_pass)
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

    // Sign the rot with the new current key and store its CESR attachment, so a
    // later `export-bundle` can AUTHENTICATE the rotation event (RT-002). Without
    // this the rot has no stored attachment and `id export-bundle` aborts with
    // "KEL event at seq N has no stored signature attachment".
    let parsed = auths_crypto::parse_key_material(params.current_pkcs8)
        .map_err(|e| RotationError::RotationFailed(format!("parse new current key: {e}")))?;
    let canonical = serialize_for_signing(&Event::Rot(params.rot.clone()))
        .map_err(|e| RotationError::RotationFailed(format!("serialize rot for signing: {e}")))?;
    let sig = auths_crypto::typed_sign(&parsed.seed, &canonical)
        .map_err(|e| RotationError::RotationFailed(format!("sign rot: {e}")))?;
    let rot_attachment = auths_keri::serialize_attachment(&[auths_keri::IndexedSignature {
        index: 0,
        prior_index: None,
        sig,
    }])
    .map_err(|e| RotationError::RotationFailed(format!("serialize rot attachment: {e}")))?;

    // Publish the signed rotation to the identity's designated backers before
    // the local append — under Enforce, a missed quorum leaves the KEL
    // untouched, and the backers hold the rotation they are declared to
    // witness.
    #[cfg(feature = "witness-client")]
    {
        let witness = match (params.witness_config, ctx.repo_path.as_deref()) {
            (Some(cfg), Some(path)) => auths_id::witness_config::WitnessParams::Enabled {
                config: cfg,
                repo_path: path,
            },
            _ => auths_id::witness_config::WitnessParams::Disabled,
        };
        auths_id::keri::witness_integration::solicit_receipts_for_event(
            &witness,
            params.prefix,
            &Event::Rot(params.rot.clone()),
            &rot_attachment,
            params.now,
        )
        .map_err(|e| RotationError::RotationFailed(format!("witness receipting: {e}")))?;
    }
    #[cfg(not(feature = "witness-client"))]
    let _ = (params.now, params.witness_config);

    apply_rotation(
        params.rot,
        params.prefix,
        &rot_attachment,
        key_material,
        ctx.registry.as_ref(),
        ctx.key_storage.as_ref(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    use auths_core::PrefilledPassphraseProvider;
    use auths_core::ports::clock::SystemClock;
    use auths_core::signing::{PassphraseProvider, StorageSigner};
    use auths_core::storage::memory::{MEMORY_KEYCHAIN, MemoryKeychainHandle};
    use auths_id::attestation::export::AttestationSink;
    use auths_id::ports::registry::RegistryBackend;
    use auths_id::storage::attestation::AttestationSource;
    use auths_id::storage::identity::IdentityStorage;
    use auths_id::testing::fakes::FakeIdentityStorage;
    use auths_id::testing::fakes::FakeRegistryBackend;
    use auths_id::testing::fakes::{FakeAttestationSink, FakeAttestationSource};

    use crate::domains::identity::service::initialize;
    use crate::domains::identity::types::InitializeResult;
    use crate::domains::identity::types::{CreateDeveloperIdentityConfig, IdentityConfig};
    use crate::domains::signing::types::GitSigningScope;

    /// Serialize tests that touch the process-global `MEMORY_KEYCHAIN`.
    /// Parallel `cargo test` runs let one test's `clear_all()` wipe
    /// another test's just-written keys, which surfaces as a spurious
    /// DID-mismatch under `retrieve_precommitted_key`. Hold this guard
    /// for the lifetime of any test that both writes and reads the
    /// shared keychain.
    fn keychain_test_guard() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        // A poisoned mutex means a previous test panicked while holding
        // the guard; the keychain state is reset by `clear_all()` on
        // the next `fake_ctx` call anyway, so recovering from poison
        // is safe.
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    fn fake_ctx(passphrase: &str) -> (MutexGuard<'static, ()>, AuthsContext) {
        // Hold the keychain serialization guard for the caller's
        // lifetime: the test holds the tuple, the guard drops when the
        // tuple drops. The clear happens *after* we own the lock so no
        // concurrent test can be mid-write.
        let guard = keychain_test_guard();
        MEMORY_KEYCHAIN.lock().unwrap().clear_all().ok();
        let ctx =
            {
                AuthsContext::builder()
                    .registry(Arc::new(FakeRegistryBackend::new())
                        as Arc<dyn RegistryBackend + Send + Sync>)
                    .key_storage(Arc::new(MemoryKeychainHandle))
                    .clock(Arc::new(SystemClock))
                    .identity_storage(Arc::new(FakeIdentityStorage::new())
                        as Arc<dyn IdentityStorage + Send + Sync>)
                    .attestation_sink(Arc::new(FakeAttestationSink::new())
                        as Arc<dyn AttestationSink + Send + Sync>)
                    .attestation_source(Arc::new(FakeAttestationSource::new())
                        as Arc<dyn AttestationSource + Send + Sync>)
                    .passphrase_provider(Arc::new(PrefilledPassphraseProvider::new(passphrase))
                        as Arc<dyn PassphraseProvider + Send + Sync>)
                    .build()
            };
        (guard, ctx)
    }

    fn provision_identity(ctx: &AuthsContext) -> KeyAlias {
        let signer = StorageSigner::new(MemoryKeychainHandle);
        let provider = PrefilledPassphraseProvider::new("Test-passphrase1!");
        let config = CreateDeveloperIdentityConfig::builder(KeyAlias::new_unchecked("test-key"))
            .with_git_signing_scope(GitSigningScope::Skip)
            .with_curve(auths_crypto::CurveType::Ed25519)
            .build();
        let result = match initialize(
            IdentityConfig::Developer(config),
            ctx,
            Arc::new(MemoryKeychainHandle),
            &signer,
            &provider,
            None,
        )
        .unwrap()
        {
            InitializeResult::Developer(r) => r,
            _ => unreachable!(),
        };
        result.key_alias
    }

    // -- resolve_rotation_context --

    #[test]
    fn resolve_rotation_context_returns_identity_and_prefix() {
        let (_keychain_guard, ctx) = fake_ctx("Test-passphrase1!");
        let key_alias = provision_identity(&ctx);

        let config = IdentityRotationConfig {
            repo_path: std::path::PathBuf::from("/unused"),
            identity_key_alias: Some(key_alias.clone()),
            next_key_alias: None,
        };

        let (identity, prefix, alias) = resolve_rotation_context(&config, &ctx).unwrap();
        assert!(identity.controller_did.as_str().starts_with("did:keri:"));
        assert_eq!(
            prefix.as_str(),
            identity
                .controller_did
                .as_str()
                .strip_prefix("did:keri:")
                .unwrap()
        );
        assert_eq!(alias, key_alias);
    }

    #[test]
    fn resolve_rotation_context_auto_discovers_alias() {
        let (_keychain_guard, ctx) = fake_ctx("Test-passphrase1!");
        let _key_alias = provision_identity(&ctx);

        let config = IdentityRotationConfig {
            repo_path: std::path::PathBuf::from("/unused"),
            identity_key_alias: None,
            next_key_alias: None,
        };

        let (_identity, _prefix, alias) = resolve_rotation_context(&config, &ctx).unwrap();
        assert!(!alias.contains("--next-"));
    }

    #[test]
    fn resolve_rotation_context_missing_identity_returns_error() {
        let (_keychain_guard, ctx) = fake_ctx("unused");

        let config = IdentityRotationConfig {
            repo_path: std::path::PathBuf::from("/unused"),
            identity_key_alias: Some(KeyAlias::new_unchecked("any")),
            next_key_alias: None,
        };

        let result = resolve_rotation_context(&config, &ctx);
        assert!(matches!(
            result,
            Err(RotationError::IdentityNotFound { .. })
        ));
    }

    // -- retrieve_precommitted_key --

    #[test]
    fn retrieve_precommitted_key_succeeds_after_setup() {
        let (_keychain_guard, ctx) = fake_ctx("Test-passphrase1!");
        let key_alias = provision_identity(&ctx);

        let config = IdentityRotationConfig {
            repo_path: std::path::PathBuf::from("/unused"),
            identity_key_alias: Some(key_alias.clone()),
            next_key_alias: None,
        };

        let (identity, prefix, _) = resolve_rotation_context(&config, &ctx).unwrap();
        let state = ctx.registry.get_key_state(&prefix).unwrap();

        let (decrypted, old_alias) =
            retrieve_precommitted_key(&identity.controller_did, &key_alias, &state, &ctx).unwrap();

        assert!(!decrypted.is_empty());
        assert!(old_alias.contains("--next-"));
    }

    #[test]
    fn retrieve_precommitted_key_wrong_did_returns_error() {
        let (_keychain_guard, ctx) = fake_ctx("Test-passphrase1!");
        let key_alias = provision_identity(&ctx);

        let config = IdentityRotationConfig {
            repo_path: std::path::PathBuf::from("/unused"),
            identity_key_alias: Some(key_alias.clone()),
            next_key_alias: None,
        };

        let (_, prefix, _) = resolve_rotation_context(&config, &ctx).unwrap();
        let state = ctx.registry.get_key_state(&prefix).unwrap();
        let wrong_did = IdentityDID::parse("did:keri:EWrongDid").unwrap();

        let result = retrieve_precommitted_key(&wrong_did, &key_alias, &state, &ctx);
        assert!(matches!(result, Err(RotationError::RotationFailed(_))));
    }

    #[test]
    fn retrieve_precommitted_key_missing_key_returns_error() {
        let (_keychain_guard, ctx) = fake_ctx("Test-passphrase1!");

        let did = IdentityDID::parse("did:keri:Etest").unwrap();
        let state = KeyState {
            prefix: Prefix::new_unchecked("Etest".to_string()),
            current_keys: vec![],
            next_commitment: vec![],
            sequence: 999,
            last_event_said: Said::default(),
            is_abandoned: false,
            threshold: Threshold::Simple(1),
            next_threshold: Threshold::Simple(1),
            backers: vec![],
            backer_threshold: Threshold::Simple(0),
            config_traits: vec![],
            is_non_transferable: false,
            delegator: None,
            last_establishment_sequence: 0,
        };

        let result = retrieve_precommitted_key(
            &did,
            &KeyAlias::new_unchecked("nonexistent-alias"),
            &state,
            &ctx,
        );
        assert!(matches!(result, Err(RotationError::KeyNotFound(_))));
    }

    // -- generate_rotation_keys --

    #[test]
    fn generate_rotation_keys_produces_valid_event() {
        let (_keychain_guard, ctx) = fake_ctx("Test-passphrase1!");
        let key_alias = provision_identity(&ctx);

        let config = IdentityRotationConfig {
            repo_path: std::path::PathBuf::from("/unused"),
            identity_key_alias: Some(key_alias.clone()),
            next_key_alias: None,
        };

        let (identity, prefix, _) = resolve_rotation_context(&config, &ctx).unwrap();
        let state = ctx.registry.get_key_state(&prefix).unwrap();
        let (decrypted, _) =
            retrieve_precommitted_key(&identity.controller_did, &key_alias, &state, &ctx).unwrap();

        let (rot, new_next_pkcs8) = generate_rotation_keys(&state, &decrypted, None).unwrap();

        assert_eq!(rot.s, KeriSequence::new(state.sequence + 1));
        assert_eq!(rot.i, prefix);
        assert!(!rot.d.is_empty());
        assert!(!new_next_pkcs8.as_ref().is_empty());
    }

    // -- finalize_rotation_storage --

    #[test]
    fn finalize_rotation_storage_persists_keys() {
        let (_keychain_guard, ctx) = fake_ctx("Test-passphrase1!");
        let key_alias = provision_identity(&ctx);

        let config = IdentityRotationConfig {
            repo_path: std::path::PathBuf::from("/unused"),
            identity_key_alias: Some(key_alias.clone()),
            next_key_alias: None,
        };

        let (identity, prefix, _) = resolve_rotation_context(&config, &ctx).unwrap();
        let state = ctx.registry.get_key_state(&prefix).unwrap();
        let (decrypted, old_next_alias) =
            retrieve_precommitted_key(&identity.controller_did, &key_alias, &state, &ctx).unwrap();
        let (rot, new_next_pkcs8) = generate_rotation_keys(&state, &decrypted, None).unwrap();

        let rotated_alias = KeyAlias::new_unchecked("rotated-key");
        let result = finalize_rotation_storage(
            FinalizeParams {
                did: &identity.controller_did,
                prefix: &prefix,
                next_alias: &rotated_alias,
                old_next_alias: &old_next_alias,
                current_pkcs8: &decrypted,
                new_next_pkcs8: new_next_pkcs8.as_ref(),
                rot: &rot,
                state: &state,
                witness_config: None,
                now: chrono::Utc::now(),
            },
            &ctx,
        );

        assert!(
            result.is_ok(),
            "finalize_rotation_storage failed: {:?}",
            result
        );

        let (loaded_did, _, _) = ctx
            .key_storage
            .load_key(&KeyAlias::new_unchecked("rotated-key"))
            .unwrap();
        assert_eq!(loaded_did, identity.controller_did);

        let new_sequence = state.sequence + 1;
        let next_key_alias = format!("rotated-key--next-{}", new_sequence);
        let (loaded_next_did, _, _) = ctx
            .key_storage
            .load_key(&KeyAlias::new_unchecked(&next_key_alias))
            .unwrap();
        assert_eq!(loaded_next_did, identity.controller_did);
    }

    #[test]
    fn finalize_rotation_storage_rejects_mismatched_passphrases() {
        use ring::rand::SystemRandom;
        use ring::signature::Ed25519KeyPair;
        use std::sync::atomic::{AtomicU32, Ordering};

        struct AlternatingProvider {
            call_count: AtomicU32,
        }

        impl PassphraseProvider for AlternatingProvider {
            fn get_passphrase(
                &self,
                _prompt: &str,
            ) -> Result<zeroize::Zeroizing<String>, auths_core::AgentError> {
                let n = self.call_count.fetch_add(1, Ordering::SeqCst);
                if n.is_multiple_of(2) {
                    Ok(zeroize::Zeroizing::new("pass-a".to_string()))
                } else {
                    Ok(zeroize::Zeroizing::new("pass-b".to_string()))
                }
            }
        }

        let prefix = Prefix::new_unchecked("ETestMismatch".to_string());
        let did = IdentityDID::parse("did:keri:ETestMismatch").unwrap();

        let state = KeyState {
            prefix: prefix.clone(),
            current_keys: vec![CesrKey::new_unchecked("D_key".to_string())],
            next_commitment: vec![Said::new_unchecked("hash".to_string())],
            sequence: 0,
            last_event_said: Said::new_unchecked("EPrior".to_string()),
            is_abandoned: false,
            threshold: Threshold::Simple(1),
            next_threshold: Threshold::Simple(1),
            backers: vec![],
            backer_threshold: Threshold::Simple(0),
            config_traits: vec![],
            is_non_transferable: false,
            delegator: None,
            last_establishment_sequence: 0,
        };

        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();

        let dummy_rot = RotEvent {
            v: VersionString::placeholder(),
            d: Said::new_unchecked("E_dummy".to_string()),
            i: prefix.clone(),
            s: KeriSequence::new(1),
            p: Said::default(),
            kt: Threshold::Simple(1),
            k: vec![],
            nt: Threshold::Simple(1),
            n: vec![],
            bt: Threshold::Simple(0),
            br: vec![],
            ba: vec![],
            c: vec![],
            a: vec![],
        };

        let ctx =
            AuthsContext::builder()
                .registry(
                    Arc::new(FakeRegistryBackend::new()) as Arc<dyn RegistryBackend + Send + Sync>
                )
                .key_storage(Arc::new(MemoryKeychainHandle))
                .clock(Arc::new(SystemClock))
                .identity_storage(
                    Arc::new(FakeIdentityStorage::new()) as Arc<dyn IdentityStorage + Send + Sync>
                )
                .attestation_sink(
                    Arc::new(FakeAttestationSink::new()) as Arc<dyn AttestationSink + Send + Sync>
                )
                .attestation_source(Arc::new(FakeAttestationSource::new())
                    as Arc<dyn AttestationSource + Send + Sync>)
                .passphrase_provider(Arc::new(AlternatingProvider {
                    call_count: AtomicU32::new(0),
                })
                    as Arc<dyn PassphraseProvider + Send + Sync>)
                .build();

        let test_alias = KeyAlias::new_unchecked("test-alias");
        let old_alias = KeyAlias::new_unchecked("old-alias");
        let result = finalize_rotation_storage(
            FinalizeParams {
                did: &did,
                prefix: &prefix,
                next_alias: &test_alias,
                old_next_alias: &old_alias,
                current_pkcs8: pkcs8.as_ref(),
                new_next_pkcs8: pkcs8.as_ref(),
                rot: &dummy_rot,
                state: &state,
                witness_config: None,
                now: chrono::Utc::now(),
            },
            &ctx,
        );

        assert!(
            matches!(result, Err(RotationError::RotationFailed(ref msg)) if msg.contains("passphrases do not match")),
            "Expected passphrase mismatch error, got: {:?}",
            result
        );
    }

    // -- rotate_identity preserves curve for the pre-committed next key --

    #[test]
    fn rotate_identity_stores_p256_next_key_as_p256_pkcs8() {
        let (_keychain_guard, ctx) = fake_ctx("Test-passphrase1!");

        let signer = StorageSigner::new(MemoryKeychainHandle);
        let provider = PrefilledPassphraseProvider::new("Test-passphrase1!");
        let config = CreateDeveloperIdentityConfig::builder(KeyAlias::new_unchecked("test-key"))
            .with_git_signing_scope(GitSigningScope::Skip)
            .with_curve(auths_crypto::CurveType::P256)
            .build();
        let key_alias = match initialize(
            IdentityConfig::Developer(config),
            &ctx,
            Arc::new(MemoryKeychainHandle),
            &signer,
            &provider,
            None,
        )
        .unwrap()
        {
            InitializeResult::Developer(r) => r.key_alias,
            _ => unreachable!(),
        };

        let rotation_config = IdentityRotationConfig {
            repo_path: std::path::PathBuf::from("/unused"),
            identity_key_alias: Some(key_alias),
            next_key_alias: Some(KeyAlias::new_unchecked("rotated-key")),
        };

        rotate_identity(rotation_config, &ctx, &SystemClock).unwrap();

        let rot_state = ctx
            .registry
            .get_key_state(
                &auths_id::keri::parse_did_keri(
                    ctx.identity_storage
                        .load_identity()
                        .unwrap()
                        .controller_did
                        .as_str(),
                )
                .unwrap(),
            )
            .unwrap();
        let new_next_alias = KeyAlias::new_unchecked(format!(
            "rotated-key--next-{}",
            rot_state.last_establishment_sequence
        ));
        let (_, _, encrypted_blob) = ctx.key_storage.load_key(&new_next_alias).unwrap();
        let decrypted_pkcs8 = decrypt_keypair(&encrypted_blob, "Test-passphrase1!").unwrap();

        let parsed = auths_crypto::parse_key_material(&decrypted_pkcs8).unwrap();
        assert_eq!(parsed.seed.curve(), auths_crypto::CurveType::P256);
        assert_eq!(
            parsed.public_key.len(),
            33,
            "P-256 compressed public key must be 33 bytes"
        );
    }

    /// Regression: after `rotate_identity`, every KEL event — the inception AND
    /// the rotation — must have a stored signature attachment.
    ///
    /// This is the exact precondition `auths id export-bundle` enforces: it reads
    /// `registry.get_attachment(prefix, seq)` for each event and aborts with "KEL
    /// event at seq N has no stored signature attachment" if any is missing. The
    /// shipped 0.1.3 wheel's rotate dropped the rot attachment, so `export-bundle`
    /// bricked after a rotation and stateless CI verification (a core claim) died
    /// with it. The fix threads the CESR-signed attachment through `apply_rotation`;
    /// this test exists so it can never regress silently again.
    #[test]
    fn rotate_persists_a_signature_attachment_for_every_kel_event() {
        let (_keychain_guard, ctx) = fake_ctx("Test-passphrase1!");

        let signer = StorageSigner::new(MemoryKeychainHandle);
        let provider = PrefilledPassphraseProvider::new("Test-passphrase1!");
        let config = CreateDeveloperIdentityConfig::builder(KeyAlias::new_unchecked("bundle-key"))
            .with_git_signing_scope(GitSigningScope::Skip)
            .build();
        let key_alias = match initialize(
            IdentityConfig::Developer(config),
            &ctx,
            Arc::new(MemoryKeychainHandle),
            &signer,
            &provider,
            None,
        )
        .unwrap()
        {
            InitializeResult::Developer(r) => r.key_alias,
            _ => unreachable!(),
        };

        let rotation_config = IdentityRotationConfig {
            repo_path: std::path::PathBuf::from("/unused"),
            identity_key_alias: Some(key_alias),
            next_key_alias: Some(KeyAlias::new_unchecked("rotated-key")),
        };
        rotate_identity(rotation_config, &ctx, &SystemClock).unwrap();

        let prefix = auths_id::keri::parse_did_keri(
            ctx.identity_storage
                .load_identity()
                .unwrap()
                .controller_did
                .as_str(),
        )
        .unwrap();

        // The rotation advances the KEL to at least seq 1 (icp@0, rot@1). Walk
        // every event and assert its attachment is present and non-empty — exactly
        // what export-bundle does before it will emit a verifiable bundle.
        let tip = ctx.registry.get_key_state(&prefix).unwrap().sequence;
        assert!(tip >= 1, "a rotation must advance the KEL past inception");
        for seq in 0..=tip {
            let att = ctx
                .registry
                .get_attachment(&prefix, seq)
                .unwrap()
                .unwrap_or_else(|| {
                    panic!(
                        "KEL event at seq {seq} has no stored signature attachment — \
                         export-bundle would abort here (the shipped-0.1.3 rotate bug)"
                    )
                });
            assert!(
                !att.is_empty(),
                "attachment for seq {seq} is present but empty — not a real signature"
            );
        }
    }

    fn p(s: &str) -> Prefix {
        Prefix::new_unchecked(s.to_string())
    }

    #[test]
    fn rot_adds_witness_via_ba() {
        let (br, ba) = witness_set_delta(&[], &[p("BW1")]);
        assert!(br.is_empty());
        assert_eq!(ba, vec![p("BW1")]);
    }

    #[test]
    fn rot_removes_witness_via_br() {
        let (br, ba) = witness_set_delta(&[p("BW1")], &[]);
        assert_eq!(br, vec![p("BW1")]);
        assert!(ba.is_empty());
    }

    #[test]
    fn rot_cut_then_readd_dedupes() {
        // w1 already present: it must NOT be re-added; only w2 is added.
        let (br, ba) = witness_set_delta(&[p("BW1")], &[p("BW1"), p("BW2")]);
        assert!(br.is_empty());
        assert_eq!(ba, vec![p("BW2")]);
    }

    #[test]
    fn rot_delta_cuts_and_adds_are_disjoint() {
        // prior {w1,w2} -> desired {w2,w3}: cut w1, add w3, retain w2.
        let (br, ba) = witness_set_delta(&[p("BW1"), p("BW2")], &[p("BW2"), p("BW3")]);
        assert_eq!(br, vec![p("BW1")]);
        assert_eq!(ba, vec![p("BW3")]);
    }
}
