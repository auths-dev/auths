//! Identity rotation workflow.
//!
//! Three-phase design:
//! 1. `compute_rotation_event` — pure, deterministic RotEvent construction.
//! 2. `apply_rotation` — side-effecting KEL append + keychain write.
//! 3. `rotate_identity` — high-level orchestrator (calls both phases in order).

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use zeroize::Zeroizing;

use auths_core::crypto::said::{compute_next_commitment, compute_said, verify_commitment};
use auths_core::crypto::signer::{decrypt_keypair, encrypt_keypair, load_seed_and_pubkey};
use auths_core::ports::clock::ClockProvider;
use auths_core::storage::keychain::{IdentityDID, KeyAlias, KeyStorage, extract_public_key_bytes};
use auths_id::identity::helpers::{
    ManagedIdentity, encode_seed_as_pkcs8, extract_seed_bytes, load_keypair_from_der_or_seed,
};
use auths_id::keri::{
    Event, KERI_VERSION, KeyState, Prefix, RotEvent, Said, serialize_for_signing,
};
use auths_id::ports::registry::RegistryBackend;
use auths_id::witness_config::WitnessConfig;

use crate::context::AuthsContext;
use crate::error::RotationError;
use crate::result::RotationResult;
use crate::types::RotationConfig;

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
        Some(cfg) if cfg.is_enabled() => (cfg.threshold.to_string(), cfg.witness_urls.clone()),
        _ => ("0".to_string(), vec![]),
    };

    let new_sequence = state.sequence + 1;
    let mut rot = RotEvent {
        v: KERI_VERSION.to_string(),
        d: Said::default(),
        i: prefix.clone(),
        s: new_sequence.to_string(),
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
                &key_material.new_current_encrypted,
            )
            .map_err(|e| e.to_string())?;

        key_storage
            .store_key(
                &key_material.new_next_alias,
                &key_material.did,
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
/// * `ctx` - The application context containing storage adapters.
/// * `clock` - Provider for timestamps.
///
/// Usage:
/// ```ignore
/// let result = rotate_identity(
///     RotationConfig {
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
    config: RotationConfig,
    ctx: &AuthsContext,
    clock: &dyn ClockProvider,
) -> Result<RotationResult, RotationError> {
    let (identity, prefix, current_alias) = resolve_rotation_context(&config, ctx)?;
    let next_alias = config.next_key_alias.unwrap_or_else(|| {
        KeyAlias::new_unchecked(format!(
            "{}-rotated-{}",
            current_alias,
            clock.now().format("%Y%m%d%H%M%S")
        ))
    });

    let previous_key_fingerprint = extract_previous_fingerprint(ctx, &current_alias)?;

    let state = ctx
        .registry
        .get_key_state(&prefix)
        .map_err(|e| RotationError::KelHistoryFailed(e.to_string()))?;

    let (decrypted_next_pkcs8, old_next_alias) =
        retrieve_precommitted_key(&identity.controller_did, &current_alias, &state, ctx)?;

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
        ctx,
    )?;

    let (_, new_pubkey) = load_seed_and_pubkey(&decrypted_next_pkcs8)
        .map_err(|e| RotationError::RotationFailed(e.to_string()))?;

    Ok(RotationResult {
        controller_did: identity.controller_did.to_string(),
        new_key_fingerprint: hex::encode(&new_pubkey[..8]),
        previous_key_fingerprint,
    })
}

/// Resolves the identity and determines which key alias is currently active.
fn resolve_rotation_context(
    config: &RotationConfig,
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
    let old_pubkey_bytes = extract_public_key_bytes(
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
    let target_alias =
        KeyAlias::new_unchecked(format!("{}--next-{}", current_alias, state.sequence));

    let (did_check, encrypted_next) = ctx.key_storage.load_key(&target_alias).map_err(|e| {
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

    let pass = ctx
        .passphrase_provider
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
        ctx.registry.as_ref(),
        ctx.key_storage.as_ref(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use auths_core::PrefilledPassphraseProvider;
    use auths_core::ports::clock::SystemClock;
    use auths_core::signing::{PassphraseProvider, StorageSigner};
    use auths_core::storage::memory::{MEMORY_KEYCHAIN, MemoryKeychainHandle};
    use auths_id::attestation::export::AttestationSink;
    use auths_id::ports::registry::RegistryBackend;
    use auths_id::storage::attestation::AttestationSource;
    use auths_id::storage::identity::IdentityStorage;
    use auths_test_utils::fakes::attestation::{FakeAttestationSink, FakeAttestationSource};
    use auths_test_utils::fakes::identity_storage::FakeIdentityStorage;
    use auths_test_utils::fakes::registry::FakeRegistryBackend;

    use crate::setup::setup_developer;
    use crate::types::{DeveloperSetupConfig, GitSigningScope};

    fn fake_ctx(passphrase: &str) -> AuthsContext {
        MEMORY_KEYCHAIN.lock().unwrap().clear_all().ok();
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
            .attestation_source(
                Arc::new(FakeAttestationSource::new())
                    as Arc<dyn AttestationSource + Send + Sync>,
            )
            .passphrase_provider(
                Arc::new(PrefilledPassphraseProvider::new(passphrase))
                    as Arc<dyn PassphraseProvider + Send + Sync>,
            )
            .build()
    }

    fn provision_identity(ctx: &AuthsContext) -> KeyAlias {
        let keychain = MemoryKeychainHandle;
        let signer = StorageSigner::new(MemoryKeychainHandle);
        let provider = PrefilledPassphraseProvider::new("Test-passphrase1!");
        let config = DeveloperSetupConfig::builder(KeyAlias::new_unchecked("test-key"))
            .with_git_signing_scope(GitSigningScope::Skip)
            .build();
        let result = setup_developer(config, ctx, &keychain, &signer, &provider, None).unwrap();
        result.key_alias
    }

    // -- resolve_rotation_context --

    #[test]
    fn resolve_rotation_context_returns_identity_and_prefix() {
        let ctx = fake_ctx("Test-passphrase1!");
        let key_alias = provision_identity(&ctx);

        let config = RotationConfig {
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
        let ctx = fake_ctx("Test-passphrase1!");
        let _key_alias = provision_identity(&ctx);

        let config = RotationConfig {
            repo_path: std::path::PathBuf::from("/unused"),
            identity_key_alias: None,
            next_key_alias: None,
        };

        let (_identity, _prefix, alias) = resolve_rotation_context(&config, &ctx).unwrap();
        assert!(!alias.contains("--next-"));
    }

    #[test]
    fn resolve_rotation_context_missing_identity_returns_error() {
        let ctx = fake_ctx("unused");

        let config = RotationConfig {
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
        let ctx = fake_ctx("Test-passphrase1!");
        let key_alias = provision_identity(&ctx);

        let config = RotationConfig {
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
        let ctx = fake_ctx("Test-passphrase1!");
        let key_alias = provision_identity(&ctx);

        let config = RotationConfig {
            repo_path: std::path::PathBuf::from("/unused"),
            identity_key_alias: Some(key_alias.clone()),
            next_key_alias: None,
        };

        let (_, prefix, _) = resolve_rotation_context(&config, &ctx).unwrap();
        let state = ctx.registry.get_key_state(&prefix).unwrap();
        let wrong_did = IdentityDID::new_unchecked("did:keri:EWrongDid".to_string());

        let result = retrieve_precommitted_key(&wrong_did, &key_alias, &state, &ctx);
        assert!(matches!(result, Err(RotationError::RotationFailed(_))));
    }

    #[test]
    fn retrieve_precommitted_key_missing_key_returns_error() {
        let ctx = fake_ctx("Test-passphrase1!");

        let did = IdentityDID::new_unchecked("did:keri:Etest".to_string());
        let state = KeyState {
            prefix: Prefix::new_unchecked("Etest".to_string()),
            current_keys: vec![],
            next_commitment: vec![],
            sequence: 999,
            last_event_said: Said::default(),
            is_abandoned: false,
            threshold: 1,
            next_threshold: 1,
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
        let ctx = fake_ctx("Test-passphrase1!");
        let key_alias = provision_identity(&ctx);

        let config = RotationConfig {
            repo_path: std::path::PathBuf::from("/unused"),
            identity_key_alias: Some(key_alias.clone()),
            next_key_alias: None,
        };

        let (identity, prefix, _) = resolve_rotation_context(&config, &ctx).unwrap();
        let state = ctx.registry.get_key_state(&prefix).unwrap();
        let (decrypted, _) =
            retrieve_precommitted_key(&identity.controller_did, &key_alias, &state, &ctx).unwrap();

        let (rot, new_next_pkcs8) = generate_rotation_keys(&identity, &state, &decrypted).unwrap();

        assert_eq!(rot.s, (state.sequence + 1).to_string());
        assert_eq!(rot.i, prefix);
        assert!(!rot.d.is_empty());
        assert!(!rot.x.is_empty());
        assert!(!new_next_pkcs8.as_ref().is_empty());
    }

    // -- finalize_rotation_storage --

    #[test]
    fn finalize_rotation_storage_persists_keys() {
        let ctx = fake_ctx("Test-passphrase1!");
        let key_alias = provision_identity(&ctx);

        let config = RotationConfig {
            repo_path: std::path::PathBuf::from("/unused"),
            identity_key_alias: Some(key_alias.clone()),
            next_key_alias: None,
        };

        let (identity, prefix, _) = resolve_rotation_context(&config, &ctx).unwrap();
        let state = ctx.registry.get_key_state(&prefix).unwrap();
        let (decrypted, old_next_alias) =
            retrieve_precommitted_key(&identity.controller_did, &key_alias, &state, &ctx).unwrap();
        let (rot, new_next_pkcs8) = generate_rotation_keys(&identity, &state, &decrypted).unwrap();

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
            },
            &ctx,
        );

        assert!(
            result.is_ok(),
            "finalize_rotation_storage failed: {:?}",
            result
        );

        let (loaded_did, _) = ctx
            .key_storage
            .load_key(&KeyAlias::new_unchecked("rotated-key"))
            .unwrap();
        assert_eq!(loaded_did, identity.controller_did);

        let new_sequence = state.sequence + 1;
        let next_key_alias = format!("rotated-key--next-{}", new_sequence);
        let (loaded_next_did, _) = ctx
            .key_storage
            .load_key(&KeyAlias::new_unchecked(&next_key_alias))
            .unwrap();
        assert_eq!(loaded_next_did, identity.controller_did);
    }

    #[test]
    fn finalize_rotation_storage_rejects_mismatched_passphrases() {
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
        let did = IdentityDID::new_unchecked("did:keri:ETestMismatch".to_string());

        let state = KeyState {
            prefix: prefix.clone(),
            current_keys: vec!["D_key".to_string()],
            next_commitment: vec!["hash".to_string()],
            sequence: 0,
            last_event_said: Said::new_unchecked("EPrior".to_string()),
            is_abandoned: false,
            threshold: 1,
            next_threshold: 1,
        };

        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();

        let dummy_rot = RotEvent {
            v: KERI_VERSION.to_string(),
            d: Said::new_unchecked("E_dummy".to_string()),
            i: prefix.clone(),
            s: "1".to_string(),
            p: Said::default(),
            kt: "1".to_string(),
            k: vec![],
            nt: "1".to_string(),
            n: vec![],
            bt: "0".to_string(),
            b: vec![],
            a: vec![],
            x: String::new(),
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
            },
            &ctx,
        );

        assert!(
            matches!(result, Err(RotationError::RotationFailed(ref msg)) if msg.contains("passphrases do not match")),
            "Expected passphrase mismatch error, got: {:?}",
            result
        );
    }
}
