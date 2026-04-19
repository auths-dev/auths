//! KERI key rotation with pre-rotation commitment verification.
//!
//! Rotates keys by:
//! 1. Verifying the next key matches the previous commitment
//! 2. Generating a new next-key commitment
//! 3. Creating and storing the rotation event

use std::ops::ControlFlow;

use auths_crypto::Pkcs8Der;
use auths_keri::KeriPublicKey;
use base64::Engine;

use auths_core::crypto::said::{compute_next_commitment, verify_commitment};
use auths_keri::compute_said;

use super::event::{CesrKey, KeriSequence, Threshold, VersionString};
use super::types::{Prefix, Said};
use super::{Event, GitKel, KelError, RotEvent, ValidationError, validate_kel};
use crate::storage::registry::backend::RegistryBackend;
use crate::witness_config::WitnessConfig;

use super::inception::generate_keypair_for_init;

/// Errors from rotation and key state operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RotationError {
    #[error("KEL error: {0}")]
    Kel(#[from] KelError),

    #[error("Validation error: {0}")]
    Validation(#[from] ValidationError),

    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("Key commitment mismatch")]
    CommitmentMismatch,

    #[error("Identity is abandoned (empty next commitment)")]
    IdentityAbandoned,

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Storage error: {0}")]
    Storage(#[from] crate::storage::registry::backend::RegistryError),

    #[error("Rotation failed: {0}")]
    RotationFailed(String),

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Key decryption failed: {0}")]
    KeyDecryptionFailed(String),
}

impl From<auths_core::error::AgentError> for RotationError {
    fn from(e: auths_core::error::AgentError) -> Self {
        RotationError::RotationFailed(e.to_string())
    }
}

impl auths_core::error::AuthsErrorInfo for RotationError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::Kel(_) => "AUTHS-E4801",
            Self::Validation(_) => "AUTHS-E4802",
            Self::KeyGeneration(_) => "AUTHS-E4803",
            Self::InvalidKey(_) => "AUTHS-E4804",
            Self::CommitmentMismatch => "AUTHS-E4805",
            Self::IdentityAbandoned => "AUTHS-E4806",
            Self::Serialization(_) => "AUTHS-E4807",
            Self::Storage(_) => "AUTHS-E4808",
            Self::RotationFailed(_) => "AUTHS-E4809",
            Self::KeyNotFound(_) => "AUTHS-E4810",
            Self::KeyDecryptionFailed(_) => "AUTHS-E4811",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::CommitmentMismatch => Some(
                "The provided key does not match the pre-committed next key. Use the key that was generated during initialization or the last rotation.",
            ),
            Self::IdentityAbandoned => Some(
                "This identity has been permanently abandoned. Create a new identity with 'auths init'.",
            ),
            _ => None,
        }
    }
}

/// Result from a successful key rotation.
#[derive(Debug, Clone)]
pub struct RotationResult {
    pub prefix: Prefix,
    pub sequence: u128,
    pub new_current_keypair_pkcs8: Pkcs8Der,
    pub new_next_keypair_pkcs8: Pkcs8Der,
    pub new_current_public_key: Vec<u8>,
    pub new_next_public_key: Vec<u8>,
}

/// Detect the curve used by the identity from the current key state.
fn detect_curve_from_state(state: &auths_keri::KeyState) -> auths_crypto::CurveType {
    state
        .current_keys
        .first()
        .and_then(|k| KeriPublicKey::parse(k.as_str()).ok())
        .map(|kp| kp.curve())
        .unwrap_or_default()
}

/// Parse a next-keypair PKCS8 into its public key bytes, seed, and CESR encoding (curve-agnostic).
fn parse_next_key(
    pkcs8: &[u8],
) -> Result<(Vec<u8>, auths_crypto::TypedSeed, String), RotationError> {
    let parsed = auths_crypto::parse_key_material(pkcs8)
        .map_err(|e| RotationError::InvalidKey(e.to_string()))?;
    let cesr_prefix = match parsed.seed.curve() {
        auths_crypto::CurveType::Ed25519 => "D",
        auths_crypto::CurveType::P256 => "1AAI",
    };
    let cesr_encoded = format!(
        "{}{}",
        cesr_prefix,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&parsed.public_key)
    );
    Ok((parsed.public_key, parsed.seed, cesr_encoded))
}

/// Sign a rotation event with a typed seed (curve-agnostic).
fn sign_rotation(
    seed: &auths_crypto::TypedSeed,
    canonical: &[u8],
) -> Result<Vec<u8>, RotationError> {
    auths_crypto::typed_sign(seed, canonical)
        .map_err(|e| RotationError::Serialization(format!("signing failed: {e}")))
}

/// Rotate keys for a KERI identity stored in a Git repository.
pub fn rotate_keys(
    repo: &git2::Repository,
    prefix: &Prefix,
    next_keypair_pkcs8: &Pkcs8Der,
    witness_config: Option<&WitnessConfig>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<RotationResult, RotationError> {
    let kel = GitKel::new(repo, prefix.as_str());
    let events = kel.get_events()?;
    let state = validate_kel(&events)?;

    if !state.can_rotate() {
        return Err(RotationError::IdentityAbandoned);
    }

    let curve = detect_curve_from_state(&state);
    let (next_pub_bytes, next_seed, next_cesr) = parse_next_key(next_keypair_pkcs8.as_ref())?;

    if !verify_commitment(&next_pub_bytes, &state.next_commitment[0]) {
        return Err(RotationError::CommitmentMismatch);
    }

    let new_next = generate_keypair_for_init(curve)
        .map_err(|e| RotationError::KeyGeneration(e.to_string()))?;

    let new_next_commitment = compute_next_commitment(&new_next.public_key);

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
        k: vec![CesrKey::new_unchecked(next_cesr.clone())],
        nt: Threshold::Simple(1),
        n: vec![new_next_commitment],
        bt,
        br: vec![],
        ba: vec![],
        c: vec![],
        a: vec![],
    };

    let rot_value = serde_json::to_value(Event::Rot(rot.clone()))
        .map_err(|e| RotationError::Serialization(e.to_string()))?;
    rot.d = compute_said(&rot_value).map_err(|e| RotationError::Serialization(e.to_string()))?;

    let canonical = super::serialize_for_signing(&Event::Rot(rot.clone()))?;
    let _sig = sign_rotation(&next_seed, &canonical)?;

    kel.append(&Event::Rot(rot.clone()), now)?;

    #[cfg(feature = "witness-client")]
    if let Some(config) = witness_config
        && config.is_enabled()
    {
        let canonical_for_witness = super::serialize_for_signing(&Event::Rot(rot.clone()))?;
        super::witness_integration::collect_and_store_receipts(
            repo.path().parent().unwrap_or(repo.path()),
            prefix,
            &rot.d,
            &canonical_for_witness,
            config,
            now,
        )
        .map_err(|e| RotationError::Serialization(e.to_string()))?;
    }

    Ok(RotationResult {
        prefix: prefix.clone(),
        sequence: new_sequence,
        new_current_keypair_pkcs8: next_keypair_pkcs8.clone(),
        new_next_keypair_pkcs8: new_next.pkcs8,
        new_current_public_key: next_pub_bytes,
        new_next_public_key: new_next.public_key,
    })
}

/// Abandon a KERI identity by rotating with an empty next commitment.
pub fn abandon_identity(
    repo: &git2::Repository,
    prefix: &Prefix,
    next_keypair_pkcs8: &Pkcs8Der,
    witness_config: Option<&WitnessConfig>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<u128, RotationError> {
    let kel = GitKel::new(repo, prefix.as_str());
    let events = kel.get_events()?;
    let state = validate_kel(&events)?;

    if state.is_abandoned {
        return Err(RotationError::IdentityAbandoned);
    }

    let (next_pub_bytes, next_seed, next_cesr) = parse_next_key(next_keypair_pkcs8.as_ref())?;

    if !verify_commitment(&next_pub_bytes, &state.next_commitment[0]) {
        return Err(RotationError::CommitmentMismatch);
    }

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
        k: vec![CesrKey::new_unchecked(next_cesr.clone())],
        nt: Threshold::Simple(0),
        n: vec![],
        bt,
        br: vec![],
        ba: vec![],
        c: vec![],
        a: vec![],
    };

    let rot_value = serde_json::to_value(Event::Rot(rot.clone()))
        .map_err(|e| RotationError::Serialization(e.to_string()))?;
    rot.d = compute_said(&rot_value).map_err(|e| RotationError::Serialization(e.to_string()))?;

    let canonical = super::serialize_for_signing(&Event::Rot(rot.clone()))?;
    let _sig = sign_rotation(&next_seed, &canonical)?;

    kel.append(&Event::Rot(rot), now)?;

    Ok(new_sequence)
}

/// Get the current key state for a KERI identity.
pub fn get_key_state(
    repo: &git2::Repository,
    prefix: &Prefix,
) -> Result<auths_keri::KeyState, RotationError> {
    let kel = GitKel::new(repo, prefix.as_str());
    let events = kel.get_events()?;
    let state = validate_kel(&events)?;
    Ok(state)
}

/// Rotate keys using any [`RegistryBackend`].
pub fn rotate_keys_with_backend(
    backend: &impl RegistryBackend,
    prefix: &Prefix,
    next_keypair_pkcs8: &Pkcs8Der,
    _now: chrono::DateTime<chrono::Utc>,
    _witness_config: Option<&WitnessConfig>,
) -> Result<RotationResult, RotationError> {
    let events = collect_events_from_backend(backend, prefix)?;
    let state = validate_kel(&events)?;

    if !state.can_rotate() {
        return Err(RotationError::IdentityAbandoned);
    }

    let curve = detect_curve_from_state(&state);
    let (next_pub_bytes, next_seed, next_cesr) = parse_next_key(next_keypair_pkcs8.as_ref())?;

    if !verify_commitment(&next_pub_bytes, &state.next_commitment[0]) {
        return Err(RotationError::CommitmentMismatch);
    }

    let new_next = generate_keypair_for_init(curve)
        .map_err(|e| RotationError::KeyGeneration(e.to_string()))?;

    let new_next_commitment = compute_next_commitment(&new_next.public_key);

    let new_sequence = state.sequence + 1;
    let mut rot = RotEvent {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: prefix.clone(),
        s: KeriSequence::new(new_sequence),
        p: state.last_event_said.clone(),
        kt: Threshold::Simple(1),
        k: vec![CesrKey::new_unchecked(next_cesr.clone())],
        nt: Threshold::Simple(1),
        n: vec![new_next_commitment],
        bt: Threshold::Simple(0),
        br: vec![],
        ba: vec![],
        c: vec![],
        a: vec![],
    };

    let rot_value = serde_json::to_value(Event::Rot(rot.clone()))
        .map_err(|e| RotationError::Serialization(e.to_string()))?;
    rot.d = compute_said(&rot_value).map_err(|e| RotationError::Serialization(e.to_string()))?;

    let canonical = super::serialize_for_signing(&Event::Rot(rot.clone()))
        .map_err(|e| RotationError::Serialization(e.to_string()))?;
    let sig = sign_rotation(&next_seed, &canonical)?;
    let attachment =
        auths_keri::serialize_attachment(&[auths_keri::IndexedSignature { index: 0, sig }])
            .map_err(|e| RotationError::Serialization(e.to_string()))?;

    backend
        .append_signed_event(prefix, &Event::Rot(rot), &attachment)
        .map_err(RotationError::Storage)?;

    Ok(RotationResult {
        prefix: prefix.clone(),
        sequence: new_sequence,
        new_current_keypair_pkcs8: next_keypair_pkcs8.clone(),
        new_next_keypair_pkcs8: new_next.pkcs8,
        new_current_public_key: next_pub_bytes,
        new_next_public_key: new_next.public_key,
    })
}

/// Get the current key state from any [`RegistryBackend`].
pub fn get_key_state_with_backend(
    backend: &impl RegistryBackend,
    prefix: &Prefix,
) -> Result<auths_keri::KeyState, RotationError> {
    let events = collect_events_from_backend(backend, prefix)?;
    let state = validate_kel(&events)?;
    Ok(state)
}

fn collect_events_from_backend(
    backend: &impl RegistryBackend,
    prefix: &Prefix,
) -> Result<Vec<Event>, RotationError> {
    let mut events = Vec::new();
    backend
        .visit_events(prefix, 0, &mut |e| {
            events.push(e.clone());
            ControlFlow::Continue(())
        })
        .map_err(RotationError::Storage)?;

    if events.is_empty() {
        return Err(RotationError::Kel(KelError::NotFound(
            prefix.as_str().to_string(),
        )));
    }
    Ok(events)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::keri::create_keri_identity_with_curve;

    #[test]
    fn rotation_updates_key_and_sequence() {
        let (_dir, repo) = auths_test_utils::git::init_test_repo();
        let init = create_keri_identity_with_curve(
            &repo,
            None,
            chrono::Utc::now(),
            auths_crypto::CurveType::Ed25519,
        )
        .unwrap();

        let rot = rotate_keys(
            &repo,
            &init.prefix,
            &init.next_keypair_pkcs8,
            None,
            chrono::Utc::now(),
        )
        .unwrap();
        assert_eq!(rot.sequence, 1);
        assert_ne!(rot.new_current_public_key, init.current_public_key);
    }

    #[test]
    fn rotation_verifies_commitment() {
        let (_dir, repo) = auths_test_utils::git::init_test_repo();
        let init = create_keri_identity_with_curve(
            &repo,
            None,
            chrono::Utc::now(),
            auths_crypto::CurveType::Ed25519,
        )
        .unwrap();

        let wrong_key = Pkcs8Der::new([99u8; 85].to_vec());
        let result = rotate_keys(&repo, &init.prefix, &wrong_key, None, chrono::Utc::now());
        assert!(result.is_err());
    }

    #[test]
    fn rotation_chain_works() {
        let (_dir, repo) = auths_test_utils::git::init_test_repo();
        let init = create_keri_identity_with_curve(
            &repo,
            None,
            chrono::Utc::now(),
            auths_crypto::CurveType::Ed25519,
        )
        .unwrap();

        let rot1 = rotate_keys(
            &repo,
            &init.prefix,
            &init.next_keypair_pkcs8,
            None,
            chrono::Utc::now(),
        )
        .unwrap();
        assert_eq!(rot1.sequence, 1);

        let rot2 = rotate_keys(
            &repo,
            &init.prefix,
            &rot1.new_next_keypair_pkcs8,
            None,
            chrono::Utc::now(),
        )
        .unwrap();
        assert_eq!(rot2.sequence, 2);
    }

    #[test]
    fn state_reflects_rotation() {
        let (_dir, repo) = auths_test_utils::git::init_test_repo();
        let init = create_keri_identity_with_curve(
            &repo,
            None,
            chrono::Utc::now(),
            auths_crypto::CurveType::Ed25519,
        )
        .unwrap();

        let _rot = rotate_keys(
            &repo,
            &init.prefix,
            &init.next_keypair_pkcs8,
            None,
            chrono::Utc::now(),
        )
        .unwrap();
        let state = get_key_state(&repo, &init.prefix).unwrap();
        assert_eq!(state.sequence, 1);
    }

    #[test]
    fn abandonment_works() {
        let (_dir, repo) = auths_test_utils::git::init_test_repo();
        let init = create_keri_identity_with_curve(
            &repo,
            None,
            chrono::Utc::now(),
            auths_crypto::CurveType::Ed25519,
        )
        .unwrap();

        let seq = abandon_identity(
            &repo,
            &init.prefix,
            &init.next_keypair_pkcs8,
            None,
            chrono::Utc::now(),
        )
        .unwrap();
        assert_eq!(seq, 1);

        let state = get_key_state(&repo, &init.prefix).unwrap();
        assert!(state.is_abandoned);
    }

    #[test]
    fn abandoned_identity_cannot_rotate() {
        let (_dir, repo) = auths_test_utils::git::init_test_repo();
        let init = create_keri_identity_with_curve(
            &repo,
            None,
            chrono::Utc::now(),
            auths_crypto::CurveType::Ed25519,
        )
        .unwrap();

        abandon_identity(
            &repo,
            &init.prefix,
            &init.next_keypair_pkcs8,
            None,
            chrono::Utc::now(),
        )
        .unwrap();

        let wrong = Pkcs8Der::new(vec![1, 2, 3]);
        let result = rotate_keys(&repo, &init.prefix, &wrong, None, chrono::Utc::now());
        assert!(matches!(result, Err(RotationError::IdentityAbandoned)));
    }

    #[test]
    fn double_abandonment_fails() {
        let (_dir, repo) = auths_test_utils::git::init_test_repo();
        let init = create_keri_identity_with_curve(
            &repo,
            None,
            chrono::Utc::now(),
            auths_crypto::CurveType::Ed25519,
        )
        .unwrap();

        abandon_identity(
            &repo,
            &init.prefix,
            &init.next_keypair_pkcs8,
            None,
            chrono::Utc::now(),
        )
        .unwrap();
        let result = abandon_identity(
            &repo,
            &init.prefix,
            &init.next_keypair_pkcs8,
            None,
            chrono::Utc::now(),
        );
        assert!(matches!(result, Err(RotationError::IdentityAbandoned)));
    }

    #[test]
    fn p256_rotation_works() {
        let (_dir, repo) = auths_test_utils::git::init_test_repo();
        let init = create_keri_identity_with_curve(
            &repo,
            None,
            chrono::Utc::now(),
            auths_crypto::CurveType::P256,
        )
        .unwrap();

        let rot = rotate_keys(
            &repo,
            &init.prefix,
            &init.next_keypair_pkcs8,
            None,
            chrono::Utc::now(),
        )
        .unwrap();
        assert_eq!(rot.sequence, 1);
        assert_eq!(rot.new_current_public_key.len(), 33);
        assert_eq!(rot.new_next_public_key.len(), 33);
    }

    #[test]
    fn p256_rotation_chain_works() {
        let (_dir, repo) = auths_test_utils::git::init_test_repo();
        let init = create_keri_identity_with_curve(
            &repo,
            None,
            chrono::Utc::now(),
            auths_crypto::CurveType::P256,
        )
        .unwrap();

        let rot1 = rotate_keys(
            &repo,
            &init.prefix,
            &init.next_keypair_pkcs8,
            None,
            chrono::Utc::now(),
        )
        .unwrap();
        let rot2 = rotate_keys(
            &repo,
            &init.prefix,
            &rot1.new_next_keypair_pkcs8,
            None,
            chrono::Utc::now(),
        )
        .unwrap();
        assert_eq!(rot2.sequence, 2);
        assert_eq!(rot2.new_next_public_key.len(), 33);
    }
}
