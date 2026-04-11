//! KERI key rotation with pre-rotation commitment verification.
//!
//! Rotates keys by:
//! 1. Verifying the next key matches the previous commitment
//! 2. Generating a new next-key commitment
//! 3. Creating and storing the rotation event

use std::ops::ControlFlow;

use auths_crypto::Pkcs8Der;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use git2::Repository;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

use auths_core::crypto::said::{compute_next_commitment, verify_commitment};
use auths_keri::compute_said;

use super::event::{CesrKey, KeriSequence, Threshold, VersionString};
use super::types::{Prefix, Said};
use super::{Event, GitKel, KelError, KeyState, RotEvent, ValidationError, validate_kel};
use crate::storage::registry::backend::{RegistryBackend, RegistryError};
use crate::witness_config::WitnessConfig;

/// Error type for rotation operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RotationError {
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    #[error("KEL error: {0}")]
    Kel(#[from] KelError),

    #[error("Storage error: {0}")]
    Storage(RegistryError),

    #[error("Validation error: {0}")]
    Validation(#[from] ValidationError),

    #[error("Identity is abandoned (cannot rotate)")]
    IdentityAbandoned,

    #[error("Commitment mismatch: next key does not match previous commitment")]
    CommitmentMismatch,

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Invalid key: {0}")]
    InvalidKey(String),
}

impl auths_core::error::AuthsErrorInfo for RotationError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::KeyGeneration(_) => "AUTHS-E4701",
            Self::Kel(_) => "AUTHS-E4702",
            Self::Storage(_) => "AUTHS-E4703",
            Self::Validation(_) => "AUTHS-E4704",
            Self::IdentityAbandoned => "AUTHS-E4705",
            Self::CommitmentMismatch => "AUTHS-E4706",
            Self::Serialization(_) => "AUTHS-E4707",
            Self::InvalidKey(_) => "AUTHS-E4708",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::KeyGeneration(_) => None,
            Self::Kel(_) => Some("Check the KEL state for the identity"),
            Self::Storage(_) => Some("Check storage backend connectivity"),
            Self::Validation(_) => None,
            Self::IdentityAbandoned => {
                Some("This identity has been abandoned and cannot be rotated")
            }
            Self::CommitmentMismatch => {
                Some("The provided next key does not match the pre-rotation commitment")
            }
            Self::Serialization(_) => None,
            Self::InvalidKey(_) => Some("Provide a valid Ed25519 key in PKCS#8 format"),
        }
    }
}

/// Result of a KERI key rotation.
pub struct RotationResult {
    /// The KERI prefix
    pub prefix: Prefix,

    /// The new sequence number
    pub sequence: u64,

    /// The new current keypair (was the "next" key, PKCS8 DER encoded, zeroed on drop)
    pub new_current_keypair_pkcs8: Pkcs8Der,

    /// The new next keypair for future rotation (PKCS8 DER encoded, zeroed on drop)
    pub new_next_keypair_pkcs8: Pkcs8Der,

    /// The new current public key (raw 32 bytes)
    pub new_current_public_key: Vec<u8>,

    /// The new next public key (raw 32 bytes)
    pub new_next_public_key: Vec<u8>,
}

impl std::fmt::Debug for RotationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RotationResult")
            .field("prefix", &self.prefix)
            .field("sequence", &self.sequence)
            .field("new_current_keypair_pkcs8", &"[REDACTED]")
            .field("new_next_keypair_pkcs8", &"[REDACTED]")
            .field("new_current_public_key", &self.new_current_public_key)
            .field("new_next_public_key", &self.new_next_public_key)
            .finish()
    }
}

/// Rotate keys for a KERI identity.
///
/// This verifies the provided next key matches the previous commitment,
/// then generates a new next-key for future rotation.
///
/// # Arguments
/// * `repo` - Git repository containing the KEL
/// * `prefix` - The KERI identifier prefix
/// * `next_keypair_pkcs8` - The next key (must match the commitment from the previous event)
/// * `witness_config` - Optional witness configuration. When provided and
///   enabled, the rotation event's `bt`/`b` fields are updated.
///
/// # Returns
/// * `RotationResult` containing the new sequence and keypairs
pub fn rotate_keys(
    repo: &Repository,
    prefix: &Prefix,
    next_keypair_pkcs8: &Pkcs8Der,
    witness_config: Option<&WitnessConfig>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<RotationResult, RotationError> {
    let rng = SystemRandom::new();

    // Load current state from KEL
    let kel = GitKel::new(repo, prefix.as_str());
    let events = kel.get_events()?;
    let state = validate_kel(&events)?;

    // Check if rotation is possible
    if !state.can_rotate() {
        return Err(RotationError::IdentityAbandoned);
    }

    // Parse the next keypair (supports multiple PKCS#8 formats and raw seeds)
    let next_keypair =
        crate::identity::helpers::load_keypair_from_der_or_seed(next_keypair_pkcs8.as_ref())
            .map_err(|e| RotationError::InvalidKey(e.to_string()))?;

    // Verify the next key matches the commitment
    if !verify_commitment(
        next_keypair.public_key().as_ref(),
        &state.next_commitment[0],
    ) {
        return Err(RotationError::CommitmentMismatch);
    }

    // Generate new next key for future rotation
    let new_next_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|e| RotationError::KeyGeneration(e.to_string()))?;
    let new_next_keypair = Ed25519KeyPair::from_pkcs8(new_next_pkcs8.as_ref())
        .map_err(|e| RotationError::KeyGeneration(e.to_string()))?;

    // Encode the new current key (the former next key)
    let new_current_pub_encoded = format!(
        "D{}",
        URL_SAFE_NO_PAD.encode(next_keypair.public_key().as_ref())
    );

    // Compute new next-key commitment
    let new_next_commitment = compute_next_commitment(new_next_keypair.public_key().as_ref());

    // Determine witness fields from config
    let bt = match witness_config {
        Some(cfg) if cfg.is_enabled() => Threshold::Simple(cfg.threshold as u64),
        _ => Threshold::Simple(0),
    };

    // Build rotation event
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
        x: String::new(),
    };

    // Compute SAID
    let rot_value = serde_json::to_value(Event::Rot(rot.clone()))
        .map_err(|e| RotationError::Serialization(e.to_string()))?;
    rot.d = compute_said(&rot_value).map_err(|e| RotationError::Serialization(e.to_string()))?;

    // Sign with the new current key (next_keypair is now the active key)
    let canonical = super::serialize_for_signing(&Event::Rot(rot.clone()))?;
    let sig = next_keypair.sign(&canonical);
    rot.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

    // Append to KEL
    kel.append(&Event::Rot(rot.clone()), now)?;

    // Collect witness receipts if configured
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
        new_next_keypair_pkcs8: Pkcs8Der::new(new_next_pkcs8.as_ref()),
        new_current_public_key: next_keypair.public_key().as_ref().to_vec(),
        new_next_public_key: new_next_keypair.public_key().as_ref().to_vec(),
    })
}

/// Abandon a KERI identity by rotating with an empty next commitment.
///
/// After abandonment, the identity can no longer be rotated.
/// This still requires using the committed next key for the final rotation.
///
/// # Arguments
/// * `repo` - Git repository containing the KEL
/// * `prefix` - The KERI identifier prefix
/// * `next_keypair_pkcs8` - The next key (must match commitment, will become final key)
/// * `witness_config` - Optional witness configuration
pub fn abandon_identity(
    repo: &Repository,
    prefix: &Prefix,
    next_keypair_pkcs8: &Pkcs8Der,
    witness_config: Option<&WitnessConfig>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<u64, RotationError> {
    // Load current state from KEL
    let kel = GitKel::new(repo, prefix.as_str());
    let events = kel.get_events()?;
    let state = validate_kel(&events)?;

    // Check if already abandoned
    if state.is_abandoned {
        return Err(RotationError::IdentityAbandoned);
    }

    // Parse the next keypair
    let next_keypair = Ed25519KeyPair::from_pkcs8(next_keypair_pkcs8.as_ref())
        .map_err(|e| RotationError::InvalidKey(e.to_string()))?;

    // Verify the next key matches the commitment
    if !verify_commitment(
        next_keypair.public_key().as_ref(),
        &state.next_commitment[0],
    ) {
        return Err(RotationError::CommitmentMismatch);
    }

    // Encode the new current key (the former next key)
    let new_current_pub_encoded = format!(
        "D{}",
        URL_SAFE_NO_PAD.encode(next_keypair.public_key().as_ref())
    );

    // Determine witness fields from config
    let bt = match witness_config {
        Some(cfg) if cfg.is_enabled() => Threshold::Simple(cfg.threshold as u64),
        _ => Threshold::Simple(0),
    };

    // Build abandonment rotation event (empty next commitment)
    let new_sequence = state.sequence + 1;
    let mut rot = RotEvent {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: prefix.clone(),
        s: KeriSequence::new(new_sequence),
        p: state.last_event_said.clone(),
        kt: Threshold::Simple(1),
        k: vec![CesrKey::new_unchecked(new_current_pub_encoded)], // Rotate to next key
        nt: Threshold::Simple(0),                                 // Zero threshold
        n: vec![],                                                // Empty = abandoned
        bt,
        br: vec![],
        ba: vec![],
        c: vec![],
        a: vec![],
        x: String::new(),
    };

    // Compute SAID
    let rot_value = serde_json::to_value(Event::Rot(rot.clone()))
        .map_err(|e| RotationError::Serialization(e.to_string()))?;
    rot.d = compute_said(&rot_value).map_err(|e| RotationError::Serialization(e.to_string()))?;

    // Sign with the new current key (next_keypair is now the active key)
    let canonical = super::serialize_for_signing(&Event::Rot(rot.clone()))?;
    let sig = next_keypair.sign(&canonical);
    rot.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

    // Append to KEL
    kel.append(&Event::Rot(rot), now)?;

    Ok(new_sequence)
}

/// Get the current key state for a KERI identity.
pub fn get_key_state(repo: &Repository, prefix: &Prefix) -> Result<KeyState, RotationError> {
    let kel = GitKel::new(repo, prefix.as_str());
    let events = kel.get_events()?;
    let state = validate_kel(&events)?;
    Ok(state)
}

/// Rotate keys for a KERI identity using any [`RegistryBackend`].
///
/// Identical logic to [`rotate_keys`] but reads from and writes to the
/// provided backend instead of a git repository.
///
/// # Arguments
/// * `backend` - The registry backend to read/write the KEL
/// * `prefix` - The KERI identifier prefix
/// * `next_keypair_pkcs8` - The next key (must match the commitment from the previous event)
/// * `witness_config` - Unused in the backend path; kept for API symmetry
pub fn rotate_keys_with_backend(
    backend: &impl RegistryBackend,
    prefix: &Prefix,
    next_keypair_pkcs8: &Pkcs8Der,
    _now: chrono::DateTime<chrono::Utc>,
    _witness_config: Option<&WitnessConfig>,
) -> Result<RotationResult, RotationError> {
    let rng = SystemRandom::new();

    // Load current state from backend
    let events = collect_events_from_backend(backend, prefix)?;
    let state = validate_kel(&events)?;

    if !state.can_rotate() {
        return Err(RotationError::IdentityAbandoned);
    }

    let next_keypair =
        crate::identity::helpers::load_keypair_from_der_or_seed(next_keypair_pkcs8.as_ref())
            .map_err(|e| RotationError::InvalidKey(e.to_string()))?;

    if !verify_commitment(
        next_keypair.public_key().as_ref(),
        &state.next_commitment[0],
    ) {
        return Err(RotationError::CommitmentMismatch);
    }

    let new_next_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|e| RotationError::KeyGeneration(e.to_string()))?;
    let new_next_keypair = Ed25519KeyPair::from_pkcs8(new_next_pkcs8.as_ref())
        .map_err(|e| RotationError::KeyGeneration(e.to_string()))?;

    let new_current_pub_encoded = format!(
        "D{}",
        URL_SAFE_NO_PAD.encode(next_keypair.public_key().as_ref())
    );
    let new_next_commitment = compute_next_commitment(new_next_keypair.public_key().as_ref());

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
        bt: Threshold::Simple(0),
        br: vec![],
        ba: vec![],
        c: vec![],
        a: vec![],
        x: String::new(),
    };

    let rot_value = serde_json::to_value(Event::Rot(rot.clone()))
        .map_err(|e| RotationError::Serialization(e.to_string()))?;
    rot.d = compute_said(&rot_value).map_err(|e| RotationError::Serialization(e.to_string()))?;

    let canonical = super::serialize_for_signing(&Event::Rot(rot.clone()))
        .map_err(|e| RotationError::Serialization(e.to_string()))?;
    let sig = next_keypair.sign(&canonical);
    rot.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

    backend
        .append_event(prefix, &Event::Rot(rot))
        .map_err(RotationError::Storage)?;

    Ok(RotationResult {
        prefix: prefix.clone(),
        sequence: new_sequence,
        new_current_keypair_pkcs8: next_keypair_pkcs8.clone(),
        new_next_keypair_pkcs8: Pkcs8Der::new(new_next_pkcs8.as_ref()),
        new_current_public_key: next_keypair.public_key().as_ref().to_vec(),
        new_next_public_key: new_next_keypair.public_key().as_ref().to_vec(),
    })
}

/// Get the current key state for a KERI identity from any [`RegistryBackend`].
///
/// # Arguments
/// * `backend` - The registry backend to read from
/// * `prefix` - The KERI identifier prefix
pub fn get_key_state_with_backend(
    backend: &impl RegistryBackend,
    prefix: &Prefix,
) -> Result<KeyState, RotationError> {
    backend
        .get_key_state(prefix)
        .map_err(RotationError::Storage)
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
    Ok(events)
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::keri::{create_keri_identity_with_curve};
    use tempfile::TempDir;

    fn setup_repo() -> (TempDir, Repository) {
        let dir = TempDir::new().unwrap();
        let repo = Repository::init(dir.path()).unwrap();

        let mut config = repo.config().unwrap();
        config.set_str("user.name", "Test User").unwrap();
        config.set_str("user.email", "test@example.com").unwrap();

        (dir, repo)
    }

    #[test]
    fn rotation_updates_key_and_sequence() {
        let (_dir, repo) = setup_repo();

        // Create identity
        let init = create_keri_identity_with_curve(
            &repo,
            None,
            chrono::Utc::now(),
            auths_crypto::CurveType::Ed25519,
        )
        .unwrap();

        // Rotate using the next key
        let rot = rotate_keys(
            &repo,
            &init.prefix,
            &init.next_keypair_pkcs8,
            None,
            chrono::Utc::now(),
        )
        .unwrap();

        assert_eq!(rot.prefix, init.prefix);
        assert_eq!(rot.sequence, 1);

        // Verify KEL has 2 events
        let kel = GitKel::new(&repo, rot.prefix.as_str());
        let events = kel.get_events().unwrap();
        assert_eq!(events.len(), 2);
        assert!(events[0].is_inception());
        assert!(events[1].is_rotation());
    }

    #[test]
    fn rotation_verifies_commitment() {
        let (_dir, repo) = setup_repo();

        let init = create_keri_identity_with_curve(
            &repo,
            None,
            chrono::Utc::now(),
            auths_crypto::CurveType::Ed25519,
        )
        .unwrap();

        // Try to rotate with a wrong key
        let rng = SystemRandom::new();
        let wrong_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let wrong_pkcs8 = Pkcs8Der::new(wrong_pkcs8.as_ref());

        let result = rotate_keys(&repo, &init.prefix, &wrong_pkcs8, None, chrono::Utc::now());
        assert!(matches!(result, Err(RotationError::CommitmentMismatch)));
    }

    #[test]
    fn rotation_chain_works() {
        let (_dir, repo) = setup_repo();

        // Create identity
        let init = create_keri_identity_with_curve(
            &repo,
            None,
            chrono::Utc::now(),
            auths_crypto::CurveType::Ed25519,
        )
        .unwrap();

        // First rotation
        let rot1 = rotate_keys(
            &repo,
            &init.prefix,
            &init.next_keypair_pkcs8,
            None,
            chrono::Utc::now(),
        )
        .unwrap();
        assert_eq!(rot1.sequence, 1);

        // Second rotation
        let rot2 = rotate_keys(
            &repo,
            &init.prefix,
            &rot1.new_next_keypair_pkcs8,
            None,
            chrono::Utc::now(),
        )
        .unwrap();
        assert_eq!(rot2.sequence, 2);

        // Verify KEL has 3 events
        let kel = GitKel::new(&repo, init.prefix.as_str());
        let events = kel.get_events().unwrap();
        assert_eq!(events.len(), 3);

        // Validate the full chain
        let state = validate_kel(&events).unwrap();
        assert_eq!(state.sequence, 2);
    }

    #[test]
    fn abandonment_works() {
        let (_dir, repo) = setup_repo();

        let init = create_keri_identity_with_curve(
            &repo,
            None,
            chrono::Utc::now(),
            auths_crypto::CurveType::Ed25519,
        )
        .unwrap();

        // Abandon the identity (must use next key)
        let seq = abandon_identity(
            &repo,
            &init.prefix,
            &init.next_keypair_pkcs8,
            None,
            chrono::Utc::now(),
        )
        .unwrap();
        assert_eq!(seq, 1);

        // Verify state
        let state = get_key_state(&repo, &init.prefix).unwrap();
        assert!(state.is_abandoned);
        assert!(!state.can_rotate());
    }

    #[test]
    fn abandoned_identity_cannot_rotate() {
        let (_dir, repo) = setup_repo();

        let init = create_keri_identity_with_curve(
            &repo,
            None,
            chrono::Utc::now(),
            auths_crypto::CurveType::Ed25519,
        )
        .unwrap();

        // Abandon first (uses next key)
        abandon_identity(
            &repo,
            &init.prefix,
            &init.next_keypair_pkcs8,
            None,
            chrono::Utc::now(),
        )
        .unwrap();

        // Generate a new key and try to rotate - should fail because abandoned
        let rng = SystemRandom::new();
        let new_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let new_pkcs8 = Pkcs8Der::new(new_pkcs8.as_ref());
        let result = rotate_keys(&repo, &init.prefix, &new_pkcs8, None, chrono::Utc::now());
        assert!(matches!(result, Err(RotationError::IdentityAbandoned)));
    }

    #[test]
    fn double_abandonment_fails() {
        let (_dir, repo) = setup_repo();

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

        // Generate a new key and try to abandon again
        let rng = SystemRandom::new();
        let new_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let new_pkcs8 = Pkcs8Der::new(new_pkcs8.as_ref());
        let result = abandon_identity(&repo, &init.prefix, &new_pkcs8, None, chrono::Utc::now());
        assert!(matches!(result, Err(RotationError::IdentityAbandoned)));
    }

    #[test]
    fn get_key_state_works() {
        let (_dir, repo) = setup_repo();

        let init = create_keri_identity_with_curve(
            &repo,
            None,
            chrono::Utc::now(),
            auths_crypto::CurveType::Ed25519,
        )
        .unwrap();

        let state = get_key_state(&repo, &init.prefix).unwrap();
        assert_eq!(state.prefix, init.prefix);
        assert_eq!(state.sequence, 0);
        assert!(!state.is_abandoned);
        assert!(state.can_rotate());
    }

    #[test]
    fn state_reflects_rotation() {
        let (_dir, repo) = setup_repo();

        let init = create_keri_identity_with_curve(
            &repo,
            None,
            chrono::Utc::now(),
            auths_crypto::CurveType::Ed25519,
        )
        .unwrap();
        rotate_keys(
            &repo,
            &init.prefix,
            &init.next_keypair_pkcs8,
            None,
            chrono::Utc::now(),
        )
        .unwrap();

        let state = get_key_state(&repo, &init.prefix).unwrap();
        assert_eq!(state.sequence, 1);

        // Current key should be the former next key
        let expected_key = format!("D{}", URL_SAFE_NO_PAD.encode(&init.next_public_key));
        assert_eq!(state.current_keys[0].as_str(), expected_key);
    }
}
