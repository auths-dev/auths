//! did:keri resolution via KEL replay.
//!
//! Resolves a `did:keri:<prefix>` to its current public key by:
//! 1. Loading the KEL from Git
//! 2. Replaying all events to derive current KeyState
//! 3. Decoding the current public key

use auths_keri::KeriPublicKey;
use auths_verifier::types::IdentityDID;
use git2::Repository;

use super::types::Prefix;
use super::{GitKel, KelError, ValidationError, validate_kel};

/// Error type for did:keri resolution.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ResolveError {
    #[error("Invalid DID format: {0}")]
    InvalidFormat(String),

    #[error("KEL not found for prefix: {0}")]
    NotFound(String),

    #[error("KEL error: {0}")]
    Kel(#[from] KelError),

    #[error("Validation error: {0}")]
    Validation(#[from] ValidationError),

    #[error("Invalid key encoding: {0}")]
    InvalidKeyEncoding(String),

    #[error("No current key in identity")]
    NoCurrentKey,

    #[error("Unknown key type: {0}")]
    UnknownKeyType(String),
}

impl auths_core::error::AuthsErrorInfo for ResolveError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidFormat(_) => "AUTHS-E4801",
            Self::NotFound(_) => "AUTHS-E4802",
            Self::Kel(_) => "AUTHS-E4803",
            Self::Validation(_) => "AUTHS-E4804",
            Self::InvalidKeyEncoding(_) => "AUTHS-E4805",
            Self::NoCurrentKey => "AUTHS-E4806",
            Self::UnknownKeyType(_) => "AUTHS-E4807",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::InvalidFormat(_) => Some("Use the format 'did:keri:E<prefix>'"),
            Self::NotFound(_) => Some("The identity does not exist; check the DID prefix"),
            Self::Kel(_) => None,
            Self::Validation(_) => None,
            Self::InvalidKeyEncoding(_) => None,
            Self::NoCurrentKey => Some("The identity has no active key; it may be abandoned"),
            Self::UnknownKeyType(_) => Some("Only Ed25519 keys (D prefix) are currently supported"),
        }
    }
}

/// Result of resolving a did:keri.
#[derive(Debug, Clone)]
pub struct DidKeriResolution {
    /// The full DID string
    pub did: IdentityDID,

    /// The KERI prefix
    pub prefix: Prefix,

    /// The current public key (raw bytes, 32 bytes for Ed25519)
    pub public_key: Vec<u8>,

    /// The current sequence number
    pub sequence: u128,

    /// Whether the identity can still be rotated
    pub can_rotate: bool,

    /// Whether the identity has been abandoned
    pub is_abandoned: bool,
}

/// Resolve a did:keri to its current public key.
///
/// This replays the entire KEL to derive the current key state.
///
/// # Arguments
/// * `repo` - Git repository containing the KEL
/// * `did` - The did:keri string (e.g., "did:keri:EXq5YqaL...")
///
/// # Returns
/// * `DidKeriResolution` with the current public key and state
pub fn resolve_did_keri(repo: &Repository, did: &str) -> Result<DidKeriResolution, ResolveError> {
    let prefix = parse_did_keri(did)?;

    // Load KEL
    let kel = GitKel::new(repo, prefix.as_str());
    if !kel.exists() {
        return Err(ResolveError::NotFound(prefix.as_str().to_string()));
    }

    // Replay KEL to get current state
    let events = kel.get_events()?;
    let state = validate_kel(&events)?;

    // Decode current public key
    let key_encoded = state.current_key().ok_or(ResolveError::NoCurrentKey)?;

    let public_key = KeriPublicKey::parse(key_encoded.as_str())
        .map(|k| k.as_bytes().to_vec())
        .map_err(|e| ResolveError::InvalidKeyEncoding(e.to_string()))?;

    Ok(DidKeriResolution {
        #[allow(clippy::disallowed_methods)] // INVARIANT: parse_did_keri() above validated the did:keri format
        did: IdentityDID::new_unchecked(did),
        prefix,
        public_key,
        sequence: state.sequence,
        can_rotate: state.can_rotate(),
        is_abandoned: state.is_abandoned,
    })
}

/// Resolve a did:keri at a specific sequence number (historical lookup).
///
/// This replays the KEL only up to the target sequence.
///
/// # Arguments
/// * `repo` - Git repository containing the KEL
/// * `did` - The did:keri string
/// * `target_sequence` - The sequence number to resolve at
pub fn resolve_did_keri_at_sequence(
    repo: &Repository,
    did: &str,
    target_sequence: u128,
) -> Result<DidKeriResolution, ResolveError> {
    let prefix = parse_did_keri(did)?;

    let kel = GitKel::new(repo, prefix.as_str());
    if !kel.exists() {
        return Err(ResolveError::NotFound(prefix.as_str().to_string()));
    }

    let events = kel.get_events()?;

    // Only process events up to target sequence
    let events_subset: Vec<_> = events
        .into_iter()
        .take_while(|e| e.sequence().value() <= target_sequence)
        .collect();

    if events_subset.is_empty() {
        return Err(ResolveError::NotFound(format!(
            "No events at sequence {}",
            target_sequence
        )));
    }

    let state = validate_kel(&events_subset)?;

    let key_encoded = state.current_key().ok_or(ResolveError::NoCurrentKey)?;
    let public_key = KeriPublicKey::parse(key_encoded.as_str())
        .map(|k| k.as_bytes().to_vec())
        .map_err(|e| ResolveError::InvalidKeyEncoding(e.to_string()))?;

    Ok(DidKeriResolution {
        #[allow(clippy::disallowed_methods)] // INVARIANT: parse_did_keri() above validated the did:keri format
        did: IdentityDID::new_unchecked(did),
        prefix,
        public_key,
        sequence: state.sequence,
        can_rotate: state.can_rotate(),
        is_abandoned: state.is_abandoned,
    })
}

/// Parse a did:keri string to extract the prefix.
pub fn parse_did_keri(did: &str) -> Result<Prefix, ResolveError> {
    const PREFIX: &str = "did:keri:";

    if !did.starts_with(PREFIX) {
        return Err(ResolveError::InvalidFormat(format!(
            "Expected did:keri: prefix, got: {}",
            did
        )));
    }

    let prefix = &did[PREFIX.len()..];
    if prefix.is_empty() {
        return Err(ResolveError::InvalidFormat("Empty KERI prefix".into()));
    }

    // Validate prefix format (starts with E for Blake3 SAID)
    if !prefix.starts_with('E') {
        return Err(ResolveError::InvalidFormat(format!(
            "Invalid KERI prefix format (expected E prefix): {}",
            prefix
        )));
    }

    Ok(Prefix::new_unchecked(prefix.to_string()))
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::keri::{create_keri_identity_with_curve, rotate_keys};
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
    fn parse_did_keri_valid() {
        let prefix = parse_did_keri("did:keri:EXq5YqaL6L48pf0fu7IUhL0JRaU2").unwrap();
        assert_eq!(prefix, "EXq5YqaL6L48pf0fu7IUhL0JRaU2");
    }

    #[test]
    fn parse_did_keri_rejects_wrong_method() {
        let result = parse_did_keri("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
        assert!(matches!(result, Err(ResolveError::InvalidFormat(_))));
    }

    #[test]
    fn parse_did_keri_rejects_empty_prefix() {
        let result = parse_did_keri("did:keri:");
        assert!(matches!(result, Err(ResolveError::InvalidFormat(_))));
    }

    #[test]
    fn parse_did_keri_rejects_invalid_prefix() {
        let result = parse_did_keri("did:keri:invalid");
        assert!(matches!(result, Err(ResolveError::InvalidFormat(_))));
    }

    #[test]
    fn resolves_after_inception() {
        let (_dir, repo) = setup_repo();

        let init = create_keri_identity_with_curve(
            &repo,
            None,
            chrono::Utc::now(),
            auths_crypto::CurveType::Ed25519,
        )
        .unwrap();
        let did = format!("did:keri:{}", init.prefix);

        let resolution = resolve_did_keri(&repo, &did).unwrap();

        assert_eq!(resolution.prefix, init.prefix);
        assert_eq!(resolution.public_key, init.current_public_key);
        assert_eq!(resolution.sequence, 0);
        assert!(resolution.can_rotate);
        assert!(!resolution.is_abandoned);
    }

    #[test]
    fn resolves_after_rotation() {
        let (_dir, repo) = setup_repo();

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

        let did = format!("did:keri:{}", init.prefix);
        let resolution = resolve_did_keri(&repo, &did).unwrap();

        // Should return the NEW key (former next key)
        assert_eq!(resolution.public_key, rot.new_current_public_key);
        assert_eq!(resolution.sequence, 1);
    }

    #[test]
    fn resolves_at_historical_sequence() {
        let (_dir, repo) = setup_repo();

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

        let did = format!("did:keri:{}", init.prefix);

        // Resolve at sequence 0 should return inception key
        let resolution = resolve_did_keri_at_sequence(&repo, &did, 0).unwrap();
        assert_eq!(resolution.public_key, init.current_public_key);
        assert_eq!(resolution.sequence, 0);
    }

    #[test]
    fn not_found_for_missing_kel() {
        let (_dir, repo) = setup_repo();

        let result = resolve_did_keri(&repo, "did:keri:ENotExist123");
        assert!(matches!(result, Err(ResolveError::NotFound(_))));
    }

    #[test]
    fn decode_ed25519_key() {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let key_bytes = [1u8; 32];
        let encoded = format!("D{}", URL_SAFE_NO_PAD.encode(key_bytes));

        let key = KeriPublicKey::parse(&encoded).unwrap();
        assert_eq!(key.as_bytes(), &key_bytes);
    }

    #[test]
    fn decode_unknown_key_type_fails() {
        let result = KeriPublicKey::parse("Xsomething");
        assert!(result.is_err());
    }
}
