//! KERI identity inception with proper pre-rotation.
//!
//! Creates a new KERI identity by:
//! 1. Generating two Ed25519 keypairs (current + next)
//! 2. Computing next-key commitment
//! 3. Building and finalizing inception event with SAID
//! 4. Storing event in Git-backed KEL

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use git2::Repository;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

use crate::storage::registry::backend::{RegistryBackend, RegistryError};
use auths_crypto::Pkcs8Der;

use auths_core::crypto::said::compute_next_commitment;

use super::event::KeriSequence;
use super::types::{Prefix, Said};
use super::{Event, GitKel, IcpEvent, KERI_VERSION, KelError, ValidationError, finalize_icp_event};
use crate::witness_config::WitnessConfig;

/// Error type for inception operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum InceptionError {
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    #[error("KEL error: {0}")]
    Kel(#[from] KelError),

    #[error("Storage error: {0}")]
    Storage(RegistryError),

    #[error("Validation error: {0}")]
    Validation(#[from] ValidationError),

    #[error("Serialization error: {0}")]
    Serialization(String),
}

impl auths_core::error::AuthsErrorInfo for InceptionError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::KeyGeneration(_) => "AUTHS-E4901",
            Self::Kel(_) => "AUTHS-E4902",
            Self::Storage(_) => "AUTHS-E4903",
            Self::Validation(_) => "AUTHS-E4904",
            Self::Serialization(_) => "AUTHS-E4905",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::KeyGeneration(_) => None,
            Self::Kel(_) => Some("Check the KEL state; a KEL may already exist for this prefix"),
            Self::Storage(_) => Some("Check storage backend connectivity"),
            Self::Validation(_) => None,
            Self::Serialization(_) => None,
        }
    }
}

/// Result of a KERI identity inception.
pub struct InceptionResult {
    /// The KERI prefix (use with `did:keri:<prefix>`)
    pub prefix: Prefix,

    /// The current signing keypair (PKCS8 DER encoded, zeroed on drop)
    pub current_keypair_pkcs8: Pkcs8Der,

    /// The next rotation keypair (PKCS8 DER encoded, zeroed on drop)
    pub next_keypair_pkcs8: Pkcs8Der,

    /// The current public key (raw 32 bytes)
    pub current_public_key: Vec<u8>,

    /// The next public key (raw 32 bytes)
    pub next_public_key: Vec<u8>,
}

impl std::fmt::Debug for InceptionResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InceptionResult")
            .field("prefix", &self.prefix)
            .field("current_keypair_pkcs8", &self.current_keypair_pkcs8)
            .field("next_keypair_pkcs8", &self.next_keypair_pkcs8)
            .field("current_public_key", &self.current_public_key)
            .field("next_public_key", &self.next_public_key)
            .finish()
    }
}

impl InceptionResult {
    /// Get the full DID for this identity.
    pub fn did(&self) -> String {
        format!("did:keri:{}", self.prefix.as_str())
    }
}

/// Create a new KERI identity with proper pre-rotation.
///
/// This generates two Ed25519 keypairs:
/// - Current key: used for immediate signing
/// - Next key: committed to in the inception event for future rotation
///
/// The inception event is stored in the Git repository at:
/// `refs/did/keri/<prefix>/kel`
///
/// # Arguments
/// * `repo` - Git repository for KEL storage
/// * `witness_config` - Optional witness configuration. When provided and
///   enabled, the inception event's `bt`/`b` fields are set accordingly.
///
/// # Returns
/// * `InceptionResult` containing the prefix and both keypairs
pub fn create_keri_identity(
    repo: &Repository,
    witness_config: Option<&WitnessConfig>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<InceptionResult, InceptionError> {
    let rng = SystemRandom::new();

    // Generate current keypair
    let current_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|e| InceptionError::KeyGeneration(e.to_string()))?;
    let current_keypair = Ed25519KeyPair::from_pkcs8(current_pkcs8.as_ref())
        .map_err(|e| InceptionError::KeyGeneration(e.to_string()))?;

    // Generate next keypair (for pre-rotation)
    let next_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|e| InceptionError::KeyGeneration(e.to_string()))?;
    let next_keypair = Ed25519KeyPair::from_pkcs8(next_pkcs8.as_ref())
        .map_err(|e| InceptionError::KeyGeneration(e.to_string()))?;

    // Encode current public key with derivation code prefix
    // 'D' prefix indicates Ed25519 in KERI
    let current_pub_encoded = format!(
        "D{}",
        URL_SAFE_NO_PAD.encode(current_keypair.public_key().as_ref())
    );

    // Compute next-key commitment (Blake3 hash of next public key)
    let next_commitment = compute_next_commitment(next_keypair.public_key().as_ref());

    // Determine witness fields from config
    let (bt, b) = match witness_config {
        Some(cfg) if cfg.is_enabled() => (
            cfg.threshold.to_string(),
            cfg.witness_urls.iter().map(|u| u.to_string()).collect(),
        ),
        _ => ("0".to_string(), vec![]),
    };

    // Build inception event (without SAID)
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

    // Finalize event (computes and sets SAID)
    let mut finalized = finalize_icp_event(icp)?;
    let prefix = finalized.i.clone();

    // Sign the event with the current key
    let canonical = super::serialize_for_signing(&Event::Icp(finalized.clone()))?;
    let sig = current_keypair.sign(&canonical);
    finalized.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

    // Store in Git KEL
    let kel = GitKel::new(repo, prefix.as_str());
    kel.create(&finalized, now)?;

    // Collect witness receipts if configured
    #[cfg(feature = "witness-client")]
    if let Some(config) = witness_config
        && config.is_enabled()
    {
        let canonical_for_witness = super::serialize_for_signing(&Event::Icp(finalized.clone()))?;
        super::witness_integration::collect_and_store_receipts(
            repo.path().parent().unwrap_or(repo.path()),
            &prefix,
            &finalized.d,
            &canonical_for_witness,
            config,
            now,
        )
        .map_err(|e| InceptionError::Serialization(e.to_string()))?;
    }

    Ok(InceptionResult {
        prefix,
        current_keypair_pkcs8: Pkcs8Der::new(current_pkcs8.as_ref()),
        next_keypair_pkcs8: Pkcs8Der::new(next_pkcs8.as_ref()),
        current_public_key: current_keypair.public_key().as_ref().to_vec(),
        next_public_key: next_keypair.public_key().as_ref().to_vec(),
    })
}

/// Create a new KERI identity using any [`RegistryBackend`].
///
/// Identical logic to [`create_keri_identity`] but stores the inception event
/// via the provided backend instead of a git repository.
///
/// # Arguments
/// * `backend` - The registry backend to store the inception event
/// * `witness_config` - Unused in the backend path; kept for API symmetry
///
/// # Returns
/// * `InceptionResult` containing the prefix and both keypairs
pub fn create_keri_identity_with_backend(
    backend: &impl RegistryBackend,
    _witness_config: Option<&WitnessConfig>,
) -> Result<InceptionResult, InceptionError> {
    let rng = SystemRandom::new();

    let current_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|e| InceptionError::KeyGeneration(e.to_string()))?;
    let current_keypair = Ed25519KeyPair::from_pkcs8(current_pkcs8.as_ref())
        .map_err(|e| InceptionError::KeyGeneration(e.to_string()))?;

    let next_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|e| InceptionError::KeyGeneration(e.to_string()))?;
    let next_keypair = Ed25519KeyPair::from_pkcs8(next_pkcs8.as_ref())
        .map_err(|e| InceptionError::KeyGeneration(e.to_string()))?;

    let current_pub_encoded = format!(
        "D{}",
        URL_SAFE_NO_PAD.encode(current_keypair.public_key().as_ref())
    );
    let next_commitment = compute_next_commitment(next_keypair.public_key().as_ref());

    let icp = IcpEvent {
        v: KERI_VERSION.to_string(),
        d: Said::default(),
        i: Prefix::default(),
        s: KeriSequence::new(0),
        kt: "1".to_string(),
        k: vec![current_pub_encoded],
        nt: "1".to_string(),
        n: vec![next_commitment],
        bt: "0".to_string(),
        b: vec![],
        a: vec![],
        x: String::new(),
    };

    let mut finalized = finalize_icp_event(icp)?;
    let prefix = finalized.i.clone();

    let canonical = super::serialize_for_signing(&Event::Icp(finalized.clone()))?;
    let sig = current_keypair.sign(&canonical);
    finalized.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

    backend
        .append_event(&prefix, &Event::Icp(finalized))
        .map_err(InceptionError::Storage)?;

    Ok(InceptionResult {
        prefix,
        current_keypair_pkcs8: Pkcs8Der::new(current_pkcs8.as_ref()),
        next_keypair_pkcs8: Pkcs8Der::new(next_pkcs8.as_ref()),
        current_public_key: current_keypair.public_key().as_ref().to_vec(),
        next_public_key: next_keypair.public_key().as_ref().to_vec(),
    })
}

/// Create a KERI identity from an existing Ed25519 key (PKCS8 DER).
///
/// Used for migrating existing `did:key` identities to `did:keri`.
/// The provided key becomes the current signing key; a new next key
/// is generated for pre-rotation.
///
/// # Arguments
/// * `repo` - Git repository for KEL storage
/// * `current_pkcs8_bytes` - Existing Ed25519 key in PKCS8 v2 DER format
/// * `witness_config` - Optional witness configuration
/// * `now` - Timestamp for the inception event
pub fn create_keri_identity_from_key(
    repo: &Repository,
    current_pkcs8_bytes: &[u8],
    witness_config: Option<&WitnessConfig>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<InceptionResult, InceptionError> {
    let rng = SystemRandom::new();

    // Use the provided key as the current keypair
    let current_keypair = Ed25519KeyPair::from_pkcs8(current_pkcs8_bytes)
        .map_err(|e| InceptionError::KeyGeneration(format!("invalid PKCS8 key: {e}")))?;

    // Generate next keypair (for pre-rotation)
    let next_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|e| InceptionError::KeyGeneration(e.to_string()))?;
    let next_keypair = Ed25519KeyPair::from_pkcs8(next_pkcs8.as_ref())
        .map_err(|e| InceptionError::KeyGeneration(e.to_string()))?;

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

    let mut finalized = finalize_icp_event(icp)?;
    let prefix = finalized.i.clone();

    let canonical = super::serialize_for_signing(&Event::Icp(finalized.clone()))?;
    let sig = current_keypair.sign(&canonical);
    finalized.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

    let kel = GitKel::new(repo, prefix.as_str());
    kel.create(&finalized, now)?;

    Ok(InceptionResult {
        prefix,
        current_keypair_pkcs8: Pkcs8Der::new(current_pkcs8_bytes),
        next_keypair_pkcs8: Pkcs8Der::new(next_pkcs8.as_ref()),
        current_public_key: current_keypair.public_key().as_ref().to_vec(),
        next_public_key: next_keypair.public_key().as_ref().to_vec(),
    })
}

/// Format a KERI prefix as a full DID.
pub fn prefix_to_did(prefix: &str) -> String {
    format!("did:keri:{}", prefix)
}

/// Extract the prefix from a did:keri DID.
///
/// Prefer [`auths_verifier::IdentityDID`] at API boundaries for type safety.
pub fn did_to_prefix(did: &str) -> Option<&str> {
    did.strip_prefix("did:keri:")
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::keri::{Event, validate_kel};
    use tempfile::TempDir;

    fn setup_repo() -> (TempDir, Repository) {
        let dir = TempDir::new().unwrap();
        let repo = Repository::init(dir.path()).unwrap();

        // Set git config for CI environments
        let mut config = repo.config().unwrap();
        config.set_str("user.name", "Test User").unwrap();
        config.set_str("user.email", "test@example.com").unwrap();

        (dir, repo)
    }

    #[test]
    fn create_identity_returns_valid_result() {
        let (_dir, repo) = setup_repo();

        let result = create_keri_identity(&repo, None, chrono::Utc::now()).unwrap();

        // Prefix should start with 'E' (Blake3 SAID prefix)
        assert!(result.prefix.as_str().starts_with('E'));

        // Keys should be present
        assert!(!result.current_keypair_pkcs8.is_empty());
        assert!(!result.next_keypair_pkcs8.is_empty());
        assert_eq!(result.current_public_key.len(), 32);
        assert_eq!(result.next_public_key.len(), 32);

        // DID should be formatted correctly
        assert!(result.did().starts_with("did:keri:E"));
    }

    #[test]
    fn create_identity_stores_kel() {
        let (_dir, repo) = setup_repo();

        let result = create_keri_identity(&repo, None, chrono::Utc::now()).unwrap();

        // Verify KEL exists and has one event
        let kel = GitKel::new(&repo, result.prefix.as_str());
        assert!(kel.exists());

        let events = kel.get_events().unwrap();
        assert_eq!(events.len(), 1);
        assert!(events[0].is_inception());
    }

    #[test]
    fn inception_event_is_valid() {
        let (_dir, repo) = setup_repo();

        let result = create_keri_identity(&repo, None, chrono::Utc::now()).unwrap();
        let kel = GitKel::new(&repo, result.prefix.as_str());
        let events = kel.get_events().unwrap();

        // Validate the KEL
        let state = validate_kel(&events).unwrap();
        assert_eq!(state.prefix, result.prefix);
        assert_eq!(state.sequence, 0);
        assert!(!state.is_abandoned);
    }

    #[test]
    fn inception_event_has_correct_structure() {
        let (_dir, repo) = setup_repo();

        let result = create_keri_identity(&repo, None, chrono::Utc::now()).unwrap();
        let kel = GitKel::new(&repo, result.prefix.as_str());
        let events = kel.get_events().unwrap();

        if let Event::Icp(icp) = &events[0] {
            // Version
            assert_eq!(icp.v, KERI_VERSION);

            // SAID equals prefix
            assert_eq!(icp.d.as_str(), icp.i.as_str());
            assert_eq!(icp.d.as_str(), result.prefix.as_str());

            // Sequence is 0
            assert_eq!(icp.s, KeriSequence::new(0));

            // Single key
            assert_eq!(icp.k.len(), 1);
            assert!(icp.k[0].starts_with('D')); // Ed25519 prefix

            // Single next commitment
            assert_eq!(icp.n.len(), 1);
            assert!(icp.n[0].starts_with('E')); // Blake3 hash prefix

            // No witnesses
            assert_eq!(icp.bt, "0");
            assert!(icp.b.is_empty());
        } else {
            panic!("Expected inception event");
        }
    }

    #[test]
    fn next_key_commitment_is_correct() {
        let (_dir, repo) = setup_repo();

        let result = create_keri_identity(&repo, None, chrono::Utc::now()).unwrap();
        let kel = GitKel::new(&repo, result.prefix.as_str());
        let events = kel.get_events().unwrap();

        if let Event::Icp(icp) = &events[0] {
            // Verify the next commitment matches the next public key
            let expected_commitment = compute_next_commitment(&result.next_public_key);
            assert_eq!(icp.n[0], expected_commitment);
        } else {
            panic!("Expected inception event");
        }
    }

    #[test]
    fn prefix_to_did_works() {
        assert_eq!(prefix_to_did("ETest123"), "did:keri:ETest123");
    }

    #[test]
    fn did_to_prefix_works() {
        assert_eq!(did_to_prefix("did:keri:ETest123"), Some("ETest123"));
        assert_eq!(did_to_prefix("did:key:z6Mk..."), None);
    }

    #[test]
    fn multiple_identities_have_different_prefixes() {
        let (_dir, repo) = setup_repo();

        let result1 = create_keri_identity(&repo, None, chrono::Utc::now()).unwrap();

        // Create second repo for second identity
        let (_dir2, repo2) = setup_repo();
        let result2 = create_keri_identity(&repo2, None, chrono::Utc::now()).unwrap();

        // Prefixes should be different
        assert_ne!(result1.prefix, result2.prefix);
    }
}
