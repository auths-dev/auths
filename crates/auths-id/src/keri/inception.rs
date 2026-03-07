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
use zeroize::Zeroizing;

use auths_core::crypto::said::compute_next_commitment;

use super::event::KeriSequence;
use super::types::{Prefix, Said};
use super::{Event, GitKel, IcpEvent, KERI_VERSION, KelError, ValidationError, finalize_icp_event};
use crate::witness_config::WitnessConfig;

/// Error type for inception operations.
#[derive(Debug, thiserror::Error)]
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

/// Result of a KERI identity inception.
pub struct InceptionResult {
    /// The KERI prefix (use with did:keri:<prefix>)
    pub prefix: Prefix,

    /// The current signing keypair (PKCS8 DER encoded)
    pub current_keypair_pkcs8: Zeroizing<Vec<u8>>,

    /// The next rotation keypair (PKCS8 DER encoded)
    pub next_keypair_pkcs8: Zeroizing<Vec<u8>>,

    /// The current public key (raw 32 bytes)
    pub current_public_key: Vec<u8>,

    /// The next public key (raw 32 bytes)
    pub next_public_key: Vec<u8>,
}

impl std::fmt::Debug for InceptionResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InceptionResult")
            .field("prefix", &self.prefix)
            .field("current_keypair_pkcs8", &"[REDACTED]")
            .field("next_keypair_pkcs8", &"[REDACTED]")
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
    kel.create(&finalized)?;

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
        )
        .map_err(|e| InceptionError::Serialization(e.to_string()))?;
    }

    Ok(InceptionResult {
        prefix,
        current_keypair_pkcs8: Zeroizing::new(current_pkcs8.as_ref().to_vec()),
        next_keypair_pkcs8: Zeroizing::new(next_pkcs8.as_ref().to_vec()),
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
        current_keypair_pkcs8: Zeroizing::new(current_pkcs8.as_ref().to_vec()),
        next_keypair_pkcs8: Zeroizing::new(next_pkcs8.as_ref().to_vec()),
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
/// Prefer [`auths_core::keri_did::KeriDid`] at API boundaries for type safety.
pub fn did_to_prefix(did: &str) -> Option<&str> {
    did.strip_prefix("did:keri:")
}

#[cfg(test)]
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

        let result = create_keri_identity(&repo, None).unwrap();

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

        let result = create_keri_identity(&repo, None).unwrap();

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

        let result = create_keri_identity(&repo, None).unwrap();
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

        let result = create_keri_identity(&repo, None).unwrap();
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

        let result = create_keri_identity(&repo, None).unwrap();
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

        let result1 = create_keri_identity(&repo, None).unwrap();

        // Create second repo for second identity
        let (_dir2, repo2) = setup_repo();
        let result2 = create_keri_identity(&repo2, None).unwrap();

        // Prefixes should be different
        assert_ne!(result1.prefix, result2.prefix);
    }
}
