//! Registry-based identity storage adapter.
//!
//! This module provides an adapter that implements [`IdentityStorage`] using
//! the [`GitRegistryBackend`]. This enables hexagonal architecture where
//! the CLI depends on traits rather than concrete implementations.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────┐     ┌──────────────────────┐     ┌─────────────────────┐
//! │  CLI Commands   │────▶│  IdentityStorage     │◀────│  PackedRegistry     │
//! │                 │     │  (trait)             │     │  Backend            │
//! └─────────────────┘     └──────────────────────┘     └─────────────────────┘
//!                                   │
//!                         ┌─────────┴─────────┐
//!                         │                   │
//!                         ▼                   ▼
//!               RegistryIdentity       (future adapters)
//!               Storage (this)
//! ```
//!
//! # Data Mapping
//!
//! - `controller_did` = `did:keri:{prefix}` (derived from KeyState)
//! - `storage_id` = repository directory name
//! - `metadata` = stored in `v1/identities/{shard}/{prefix}/metadata.json`

use std::path::PathBuf;

use anyhow::{Context, Error, Result};
use git2::Repository;
use serde::{Deserialize, Serialize};

use auths_core::storage::keychain::IdentityDID;
use auths_id::identity::helpers::ManagedIdentity;
use auths_id::storage::identity::IdentityStorage;

use super::adapter::{GitRegistryBackend, REGISTRY_REF};
use super::config::RegistryConfig;
use super::tree_ops::{TreeMutator, TreeNavigator};
use auths_id::ports::registry::RegistryBackend;
use auths_id::storage::registry::shard::identity_path;

/// Identity metadata stored alongside KERI events.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredMetadata {
    /// Schema version for forward compatibility
    version: u32,
    /// Arbitrary metadata JSON
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<serde_json::Value>,
}

impl StoredMetadata {
    const CURRENT_VERSION: u32 = 1;

    fn new(metadata: Option<serde_json::Value>) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            metadata,
        }
    }
}

/// Registry-based implementation of [`IdentityStorage`].
///
/// Uses [`GitRegistryBackend`] to store identity data in the registry tree.
/// Identity metadata is stored in `v1/identities/{shard}/{prefix}/metadata.json`.
///
/// # Example
///
/// ```rust,ignore
/// use auths_storage::git::RegistryIdentityStorage;
/// use auths_id::storage::identity::IdentityStorage;
///
/// let storage = RegistryIdentityStorage::new("/path/to/repo");
/// let identity = storage.load_identity()?;
/// println!("Controller: {}", identity.controller_did);
/// ```
pub struct RegistryIdentityStorage {
    repo_path: PathBuf,
    backend: GitRegistryBackend,
}

impl RegistryIdentityStorage {
    /// Create a new registry identity storage for the given repository.
    pub fn new(repo_path: impl Into<PathBuf>) -> Self {
        let repo_path = repo_path.into();
        let backend =
            GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(&repo_path));
        Self { repo_path, backend }
    }

    /// Initialize the registry if needed and create a KERI identity.
    ///
    /// This is the registry equivalent of identity initialization.
    /// It creates a KERI inception event and stores it in the registry,
    /// along with optional metadata.
    ///
    /// # Returns
    ///
    /// A tuple of (controller_did, InceptionResult) where InceptionResult
    /// contains the keypairs for storage.
    pub fn initialize_identity(
        &self,
        metadata: Option<serde_json::Value>,
        witness_config: Option<&auths_id::witness_config::WitnessConfig>,
    ) -> Result<(String, auths_id::keri::InceptionResult), Error> {
        use auths_core::crypto::said::compute_next_commitment;
        use auths_id::keri::{
            Event, IcpEvent, InceptionResult, KeriSequence, KERI_VERSION, Prefix, Said,
            finalize_icp_event, serialize_for_signing,
        };
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        use ring::rand::SystemRandom;
        use ring::signature::{Ed25519KeyPair, KeyPair};

        // Initialize registry if needed
        self.backend
            .init_if_needed()
            .context("Failed to initialize registry")?;

        // Generate keypairs
        let rng = SystemRandom::new();
        let current_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|e| anyhow::anyhow!("Key generation failed: {}", e))?;
        let current_keypair = Ed25519KeyPair::from_pkcs8(current_pkcs8.as_ref())
            .map_err(|e| anyhow::anyhow!("Key generation failed: {}", e))?;

        let next_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|e| anyhow::anyhow!("Key generation failed: {}", e))?;
        let next_keypair = Ed25519KeyPair::from_pkcs8(next_pkcs8.as_ref())
            .map_err(|e| anyhow::anyhow!("Key generation failed: {}", e))?;

        // Encode current public key with derivation code prefix
        let current_pub_encoded = format!(
            "D{}",
            URL_SAFE_NO_PAD.encode(current_keypair.public_key().as_ref())
        );

        // Compute next-key commitment
        let next_commitment = compute_next_commitment(next_keypair.public_key().as_ref());

        // Determine witness fields from config
        let (bt, b) = match witness_config {
            Some(cfg) if cfg.is_enabled() => (cfg.threshold.to_string(), cfg.witness_urls.iter().map(|u| u.to_string()).collect()),
            _ => ("0".to_string(), vec![]),
        };

        // Build inception event
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

        // Finalize event (computes SAID)
        let mut finalized = finalize_icp_event(icp)
            .map_err(|e| anyhow::anyhow!("Failed to finalize ICP: {}", e))?;
        let prefix = finalized.i.clone();

        // Sign the event
        let canonical = serialize_for_signing(&Event::Icp(finalized.clone()))
            .map_err(|e| anyhow::anyhow!("Failed to serialize for signing: {}", e))?;
        let sig = current_keypair.sign(&canonical);
        finalized.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

        // Store event in packed registry
        self.backend
            .append_event(&prefix, &Event::Icp(finalized))
            .map_err(|e| anyhow::anyhow!("Failed to store event in registry: {}", e))?;

        let controller_did = format!("did:keri:{}", prefix);

        // Store metadata if provided
        if metadata.is_some() {
            self.store_metadata(&prefix, metadata)?;
        }

        Ok((
            controller_did,
            InceptionResult {
                prefix,
                current_keypair_pkcs8: current_pkcs8.as_ref().to_vec(),
                next_keypair_pkcs8: next_pkcs8.as_ref().to_vec(),
                current_public_key: current_keypair.public_key().as_ref().to_vec(),
                next_public_key: next_keypair.public_key().as_ref().to_vec(),
            },
        ))
    }

    /// Store metadata for an identity.
    fn store_metadata(
        &self,
        prefix: &auths_verifier::keri::Prefix,
        metadata: Option<serde_json::Value>,
    ) -> Result<(), Error> {
        let repo = Repository::open(&self.repo_path)?;

        // Get current registry tree
        let registry_ref = repo.find_reference(REGISTRY_REF)?;
        let commit = registry_ref.peel_to_commit()?;
        let tree = commit.tree()?;

        // Build metadata path
        let id_path =
            identity_path(prefix).map_err(|e| anyhow::anyhow!("Invalid prefix: {}", e))?;
        let metadata_path = format!("{}/metadata.json", id_path);

        // Serialize metadata
        let stored = StoredMetadata::new(metadata);
        let json = serde_json::to_vec_pretty(&stored)?;

        // Write to tree
        let mut mutator = TreeMutator::new();
        mutator.write_blob(&metadata_path, json);
        let new_tree_oid = mutator.build_tree(&repo, Some(&tree))?;
        let new_tree = repo.find_tree(new_tree_oid)?;

        // Create commit
        let sig = git2::Signature::now("auths", "auths@local")?;
        let parent = &[&commit];
        repo.commit(
            Some(REGISTRY_REF),
            &sig,
            &sig,
            "Store identity metadata",
            &new_tree,
            parent,
        )?;

        Ok(())
    }

    /// Load metadata for an identity.
    fn load_metadata(
        &self,
        prefix: &auths_verifier::keri::Prefix,
    ) -> Result<Option<serde_json::Value>, Error> {
        let repo = Repository::open(&self.repo_path)?;

        let registry_ref = match repo.find_reference(REGISTRY_REF) {
            Ok(r) => r,
            Err(_) => return Ok(None),
        };

        let commit = registry_ref.peel_to_commit()?;
        let tree = commit.tree()?;

        let id_path =
            identity_path(prefix).map_err(|e| anyhow::anyhow!("Invalid prefix: {}", e))?;
        let metadata_path = format!("{}/metadata.json", id_path);

        let nav = TreeNavigator::new(&repo, tree);
        match nav.read_blob_path(&metadata_path) {
            Ok(bytes) => {
                let stored: StoredMetadata = serde_json::from_slice(&bytes)?;
                Ok(stored.metadata)
            }
            Err(_) => Ok(None),
        }
    }

    /// Get the storage ID (repository directory name).
    fn get_storage_id(&self) -> String {
        self.repo_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string()
    }

    /// Find the first identity prefix in the registry.
    fn find_first_identity(&self) -> Result<Option<String>, Error> {
        use std::ops::ControlFlow;

        let mut prefix = None;
        self.backend
            .visit_identities(&mut |p| {
                prefix = Some(p.to_string());
                ControlFlow::Break(())
            })
            .map_err(|e| anyhow::anyhow!("Failed to visit identities: {}", e))?;

        Ok(prefix)
    }
}

impl IdentityStorage for RegistryIdentityStorage {
    fn create_identity(
        &self,
        controller_did: &str,
        metadata: Option<serde_json::Value>,
    ) -> Result<(), Error> {
        use auths_verifier::keri::Prefix;

        // Extract prefix from controller_did (did:keri:{prefix})
        let prefix_str = controller_did
            .strip_prefix("did:keri:")
            .ok_or_else(|| anyhow::anyhow!("Invalid controller DID format: {}", controller_did))?;
        let prefix = Prefix::new_unchecked(prefix_str.to_string());

        // Store metadata for this identity
        self.store_metadata(&prefix, metadata)?;

        Ok(())
    }

    fn load_identity(&self) -> Result<ManagedIdentity, Error> {
        use auths_verifier::keri::Prefix;

        // Find the first (and typically only) identity in the registry
        let prefix_str = self
            .find_first_identity()?
            .ok_or_else(|| anyhow::anyhow!("No identity found in registry"))?;
        let prefix = Prefix::new_unchecked(prefix_str.clone());

        // Load key state to verify identity exists
        self.backend
            .get_key_state(&prefix)
            .map_err(|e| anyhow::anyhow!("Failed to load key state: {}", e))?;

        // Build controller DID
        let controller_did = format!("did:keri:{}", prefix_str);

        // Load metadata
        let metadata = self.load_metadata(&prefix)?;

        Ok(ManagedIdentity {
            controller_did: IdentityDID::new_unchecked(controller_did),
            storage_id: self.get_storage_id(),
            metadata,
        })
    }

    fn get_identity_ref(&self) -> Result<String, Error> {
        Ok(REGISTRY_REF.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup_test_repo() -> (TempDir, RegistryIdentityStorage) {
        let dir = TempDir::new().unwrap();
        Repository::init(dir.path()).unwrap();
        let storage = RegistryIdentityStorage::new(dir.path());
        (dir, storage)
    }

    #[test]
    fn test_get_identity_ref() {
        let (_dir, storage) = setup_test_repo();
        let ref_name = storage.get_identity_ref().unwrap();
        assert_eq!(ref_name, "refs/auths/registry");
    }

    #[test]
    fn test_initialize_and_load_identity() {
        let (_dir, storage) = setup_test_repo();

        // Initialize with metadata
        let metadata = serde_json::json!({
            "name": "Test Identity",
            "created": "2024-01-01"
        });

        let (did, _result) = storage
            .initialize_identity(Some(metadata.clone()), None)
            .unwrap();
        assert!(did.starts_with("did:keri:"));

        // Load identity
        let identity = storage.load_identity().unwrap();
        assert_eq!(identity.controller_did, did.as_str());
        assert!(identity.metadata.is_some());
        assert_eq!(identity.metadata.as_ref().unwrap()["name"], "Test Identity");
    }

    #[test]
    fn test_load_identity_without_metadata() {
        let (_dir, storage) = setup_test_repo();

        // Initialize without metadata
        let (did, _result) = storage.initialize_identity(None, None).unwrap();

        // Load identity
        let identity = storage.load_identity().unwrap();
        assert_eq!(identity.controller_did, did.as_str());
        assert!(identity.metadata.is_none());
    }

    #[test]
    fn test_load_identity_not_found() {
        let (_dir, storage) = setup_test_repo();

        // Initialize registry but don't create identity
        storage.backend.init_if_needed().unwrap();

        let result = storage.load_identity();
        assert!(result.is_err());
    }
}
