//! Registry-based attestation storage adapter.
//!
//! This module provides an adapter that implements [`AttestationSource`] and
//! [`AttestationSink`] using the [`GitRegistryBackend`]. This enables hexagonal
//! architecture where the CLI depends on traits rather than concrete implementations.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────┐     ┌──────────────────────┐     ┌─────────────────────┐
//! │  CLI Commands   │────▶│  AttestationSource   │◀────│  PackedRegistry     │
//! │                 │     │  AttestationSink     │     │  Backend            │
//! └─────────────────┘     └──────────────────────┘     └─────────────────────┘
//!                                   │
//!                         ┌─────────┴─────────┐
//!                         │                   │
//!                         ▼                   ▼
//!               RegistryAttestation    (future adapters)
//!               Storage (this)
//! ```
//!
//! # Semantic Differences from GitAttestationStorage
//!
//! - **GitAttestationStorage**: Stores all attestation history as Git commit history
//! - **RegistryAttestationStorage**: Stores latest attestation + separate history directory
//!
//! Both adapters expose the same `AttestationSource` trait, allowing transparent switching.

use std::ops::ControlFlow;
use std::path::PathBuf;

use anyhow::{Error, Result};
use auths_verifier::core::{Attestation, VerifiedAttestation};
use auths_verifier::types::DeviceDID;

use auths_id::attestation::AttestationSink;
use auths_id::storage::attestation::AttestationSource;

use super::adapter::GitRegistryBackend;
use super::config::RegistryConfig;
use auths_id::ports::registry::RegistryBackend;

/// Registry-based implementation of [`AttestationSource`] and [`AttestationSink`].
///
/// Uses [`GitRegistryBackend`] to store attestations in the registry tree.
/// Device attestations are stored at `v1/devices/{shard}/{did}/attestation.json`
/// with history preserved in `attestation_history/`.
///
/// # Example
///
/// ```rust,ignore
/// use auths_storage::git::RegistryAttestationStorage;
/// use auths_id::storage::attestation::AttestationSource;
///
/// let storage = RegistryAttestationStorage::new("/path/to/repo");
/// let devices = storage.discover_device_dids()?;
/// for device in devices {
///     let attestations = storage.load_attestations_for_device(&device)?;
///     println!("{}: {} attestations", device, attestations.len());
/// }
/// ```
pub struct RegistryAttestationStorage {
    backend: GitRegistryBackend,
}

impl RegistryAttestationStorage {
    /// Create a new registry attestation storage for the given repository.
    pub fn new(repo_path: impl Into<PathBuf>) -> Self {
        let backend =
            GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(repo_path));
        Self { backend }
    }

    /// Initialize the registry if needed.
    ///
    /// Creates the initial registry commit if no registry exists.
    pub fn init_if_needed(&self) -> Result<(), Error> {
        self.backend
            .init_if_needed()
            .map(|_| ())
            .map_err(|e| anyhow::anyhow!("Failed to initialize registry: {}", e))
    }

    /// Get a reference to the underlying backend.
    ///
    /// Useful for accessing registry-specific operations not exposed via traits.
    pub fn backend(&self) -> &GitRegistryBackend {
        &self.backend
    }
}

impl AttestationSource for RegistryAttestationStorage {
    /// Loads all attestations for a specific device DID.
    ///
    /// Returns attestations in chronological order (oldest first), including
    /// all historical attestations and the current one.
    ///
    /// # Implementation Note
    ///
    /// The registry stores attestations to both `attestation.json` (current) and
    /// `history/` (append-only log) on every store. So:
    /// - If history is non-empty, it contains all attestations including current
    /// - If history is empty (legacy device), only current exists
    fn load_attestations_for_device(
        &self,
        device_did: &DeviceDID,
    ) -> Result<Vec<Attestation>, Error> {
        let mut attestations = Vec::new();

        // Collect from history (oldest to newest)
        self.backend
            .visit_attestation_history(device_did, &mut |att| {
                attestations.push(att.clone());
                ControlFlow::Continue(())
            })
            .map_err(|e| anyhow::anyhow!("Failed to load attestation history: {}", e))?;

        // If history is empty, this might be a legacy device with only current
        if attestations.is_empty()
            && let Ok(Some(att)) = self.backend.load_attestation(device_did)
        {
            attestations.push(att);
        }

        Ok(attestations)
    }

    fn load_all_attestations(&self) -> Result<Vec<Attestation>, Error> {
        self.load_all_attestations_paginated(usize::MAX, 0)
    }

    fn load_all_attestations_paginated(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<Attestation>, Error> {
        let mut all_attestations = Vec::new();
        let devices = self.discover_device_dids()?;

        for device_did in devices.into_iter().skip(offset).take(limit) {
            match self.load_attestations_for_device(&device_did) {
                Ok(device_attestations) => {
                    all_attestations.extend(device_attestations);
                }
                Err(e) => {
                    log::warn!(
                        "Failed to load attestations for device {}: {}",
                        device_did,
                        e
                    );
                }
            }
        }

        Ok(all_attestations)
    }

    /// Discovers device DIDs that have attestations stored in the registry.
    fn discover_device_dids(&self) -> Result<Vec<DeviceDID>, Error> {
        let mut devices = Vec::new();

        self.backend
            .visit_devices(&mut |did| {
                devices.push(did.clone());
                ControlFlow::Continue(())
            })
            .map_err(|e| anyhow::anyhow!("Failed to discover devices: {}", e))?;

        Ok(devices)
    }
}

impl AttestationSink for RegistryAttestationStorage {
    /// Stores a verified attestation in the registry.
    ///
    /// Uses the backend's `store_attestation` which has overwrite semantics:
    /// the current attestation is replaced, but history is preserved.
    fn export(&self, attestation: &VerifiedAttestation) -> Result<()> {
        self.backend
            .store_attestation(attestation.inner())
            .map_err(|e| anyhow::anyhow!("Failed to store attestation: {}", e))
    }

    fn sync_index(&self, attestation: &Attestation) {
        #[cfg(feature = "indexed-storage")]
        {
            use auths_id::storage::layout::StorageLayoutConfig;
            use auths_index::{AttestationIndex, IndexedAttestation};

            let config = StorageLayoutConfig::default();
            let index_path = self.backend.repo_path().join(".auths-index.db");

            let index = match AttestationIndex::open_or_create(&index_path) {
                Ok(idx) => idx,
                Err(e) => {
                    log::info!(
                        "Could not open index (this is OK if index hasn't been created yet): {}",
                        e
                    );
                    return;
                }
            };

            let device_did_sanitized = attestation.subject.to_string().replace([':', '/'], "_");
            let git_ref = format!(
                "{}/{}/signatures",
                config.device_attestation_prefix, device_did_sanitized
            );

            let indexed = IndexedAttestation {
                rid: attestation.rid.clone(),
                issuer_did: attestation.issuer.to_string(),
                device_did: attestation.subject.to_string(),
                git_ref,
                commit_oid: String::new(),
                revoked_at: attestation.revoked_at,
                expires_at: attestation.expires_at,
                updated_at: attestation.timestamp.unwrap_or_else(chrono::Utc::now),
            };

            if let Err(e) = index.upsert_attestation(&indexed) {
                log::warn!("Failed to update index: {}", e);
            } else {
                log::info!("Updated index for attestation {}", attestation.rid);
            }
        }
        #[cfg(not(feature = "indexed-storage"))]
        let _ = attestation;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_verifier::core::{Ed25519PublicKey, ResourceId};
    use auths_verifier::types::IdentityDID;
    use git2::Repository;
    use tempfile::TempDir;

    fn setup_test_repo() -> (TempDir, RegistryAttestationStorage) {
        let dir = TempDir::new().unwrap();
        Repository::init(dir.path()).unwrap();
        let storage = RegistryAttestationStorage::new(dir.path());
        storage.init_if_needed().unwrap();
        (dir, storage)
    }

    fn create_test_attestation(
        subject: &str,
        revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Attestation {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        Attestation {
            version: 1,
            rid: ResourceId::new(format!("test-rid-{}", seq)),
            issuer: IdentityDID::new("did:keri:ETestIssuer"),
            subject: DeviceDID::new(subject),
            device_public_key: Ed25519PublicKey::from_bytes([0u8; 32]),
            identity_signature: vec![5, 6, 7, 8],
            device_signature: vec![9, 10, 11, 12],
            revoked_at,
            expires_at: None,
            timestamp: Some(chrono::Utc::now() + chrono::Duration::seconds(seq as i64)),
            note: None,
            payload: None,
            role: None,
            capabilities: vec![],
            delegated_by: None,
            signer_type: None,
        }
    }

    #[test]
    fn test_discover_device_dids_empty() {
        let (_dir, storage) = setup_test_repo();
        let devices = storage.discover_device_dids().unwrap();
        assert!(devices.is_empty());
    }

    #[test]
    fn test_store_and_load_attestation() {
        let (_dir, storage) = setup_test_repo();

        let att = create_test_attestation("did:key:zTestDevice1", None);
        storage
            .export(&VerifiedAttestation::dangerous_from_unchecked(att.clone()))
            .unwrap();

        let devices = storage.discover_device_dids().unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].to_string(), "did:key:zTestDevice1");

        let loaded = storage.load_attestations_for_device(&devices[0]).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].subject, att.subject);
    }

    #[test]
    fn test_load_all_attestations() {
        let (_dir, storage) = setup_test_repo();

        let att1 = create_test_attestation("did:key:zDevice1", None);
        let att2 = create_test_attestation("did:key:zDevice2", None);

        storage
            .export(&VerifiedAttestation::dangerous_from_unchecked(att1))
            .unwrap();
        storage
            .export(&VerifiedAttestation::dangerous_from_unchecked(att2))
            .unwrap();

        let all = storage.load_all_attestations().unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_attestation_history() {
        let (_dir, storage) = setup_test_repo();

        let device_did = DeviceDID::new("did:key:zHistoryDevice");

        // Store first attestation
        let att1 = create_test_attestation("did:key:zHistoryDevice", None);
        storage
            .export(&VerifiedAttestation::dangerous_from_unchecked(att1))
            .unwrap();

        // Store updated attestation (this should create history)
        let att2 = create_test_attestation("did:key:zHistoryDevice", Some(chrono::Utc::now()));
        storage
            .export(&VerifiedAttestation::dangerous_from_unchecked(att2))
            .unwrap();

        // Load all attestations for this device
        let loaded = storage.load_attestations_for_device(&device_did).unwrap();

        // Should have history + current
        assert!(!loaded.is_empty());

        // The last one should be the revoked one (current)
        assert!(loaded.last().unwrap().is_revoked());
    }
}
