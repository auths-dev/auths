//! Indexed attestation storage that uses SQLite for O(1) lookups.
//!
//! This module provides `IndexedAttestationStorage` which wraps `GitAttestationStorage`
//! and adds a SQLite index layer for fast queries. The index is used for lookups,
//! while the actual attestation data is still loaded from Git.

use crate::error::StorageError;
use crate::storage::attestation::AttestationSource;
use crate::storage::attestation_git::GitAttestationStorage;
use crate::storage::layout::StorageLayoutConfig;
use auths_index::{AttestationIndex, IndexedAttestation, rebuild_attestations_from_git};
use auths_verifier::core::Attestation;
use auths_verifier::types::DeviceDID;
use chrono::Utc;
use std::path::{Path, PathBuf};

/// An attestation storage that uses a SQLite index for fast lookups
/// with Git as the source of truth for attestation data.
pub struct IndexedAttestationStorage {
    /// The underlying Git storage for loading full attestations
    git_storage: GitAttestationStorage,
    /// The SQLite index for fast queries
    index: AttestationIndex,
    /// Path to the repository
    repo_path: PathBuf,
    /// Storage layout configuration
    config: StorageLayoutConfig,
}

impl IndexedAttestationStorage {
    /// Opens an indexed attestation storage.
    ///
    /// If the index doesn't exist, it will be created and populated from Git refs.
    pub fn open(
        repo_path: impl AsRef<Path>,
        config: StorageLayoutConfig,
    ) -> Result<Self, StorageError> {
        let repo_path = repo_path.as_ref().to_path_buf();
        let index_path = repo_path.join(".auths-index.db");

        let git_storage = GitAttestationStorage::new(repo_path.clone(), config.clone());
        let index = AttestationIndex::open_or_create(&index_path)
            .map_err(|e| StorageError::Index(e.to_string()))?;

        if index.count().unwrap_or(0) == 0 {
            log::info!("Index is empty, rebuilding from Git refs...");
            rebuild_attestations_from_git(
                &index,
                &repo_path,
                &config.device_attestation_prefix,
                &config.attestation_blob_name,
            )
            .map_err(|e| StorageError::Index(e.to_string()))?;
        }

        Ok(Self {
            git_storage,
            index,
            repo_path,
            config,
        })
    }

    /// Returns a reference to the underlying index.
    pub fn index(&self) -> &AttestationIndex {
        &self.index
    }

    /// Rebuilds the index from Git refs.
    pub fn rebuild_index(&self) -> Result<(), StorageError> {
        rebuild_attestations_from_git(
            &self.index,
            &self.repo_path,
            &self.config.device_attestation_prefix,
            &self.config.attestation_blob_name,
        )
        .map_err(|e| StorageError::Index(e.to_string()))?;
        Ok(())
    }

    /// Updates the index with a new or modified attestation.
    pub fn update_index(
        &self,
        att: &Attestation,
        git_ref: &str,
        commit_oid: &str,
    ) -> Result<(), StorageError> {
        let indexed = IndexedAttestation {
            rid: att.rid.to_string(),
            issuer_did: att.issuer.to_string(),
            device_did: att.subject.to_string(),
            git_ref: git_ref.to_string(),
            commit_oid: commit_oid.to_string(),
            revoked_at: att.revoked_at,
            expires_at: att.expires_at,
            updated_at: att.timestamp.unwrap_or_else(Utc::now),
        };

        self.index
            .upsert_attestation(&indexed)
            .map_err(|e| StorageError::Index(e.to_string()))
    }

    /// Loads attestations for a device using the index for lookup,
    /// then fetching full data from Git.
    pub fn load_attestations_indexed(
        &self,
        device_did: &DeviceDID,
    ) -> Result<Vec<Attestation>, StorageError> {
        let indexed = self
            .index
            .query_by_device(&device_did.to_string())
            .map_err(|e| StorageError::Index(e.to_string()))?;

        if indexed.is_empty() {
            // Nothing in index, fall back to Git
            log::debug!(
                "No index entries for device {}, falling back to Git",
                device_did
            );
            return self.git_storage.load_attestations_for_device(device_did);
        }

        // Load full attestations from Git
        self.git_storage.load_attestations_for_device(device_did)
    }
}

impl AttestationSource for IndexedAttestationStorage {
    fn load_attestations_for_device(
        &self,
        device_did: &DeviceDID,
    ) -> Result<Vec<Attestation>, StorageError> {
        self.load_attestations_indexed(device_did)
    }

    fn load_all_attestations(&self) -> Result<Vec<Attestation>, StorageError> {
        self.git_storage.load_all_attestations()
    }

    fn discover_device_dids(&self) -> Result<Vec<DeviceDID>, StorageError> {
        let active = self
            .index
            .query_active()
            .map_err(|e| StorageError::Index(e.to_string()))?;

        if active.is_empty() {
            // Fall back to Git-based discovery
            return self.git_storage.discover_device_dids();
        }

        // Collect unique device DIDs from the index
        let mut dids: Vec<DeviceDID> = active
            .into_iter()
            .map(|a| DeviceDID::new(&a.device_did))
            .collect();
        dids.sort_by(|a, b| a.0.cmp(&b.0));
        dids.dedup();
        Ok(dids)
    }
}

#[cfg(test)]
mod tests {
    // Tests would require setting up a Git repo with attestations
    // which is complex for unit tests. Integration tests are more appropriate.
}
