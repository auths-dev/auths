use auths_id::error::StorageError;
use auths_id::storage::attestation::AttestationSource;
use auths_id::storage::layout::{
    StorageLayoutConfig, attestation_blob_name, attestation_ref_for_device,
    default_attestation_prefixes,
};
use auths_verifier::core::Attestation;
use auths_verifier::types::DeviceDID;
use git2::{ErrorCode, Repository, Tree};
use std::collections::HashSet;
use std::path::PathBuf;

/// An implementation of `AttestationSource` that uses a Git repository
/// with a configurable reference and blob name layout for attestations.
#[derive(Debug, Clone)]
pub struct GitAttestationStorage {
    repo_path: PathBuf,
    config: StorageLayoutConfig,
}

impl GitAttestationStorage {
    /// Creates a new GitAttestationStorage instance for the given repository path
    /// using the specified layout configuration.
    pub fn new(repo_path: impl Into<PathBuf>, config: StorageLayoutConfig) -> Self {
        GitAttestationStorage {
            repo_path: repo_path.into(),
            config,
        }
    }

    /// Creates a new GitAttestationStorage instance using the default layout configuration.
    pub fn new_with_defaults(repo_path: impl Into<PathBuf>) -> Self {
        Self::new(repo_path, StorageLayoutConfig::default())
    }

    fn open_repo(&self) -> Result<Repository, StorageError> {
        Ok(Repository::open(&self.repo_path)?)
    }

    fn read_attestation_from_tree(
        &self,
        repo: &Repository,
        tree: &Tree,
    ) -> Result<Attestation, StorageError> {
        let blob_filename = attestation_blob_name(&self.config);
        let entry = tree.get_name(blob_filename).ok_or_else(|| {
            StorageError::NotFound(format!(
                "Attestation tree missing blob named '{}'",
                blob_filename
            ))
        })?;

        let blob = repo.find_blob(entry.id())?;
        let att: Attestation = serde_json::from_slice(blob.content())?;

        Ok(att)
    }

    fn load_history(
        &self,
        repo: &Repository,
        ref_name: &str,
    ) -> Result<Vec<Attestation>, StorageError> {
        let mut attestations = Vec::new();
        let reference = match repo.find_reference(ref_name) {
            Ok(r) => r,
            Err(e) if e.code() == ErrorCode::NotFound => return Ok(attestations),
            Err(e) => return Err(e.into()),
        };

        let mut commit = reference.peel_to_commit()?;

        loop {
            match commit.tree() {
                Ok(tree) => match self.read_attestation_from_tree(repo, &tree) {
                    Ok(att) => attestations.push(att),
                    Err(e) => log::warn!(
                        "Failed to read attestation from commit {}: {}",
                        commit.id(),
                        e
                    ),
                },
                Err(e) => log::warn!("Failed to get tree for commit {}: {}", commit.id(), e),
            }

            if commit.parent_count() > 0 {
                match commit.parent(0) {
                    Ok(parent) => commit = parent,
                    Err(e) => {
                        log::warn!(
                            "Failed to get parent commit for {}: {}. Stopping history walk.",
                            commit.id(),
                            e
                        );
                        break;
                    }
                }
            } else {
                break;
            }
        }
        attestations.reverse();
        Ok(attestations)
    }
}

impl AttestationSource for GitAttestationStorage {
    fn load_attestations_for_device(
        &self,
        device_did: &DeviceDID,
    ) -> Result<Vec<Attestation>, StorageError> {
        let repo = self.open_repo()?;
        let sig_ref = attestation_ref_for_device(&self.config, device_did);
        log::debug!(
            "Loading attestation history for device {} from ref '{}'",
            device_did,
            sig_ref
        );
        self.load_history(&repo, &sig_ref)
    }

    fn load_all_attestations(&self) -> Result<Vec<Attestation>, StorageError> {
        self.load_all_attestations_paginated(usize::MAX, 0)
    }

    fn load_all_attestations_paginated(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<Attestation>, StorageError> {
        log::debug!(
            "Loading attestations (limit={}, offset={})...",
            limit,
            offset
        );
        let mut all_attestations = Vec::new();
        let discovered_dids = self.discover_device_dids()?;
        log::debug!(
            "Discovered {} potential device DIDs.",
            discovered_dids.len()
        );

        for device_did in discovered_dids.into_iter().skip(offset).take(limit) {
            match self.load_attestations_for_device(&device_did) {
                Ok(device_attestations) => {
                    log::trace!(
                        "Loaded {} attestations for device {}",
                        device_attestations.len(),
                        device_did
                    );
                    all_attestations.extend(device_attestations);
                }
                Err(e) => {
                    log::warn!(
                        "Failed to load attestations for discovered device {}: {}",
                        device_did,
                        e
                    );
                }
            }
        }
        log::debug!("Total attestations loaded: {}", all_attestations.len());
        Ok(all_attestations)
    }

    fn discover_device_dids(&self) -> Result<Vec<DeviceDID>, StorageError> {
        let repo = self.open_repo()?;
        let mut discovered_dids = HashSet::new();
        let patterns = default_attestation_prefixes(&self.config);
        log::debug!("Discovering device DIDs using patterns: {:?}", patterns);

        for pattern_base in patterns {
            let glob_pattern = format!("{}/{}", pattern_base.trim_end_matches('/'), "*/signatures");
            log::trace!("Globbing with pattern: {}", glob_pattern);

            match repo.references_glob(&glob_pattern) {
                Ok(references) => {
                    for reference_result in references {
                        let reference = match reference_result {
                            Ok(r) => r,
                            Err(e) => {
                                log::warn!(
                                    "Error iterating glob results for pattern '{}': {}",
                                    glob_pattern,
                                    e
                                );
                                continue;
                            }
                        };

                        if let Some(full_ref_name) = reference.name() {
                            let prefix_to_strip = format!("{}/", pattern_base);
                            if let Some(suffix) = full_ref_name.strip_prefix(&prefix_to_strip)
                                && let Some(sanitized_did) = suffix.strip_suffix("/signatures")
                            {
                                log::trace!(
                                    "Found potential sanitized DID: {} from ref {}",
                                    sanitized_did,
                                    full_ref_name
                                );
                                discovered_dids.insert(DeviceDID::new_unchecked(sanitized_did));
                            }
                        }
                    }
                }
                Err(e) => {
                    log::warn!(
                        "Failed to execute references_glob for pattern '{}': {}",
                        glob_pattern,
                        e
                    );
                }
            }
        }
        log::debug!(
            "Discovery finished, found {} unique sanitized DID refs.",
            discovered_dids.len()
        );
        Ok(discovered_dids.into_iter().collect())
    }
}
