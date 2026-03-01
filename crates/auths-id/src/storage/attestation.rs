use crate::storage::layout::{
    StorageLayoutConfig, attestation_blob_name, attestation_ref_for_device,
    default_attestation_prefixes,
};
use anyhow::{Context, Error, Result, anyhow};
use auths_verifier::core::Attestation;
use auths_verifier::types::DeviceDID;
use git2::{ErrorCode, Repository, Tree};
use std::collections::HashSet;
use std::path::PathBuf;

/// Abstracts the source and loading of device attestations from the underlying storage.
///
/// Implementations may read from Git refs, SQLite indexes, packed registries, or
/// in-memory stores. Domain logic interacts with attestation data exclusively
/// through this trait without knowledge of the backing store.
///
/// Args:
/// * `device_did`: A `DeviceDID` identifying the device whose attestations to load.
///
/// Usage:
/// ```ignore
/// use auths_id::storage::attestation::AttestationSource;
///
/// fn count_device_attestations(source: &dyn AttestationSource, did: &DeviceDID) -> usize {
///     source.load_attestations_for_device(did)
///         .map(|atts| atts.len())
///         .unwrap_or(0)
/// }
/// ```
pub trait AttestationSource {
    /// Loads all attestations found for a specific device DID using the configured layout.
    fn load_attestations_for_device(
        &self,
        device_did: &DeviceDID,
    ) -> Result<Vec<Attestation>, Error>;

    /// Loads all known attestations from the storage backend by discovering devices
    /// based on the configured layout.
    fn load_all_attestations(&self) -> Result<Vec<Attestation>, Error>;

    /// Loads attestations for a bounded page of devices.
    ///
    /// Avoids loading the entire device set at once, which can stall
    /// the thread when thousands of devices exist. `limit` controls
    /// the maximum number of devices to process, and `offset` skips
    /// that many devices from the discovered list.
    ///
    /// Args:
    /// * `limit`: Maximum number of devices to load attestations for.
    /// * `offset`: Number of devices to skip before loading.
    ///
    /// Usage:
    /// ```ignore
    /// let page = storage.load_all_attestations_paginated(100, 0)?;
    /// ```
    fn load_all_attestations_paginated(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<Attestation>, Error> {
        let devices = self.discover_device_dids()?;
        let mut all_attestations = Vec::new();

        for device_did in devices.into_iter().skip(offset).take(limit) {
            match self.load_attestations_for_device(&device_did) {
                Ok(atts) => all_attestations.extend(atts),
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

    /// Discovers device DIDs that have attestations stored based on the configured layout.
    fn discover_device_dids(&self) -> Result<Vec<DeviceDID>, Error>;
}

/// An implementation of `AttestationSource` that uses a Git repository
/// with a configurable reference and blob name layout for attestations.
#[derive(Debug, Clone)]
pub struct GitAttestationStorage {
    repo_path: PathBuf,
    config: StorageLayoutConfig, // Store the layout configuration
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

    /// Helper to open the associated git repository.
    fn open_repo(&self) -> Result<Repository> {
        Repository::open(&self.repo_path)
            .with_context(|| format!("Failed to open repository at {:?}", self.repo_path))
    }

    /// Helper function to parse an Attestation from a Git commit's tree,
    /// using the blob name defined in the configuration.
    fn read_attestation_from_tree(&self, repo: &Repository, tree: &Tree) -> Result<Attestation> {
        // Get the expected blob name from the configuration
        let blob_filename = attestation_blob_name(&self.config);
        let entry = tree
            .get_name(blob_filename)
            .ok_or_else(|| anyhow!("Attestation tree missing blob named '{}'", blob_filename))?;

        let blob = repo.find_blob(entry.id())?;
        let att: Attestation = serde_json::from_slice(blob.content()).with_context(|| {
            format!("Failed to deserialize attestation from blob {}", blob.id())
        })?;

        Ok(att)
    }

    /// Helper to walk the Git history of a specific ref and load attestations
    /// from each commit's tree using `read_attestation_from_tree`.
    fn load_history(&self, repo: &Repository, ref_name: &str) -> Result<Vec<Attestation>> {
        let mut attestations = Vec::new();
        // Find the starting reference
        let reference = match repo.find_reference(ref_name) {
            Ok(r) => r,
            // If ref not found, it simply has no history (empty vec)
            Err(e) if e.code() == ErrorCode::NotFound => return Ok(attestations),
            Err(e) => {
                return Err(e).with_context(|| format!("Failed to find reference '{}'", ref_name));
            }
        };

        // Peel ref to the commit it points to
        let mut commit = reference
            .peel_to_commit()
            .with_context(|| format!("Failed to peel reference '{}' to commit", ref_name))?;

        // Walk backwards from the tip commit through the first parent line
        loop {
            match commit.tree() {
                Ok(tree) => {
                    // Attempt to read attestation using the config-aware helper
                    match self.read_attestation_from_tree(repo, &tree) {
                        Ok(att) => attestations.push(att),
                        Err(e) => log::warn!(
                            "Failed to read attestation from commit {}: {}",
                            commit.id(),
                            e
                        ),
                    }
                }
                Err(e) => log::warn!("Failed to get tree for commit {}: {}", commit.id(), e),
            }

            // Move to the first parent commit
            if commit.parent_count() > 0 {
                match commit.parent(0) {
                    Ok(parent) => commit = parent,
                    Err(e) => {
                        log::warn!(
                            "Failed to get parent commit for {}: {}. Stopping history walk.",
                            commit.id(),
                            e
                        );
                        break; // Stop walking if parent is inaccessible
                    }
                }
            } else {
                break; // Reached the root commit for this ref's history
            }
        }
        // History was loaded newest-to-oldest, reverse for chronological order
        attestations.reverse();
        Ok(attestations)
    }
}

impl AttestationSource for GitAttestationStorage {
    /// Loads attestations by reading the history of the specific device's attestation ref,
    /// determined by the stored configuration.
    fn load_attestations_for_device(
        &self,
        device_did: &DeviceDID,
    ) -> Result<Vec<Attestation>, Error> {
        let repo = self.open_repo()?;
        // Generate the correct ref path using the stored config and the layout helper
        let sig_ref = attestation_ref_for_device(&self.config, device_did);
        log::debug!(
            "Loading attestation history for device {} from ref '{}'",
            device_did,
            sig_ref
        );
        self.load_history(&repo, &sig_ref)
    }

    fn load_all_attestations(&self) -> Result<Vec<Attestation>, Error> {
        self.load_all_attestations_paginated(usize::MAX, 0)
    }

    fn load_all_attestations_paginated(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<Attestation>, Error> {
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

    /// Discovers device DIDs by globbing known attestation ref patterns based on the
    /// stored configuration.
    fn discover_device_dids(&self) -> Result<Vec<DeviceDID>, Error> {
        let repo = self.open_repo()?;
        let mut discovered_dids = HashSet::new(); // Use HashSet to avoid duplicates
        // Get the base pattern(s) to search from the configuration
        let patterns = default_attestation_prefixes(&self.config);
        log::debug!("Discovering device DIDs using patterns: {:?}", patterns);

        for pattern_base in patterns {
            // Construct the glob pattern (e.g., "refs/auths/devices/nodes/*/signatures")
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
                                continue; // Skip this problematic ref
                            }
                        };

                        if let Some(full_ref_name) = reference.name() {
                            // Extract the potential sanitized DID part from the path
                            // Example: refs/auths/devices/nodes/<sanitized_did>/signatures
                            let prefix_to_strip = format!("{}/", pattern_base);
                            if let Some(suffix) = full_ref_name.strip_prefix(&prefix_to_strip)
                                && let Some(sanitized_did) = suffix.strip_suffix("/signatures")
                            {
                                log::trace!(
                                    "Found potential sanitized DID: {} from ref {}",
                                    sanitized_did,
                                    full_ref_name
                                );
                                // As noted before, this discovery only finds the ref name component.
                                // The actual DID must be retrieved by loading the attestation.
                                // We insert the *sanitized* name wrapped in DeviceDID.
                                discovered_dids.insert(DeviceDID::new(sanitized_did));
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
