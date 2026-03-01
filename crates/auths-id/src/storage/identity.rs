use anyhow::{Context, Error, Result, anyhow};
use git2::{ErrorCode, Repository, Signature};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::str;

use crate::identity::helpers::ManagedIdentity;
use crate::storage::layout::{StorageLayoutConfig, identity_blob_name, identity_ref};
use auths_core::storage::keychain::IdentityDID;

/// Internal structure for serializing/deserializing identity data to/from JSON.
///
/// This structure defines the minimal data stored in the identity blob.
/// The `metadata` field is intended to hold arbitrary JSON defined by the
/// consumer/application, allowing flexibility for different identity standards
/// (like Radicle's `xyz.radicle.agent` payload or other custom schemas).
#[derive(Serialize, Deserialize, Debug)]
struct StoredIdentityData {
    /// Version number for the stored data format.
    version: u32,
    /// The Decentralized Identifier (DID) string that controls this identity.
    controller_did: String,
    /// Optional, arbitrary JSON metadata associated with the identity.
    /// Consumers are responsible for defining and interpreting the structure
    /// within this field (e.g., storing profile information, specific payload keys
    /// like `xyz.radicle.agent`, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<serde_json::Value>,
}

/// Trait for abstracting the storage and retrieval of identity information.
///
/// Implementations handle the underlying storage mechanism (e.g., Git repository)
/// and use a `StorageLayoutConfig` to determine specific paths and filenames.
pub trait IdentityStorage {
    /// Creates or updates the identity reference (defined in config) with the
    /// controller DID and optional, arbitrary metadata.
    ///
    /// The structure and interpretation of the `metadata` JSON is the responsibility
    /// of the caller. This function stores the provided `controller_did` and `metadata`
    /// generically in a blob (name defined in config).
    ///
    /// # Arguments
    /// * `controller_did`: The DID string controlling this identity.
    /// * `metadata`: Optional arbitrary JSON value representing identity metadata.
    fn create_identity(
        &self,
        controller_did: &str,
        metadata: Option<serde_json::Value>,
    ) -> Result<(), Error>;

    /// Loads the identity information (controller DID, metadata, storage ID)
    /// from the configured identity reference and blob name.
    ///
    /// Returns a `ManagedIdentity` struct containing the loaded `controller_did`,
    /// the storage identifier (e.g., repository name), and the full `metadata`
    /// field as a `serde_json::Value` for the caller to interpret.
    fn load_identity(&self) -> Result<ManagedIdentity, Error>;

    /// Gets the configured primary Git reference used for storing the identity commit.
    fn get_identity_ref(&self) -> Result<String, Error>;

    // Optional: Add a method to get the config if needed externally
    // fn config(&self) -> &StorageLayoutConfig;
}

/// An implementation of `IdentityStorage` that uses a Git repository
/// with a configurable reference and blob name layout defined by `StorageLayoutConfig`.
#[derive(Debug, Clone)]
pub struct GitIdentityStorage {
    repo_path: PathBuf,
    config: StorageLayoutConfig, // Store the layout configuration
}

impl GitIdentityStorage {
    /// Creates a new `GitIdentityStorage` instance for the given repository path
    /// using the specified layout configuration.
    ///
    /// This is the primary constructor allowing custom Git layouts.
    pub fn new(repo_path: impl Into<PathBuf>, config: StorageLayoutConfig) -> Self {
        GitIdentityStorage {
            repo_path: repo_path.into(),
            config, // Store the provided config
        }
    }

    /// Creates a new `GitIdentityStorage` instance using the *generic default*
    /// layout configuration defined in `StorageLayoutConfig::default()`.
    ///
    /// Use `::new()` to provide a custom layout (e.g., for Radicle compatibility).
    pub fn new_with_defaults(repo_path: impl Into<PathBuf>) -> Self {
        Self::new(repo_path, StorageLayoutConfig::default())
    }

    /// Helper to open the associated git repository.
    fn open_repo(&self) -> Result<Repository> {
        Repository::open(&self.repo_path)
            .with_context(|| format!("Failed to open repository at {:?}", self.repo_path))
    }

    /// Helper function to get the storage ID (typically the repository directory name).
    /// This is used as a local identifier for the storage backend.
    fn get_storage_id(&self) -> String {
        self.repo_path
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            // Fallback to full path string if filename is not available (e.g., "/")
            .unwrap_or_else(|| self.repo_path.to_string_lossy().to_string())
    }
}

impl IdentityStorage for GitIdentityStorage {
    /// Creates or updates the identity commit in the Git repository.
    ///
    /// Uses the `identity_ref` and `identity_blob_name` from the stored `config`.
    /// Serializes the provided `controller_did` and arbitrary `metadata` into the
    /// blob using the internal `StoredIdentityData` structure.
    fn create_identity(
        &self,
        controller_did: &str,
        metadata: Option<serde_json::Value>,
    ) -> Result<()> {
        let repo = self.open_repo()?;

        // Get paths/names from config
        let identity_ref_name = identity_ref(&self.config);
        let identity_blob_filename = identity_blob_name(&self.config);

        // Prepare data and Git objects (blob, tree)
        let stored_data = StoredIdentityData {
            version: 1,
            controller_did: controller_did.to_string(),
            metadata,
        };
        let json_bytes = serde_json::to_vec_pretty(&stored_data)
            .context("Failed to serialize identity data to JSON")?;
        let blob_oid = repo
            .blob(&json_bytes)
            .context("Failed to write identity JSON blob")?;
        let mut tree_builder = repo.treebuilder(None)?;
        tree_builder.insert(identity_blob_filename, blob_oid, 0o100644)?;
        let tree_oid = tree_builder.write()?;
        let tree = repo.find_tree(tree_oid)?;

        // Get signature
        let sig = repo
            .signature()
            .or_else(|_| Signature::now("auths", "auths@localhost"))
            .context("Failed to create Git signature")?;

        // Find parent commit(s) by resolving the *target reference name*
        let mut parent_commits = Vec::new();
        match repo.find_reference(identity_ref_name) {
            Ok(reference) => {
                // If ref exists, try to peel it to a commit to use as parent
                match reference.peel_to_commit() {
                    Ok(commit) => {
                        log::debug!(
                            "Found existing commit {} for ref '{}'. Using as parent.",
                            commit.id(),
                            identity_ref_name
                        );
                        parent_commits.push(commit);
                    }
                    Err(e)
                        if e.code() == ErrorCode::Peel
                            || e.code() == ErrorCode::NotFound
                            || e.code() == ErrorCode::InvalidSpec =>
                    {
                        // Ref exists but doesn't point to a valid commit (e.g., symbolic, broken, unborn)
                        // Treat as initial commit for this ref (no parent)
                        log::warn!(
                            "Ref '{}' exists but doesn't point to a valid commit ({:?}). Creating commit without parent.",
                            identity_ref_name,
                            e.code()
                        );
                    }
                    Err(e) => {
                        // Other error peeling the reference
                        return Err(e).with_context(|| {
                            format!(
                                "Failed to peel existing reference '{}' to commit",
                                identity_ref_name
                            )
                        });
                    }
                }
            }
            Err(e) if e.code() == ErrorCode::NotFound => {
                log::debug!(
                    "Reference '{}' not found. Creating initial commit.",
                    identity_ref_name
                );
            }
            Err(e) => {
                // Other error finding the reference
                return Err(e)
                    .with_context(|| format!("Failed to find reference '{}'", identity_ref_name));
            }
        }

        let parents_refs: Vec<&git2::Commit> = parent_commits.iter().collect();
        let commit_msg = if parents_refs.is_empty() {
            format!("Create Identity ({})", identity_ref_name)
        } else {
            format!("Update Identity ({})", identity_ref_name)
        };

        // --- Create the commit ---
        // Set update_ref to None. This will usually update HEAD.
        let commit_oid = repo
            .commit(
                None,          // Don't update the target ref directly here
                &sig,          // author
                &sig,          // committer
                &commit_msg,   // Use specific commit message
                &tree,         // tree
                &parents_refs, // parents slice
            )
            .with_context(|| "Failed to create identity commit object".to_string())?;

        log::debug!("Created commit {}", commit_oid);

        // --- Explicitly create or update the target reference ---
        // Use force=true to overwrite if the reference already exists.
        let ref_log_message = format!("commit: {}", commit_msg);
        repo.reference(identity_ref_name, commit_oid, true, &ref_log_message)
            .with_context(|| {
                format!(
                    "Failed to create/update reference '{}' to point to commit {}",
                    identity_ref_name, commit_oid
                )
            })?;

        log::debug!(
            "Updated reference '{}' to commit {}",
            identity_ref_name,
            commit_oid
        );

        Ok(())
    }

    /// Loads the identity using the configured ref name and blob name.
    // (load_identity function remains the same as before)
    fn load_identity(&self) -> Result<ManagedIdentity> {
        let repo = self.open_repo()?;
        let storage_id = self.get_storage_id(); // Get the RID

        // Use the config to get ref and blob names
        let identity_ref_name = identity_ref(&self.config);
        let identity_blob_filename = identity_blob_name(&self.config);

        // Find the commit pointed to by the configured identity ref
        let commit = repo
            .find_reference(identity_ref_name)
            .with_context(|| {
                format!(
                    "Identity reference '{}' not found in repo {:?}",
                    identity_ref_name, self.repo_path
                )
            })?
            .resolve()? // Resolve symbolic refs if any
            .peel_to_commit()
            .with_context(|| {
                format!("Failed to peel reference '{}' to commit", identity_ref_name)
            })?;

        let tree = commit.tree()?;

        // Find the blob using the configured name within the commit's tree
        let blob_entry = tree.get_name(identity_blob_filename).ok_or_else(|| {
            anyhow!(
                "Commit {} missing blob named '{}' for identity ref '{}'",
                commit.id(),
                identity_blob_filename,
                identity_ref_name
            )
        })?;

        let blob = repo.find_blob(blob_entry.id())?;

        // Deserialize the blob content into our internal generic struct
        let stored_data: StoredIdentityData =
            serde_json::from_slice(blob.content()).with_context(|| {
                format!(
                    "Failed to deserialize identity data from blob {}",
                    blob.id()
                )
            })?;

        // Construct and return the ManagedIdentity, including the opaque metadata
        Ok(ManagedIdentity {
            controller_did: IdentityDID::new_unchecked(stored_data.controller_did),
            storage_id,
            metadata: stored_data.metadata,
            // storage_revision: Some(commit.id().to_string()), // Optionally include revision
        })
    }

    /// Returns the configured primary Git reference used for storing the identity commit.
    // (get_identity_ref function remains the same as before)
    fn get_identity_ref(&self) -> Result<String> {
        Ok(identity_ref(&self.config).to_string())
    }
}
