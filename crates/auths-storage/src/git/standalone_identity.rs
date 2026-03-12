use auths_core::storage::keychain::IdentityDID;
use auths_id::error::StorageError;
use auths_id::identity::managed::ManagedIdentity;
use auths_id::storage::identity::IdentityStorage;
use auths_id::storage::layout::{StorageLayoutConfig, identity_blob_name, identity_ref};
use git2::{ErrorCode, Repository, Signature};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::str;

/// Internal structure for serializing/deserializing identity data to/from JSON.
#[derive(Serialize, Deserialize, Debug)]
struct StoredIdentityData {
    version: u32,
    controller_did: IdentityDID,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<serde_json::Value>,
}

/// An implementation of `IdentityStorage` that uses a Git repository
/// with a configurable reference and blob name layout defined by `StorageLayoutConfig`.
#[derive(Debug, Clone)]
pub struct GitIdentityStorage {
    repo_path: PathBuf,
    config: StorageLayoutConfig,
}

impl GitIdentityStorage {
    /// Creates a new `GitIdentityStorage` instance for the given repository path
    /// using the specified layout configuration.
    pub fn new(repo_path: impl Into<PathBuf>, config: StorageLayoutConfig) -> Self {
        GitIdentityStorage {
            repo_path: repo_path.into(),
            config,
        }
    }

    /// Creates a new `GitIdentityStorage` instance using the *generic default*
    /// layout configuration defined in `StorageLayoutConfig::default()`.
    pub fn new_with_defaults(repo_path: impl Into<PathBuf>) -> Self {
        Self::new(repo_path, StorageLayoutConfig::default())
    }

    fn open_repo(&self) -> Result<Repository, StorageError> {
        Ok(Repository::open(&self.repo_path)?)
    }

    fn get_storage_id(&self) -> String {
        self.repo_path
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| self.repo_path.to_string_lossy().to_string())
    }
}

impl IdentityStorage for GitIdentityStorage {
    fn create_identity(
        &self,
        controller_did: &str,
        metadata: Option<serde_json::Value>,
    ) -> Result<(), StorageError> {
        let repo = self.open_repo()?;

        let identity_ref_name = identity_ref(&self.config);
        let identity_blob_filename = identity_blob_name(&self.config);

        #[allow(clippy::disallowed_methods)]
        // INVARIANT: controller_did is a validated DID string from the caller (SDK layer)
        let controller_did = IdentityDID::new_unchecked(controller_did);
        let stored_data = StoredIdentityData {
            version: 1,
            controller_did,
            metadata,
        };
        let json_bytes = serde_json::to_vec_pretty(&stored_data)?;
        let blob_oid = repo.blob(&json_bytes)?;
        let mut tree_builder = repo.treebuilder(None)?;
        tree_builder.insert(identity_blob_filename, blob_oid, 0o100644)?;
        let tree_oid = tree_builder.write()?;
        let tree = repo.find_tree(tree_oid)?;

        #[allow(clippy::disallowed_methods)]
        let now = chrono::Utc::now();
        let sig = repo.signature().or_else(|_| {
            Signature::new(
                "auths",
                "auths@localhost",
                &git2::Time::new(now.timestamp(), 0),
            )
        })?;

        let mut parent_commits = Vec::new();
        match repo.find_reference(identity_ref_name) {
            Ok(reference) => match reference.peel_to_commit() {
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
                    log::warn!(
                        "Ref '{}' exists but doesn't point to a valid commit ({:?}). Creating commit without parent.",
                        identity_ref_name,
                        e.code()
                    );
                }
                Err(e) => return Err(e.into()),
            },
            Err(e) if e.code() == ErrorCode::NotFound => {
                log::debug!(
                    "Reference '{}' not found. Creating initial commit.",
                    identity_ref_name
                );
            }
            Err(e) => return Err(e.into()),
        }

        let parents_refs: Vec<&git2::Commit> = parent_commits.iter().collect();
        let commit_msg = if parents_refs.is_empty() {
            format!("Create Identity ({})", identity_ref_name)
        } else {
            format!("Update Identity ({})", identity_ref_name)
        };

        let commit_oid = repo.commit(None, &sig, &sig, &commit_msg, &tree, &parents_refs)?;

        log::debug!("Created commit {}", commit_oid);

        let ref_log_message = format!("commit: {}", commit_msg);
        repo.reference(identity_ref_name, commit_oid, true, &ref_log_message)?;

        log::debug!(
            "Updated reference '{}' to commit {}",
            identity_ref_name,
            commit_oid
        );

        Ok(())
    }

    fn load_identity(&self) -> Result<ManagedIdentity, StorageError> {
        let repo = self.open_repo()?;
        let storage_id = self.get_storage_id();

        let identity_ref_name = identity_ref(&self.config);
        let identity_blob_filename = identity_blob_name(&self.config);

        let commit = repo
            .find_reference(identity_ref_name)?
            .resolve()?
            .peel_to_commit()?;

        let tree = commit.tree()?;

        let blob_entry = tree.get_name(identity_blob_filename).ok_or_else(|| {
            StorageError::NotFound(format!(
                "Commit {} missing blob named '{}' for identity ref '{}'",
                commit.id(),
                identity_blob_filename,
                identity_ref_name
            ))
        })?;

        let blob = repo.find_blob(blob_entry.id())?;

        let stored_data: StoredIdentityData = serde_json::from_slice(blob.content())?;

        Ok(ManagedIdentity {
            controller_did: stored_data.controller_did,
            storage_id,
            metadata: stored_data.metadata,
        })
    }

    fn get_identity_ref(&self) -> Result<String, StorageError> {
        Ok(identity_ref(&self.config).to_string())
    }
}
