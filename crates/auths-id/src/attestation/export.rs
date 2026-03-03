use crate::attestation::encoders::json_encoder;
use crate::error::StorageError;
use crate::storage::layout::{
    StorageLayoutConfig, attestation_blob_name, attestation_ref_for_device,
};
use auths_verifier::core::{Attestation, VerifiedAttestation};
use git2::{Repository, Signature, Tree};
use log::{debug, info};
use std::path::PathBuf;
use std::sync::Arc;

/// Function signature for encoding an attestation into bytes.
pub type AttestationEncoder = Arc<dyn Fn(&Attestation) -> Result<Vec<u8>, StorageError> + Send + Sync>;

/// Trait for destinations that can accept and store an attestation.
pub trait AttestationSink {
    /// Export/Save a verified attestation to the configured destination.
    ///
    /// Accepts a [`VerifiedAttestation`] to enforce at the type level that
    /// signatures were checked before storage.
    fn export(&self, attestation: &VerifiedAttestation) -> Result<(), StorageError>;

    /// Update any secondary index after an attestation mutation.
    ///
    /// The default implementation is a no-op. Adapters backed by a searchable
    /// index (e.g. SQLite) override this to keep their index consistent.
    /// Callers invoke this unconditionally after every mutation — no feature
    /// flags are needed in orchestration code.
    fn sync_index(&self, _attestation: &Attestation) {}
}

/// Exports attestations as JSON commits under a Git reference specific to the device,
/// using a configurable layout defined by `StorageLayoutConfig`.
#[derive(Clone)]
pub struct GitRefSink {
    repo_path: PathBuf,
    encoder: AttestationEncoder,
    config: StorageLayoutConfig,
}

impl GitRefSink {
    /// Creates a new GitRefSink with specified path, encoder, and layout config.
    /// This is the primary constructor.
    pub fn new(
        repo_path: impl Into<PathBuf>,
        encoder: AttestationEncoder,
        config: StorageLayoutConfig,
    ) -> Self {
        Self {
            repo_path: repo_path.into(),
            encoder,
            config,
        }
    }

    /// Convenience constructor using the default JSON encoder and specified layout config.
    pub fn with_config(repo_path: impl Into<PathBuf>, config: StorageLayoutConfig) -> Self {
        Self::new(repo_path, Arc::new(json_encoder), config)
    }

    /// Convenience constructor using the default JSON encoder and the default layout config.
    pub fn with_defaults(repo_path: impl Into<PathBuf>) -> Self {
        Self::new(
            repo_path,
            Arc::new(json_encoder),
            StorageLayoutConfig::default(),
        )
    }

    // Removed: get_ref_path_for_attestation (logic moved inside export)

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
        Ok(serde_json::from_slice(blob.content())?)
    }
}

impl AttestationSink for GitRefSink {
    fn export(&self, attestation: &VerifiedAttestation) -> Result<(), StorageError> {
        let attestation = attestation.inner();
        info!(
            "Exporting attestation for device {} using configured layout...",
            attestation.subject
        );
        let repo = self.open_repo()?;

        // 1. Encode the attestation payload
        let content = (self.encoder)(attestation)?;

        // 2. Write the blob
        let blob_oid = repo.blob(&content)?;

        // 3. Create the tree using the configured blob name
        let blob_filename = attestation_blob_name(&self.config); // Use helper
        let mut tree_builder = repo.treebuilder(None)?;
        tree_builder.insert(blob_filename, blob_oid, 0o100644)?;
        let tree_oid = tree_builder.write()?;
        let tree = repo.find_tree(tree_oid)?;
        debug!(
            "Created tree {} with blob {} ('{}')",
            tree_oid, blob_oid, blob_filename
        );

        // 4. Determine the target ref path using the config
        let ref_path = attestation_ref_for_device(&self.config, &attestation.subject); // Use helper
        debug!("Target ref path for export: {}", ref_path);

        // 5. Find parent commit(s) on this specific ref
        let parent_commit = repo
            .find_reference(&ref_path)
            .ok()
            .and_then(|reference| reference.peel_to_commit().ok());
        let parents = parent_commit.iter().collect::<Vec<_>>();
        if let Some(p) = parent_commit.as_ref() {
            debug!("Found parent commit on ref '{}': {}", ref_path, p.id());
        } else {
            debug!(
                "No parent commit found for ref '{}', creating initial commit on this ref.",
                ref_path
            );
        }

        // 6. Create commit message
        let previous_attestation = parent_commit.as_ref().and_then(|p| {
            p.tree()
                .ok()
                .and_then(|t| self.read_attestation_from_tree(&repo, &t).ok()) // Log inside read helper if needed
        });
        let message = if attestation.is_revoked()
            && !previous_attestation
                .as_ref()
                .is_some_and(|pa| pa.is_revoked())
        {
            "🛑 Revoked device attestation"
        } else if previous_attestation.is_none() {
            "✅ Linked device attestation"
        } else if *attestation != *previous_attestation.as_ref().unwrap() {
            "🔄 Updated device attestation"
        } else {
            "📄 Updated device attestation record (no change detected)"
        };
        debug!("Commit message determined: '{}'", message);

        // 7. Get Git signature
        let author = repo
            .signature()
            .or_else(|_| Signature::now("auths", "auths@localhost"))?;
        debug!("Using Git author/committer: {}", author);

        // 8. Create the commit object
        let commit_oid = repo.commit(
            None,
            &author,
            &author,
            message,
            &tree,
            &parents,
        )?;

        debug!("Created attestation commit object {}", commit_oid);

        // 9. Explicitly create or update the target reference
        let ref_log_message = format!("commit (attestation): {}", message);
        repo.reference(&ref_path, commit_oid, true, &ref_log_message)?;

        info!(
            "Saved attestation commit {} and updated ref '{}'", // Updated log message
            commit_oid, ref_path
        );
        Ok(())
    }
}
