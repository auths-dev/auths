use crate::error::StorageError;
use crate::storage::layout;
use git2::{Oid, Repository};
use serde_json::from_slice;

use auths_verifier::core::Attestation;

pub fn load_attestations_by_prefix(
    repo: &Repository,
    ref_prefix: &str,
) -> Result<Vec<Attestation>, StorageError> {
    let mut result = Vec::new();

    let refs = repo.references()?;

    for reference in refs.filter_map(Result::ok) {
        let name = match reference.name() {
            Some(name) => name,
            None => continue,
        };

        if name.starts_with(ref_prefix) {
            log::debug!("Found matching ref: {name}");

            match reference.peel_to_commit() {
                Ok(commit) => {
                    let oid = commit.id();
                    log::trace!("Peeled commit OID: {oid}");

                    match load_attestation_from_commit(repo, oid) {
                        Ok(att) => {
                            log::trace!("Parsed attestation from {oid}");
                            result.push(att);
                        }
                        Err(err) => {
                            log::warn!("Failed to parse attestation from {oid}: {err:#}");
                        }
                    }
                }
                Err(err) => {
                    log::warn!("Could not peel ref to commit: {err:#}");
                }
            }
        }
    }

    Ok(result)
}

/// Loads a single attestation from a commit SHA.
///
/// The commit should contain a tree with a single file, e.g. `attestation.json`.
pub fn load_attestation_from_commit(
    repo: &Repository,
    oid: Oid,
) -> Result<Attestation, StorageError> {
    let commit = repo.find_commit(oid)?;
    let tree = commit.tree()?;

    let entry = tree
        .get_name(layout::ATTESTATION_JSON)
        .ok_or_else(|| StorageError::NotFound("Attestation tree missing entry".into()))?;

    let blob = repo.find_blob(entry.id())?;
    let attestation: Attestation = from_slice(blob.content())?;

    Ok(attestation)
}
