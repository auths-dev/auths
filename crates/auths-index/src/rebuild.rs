use crate::error::Result;
use crate::index::{AttestationIndex, IndexedAttestation};
use auths_verifier::core::{CommitOid, ResourceId};
use auths_verifier::types::{CanonicalDid, IdentityDID};
use chrono::Utc;
use git2::Repository;
use std::path::Path;

/// Default attestation ref prefix to scan during rebuild.
pub const DEFAULT_ATTESTATION_PREFIX: &str = "refs/auths/devices/nodes";

/// Rebuilds the attestation index from Git refs.
///
/// This function scans all Git refs matching the attestation prefix pattern
/// and populates the index with metadata extracted from each attestation.
pub fn rebuild_attestations_from_git(
    index: &AttestationIndex,
    repo_path: &Path,
    attestation_prefix: &str,
    attestation_blob_name: &str,
) -> Result<RebuildStats> {
    let repo = Repository::open(repo_path)?;
    let mut stats = RebuildStats::default();

    // Clear existing index before rebuild
    index.clear()?;

    // Iterate all refs matching the prefix pattern
    let refs = repo.references()?;

    for reference in refs.filter_map(|r| r.ok()) {
        let name = match reference.name() {
            Some(name) => name,
            None => continue,
        };

        // Check if this ref matches our attestation pattern
        if !name.starts_with(attestation_prefix) {
            continue;
        }

        stats.refs_scanned += 1;

        // Try to extract attestation from this ref
        match extract_attestation_from_ref(&repo, name, attestation_blob_name) {
            Ok(indexed) => {
                index.upsert_attestation(&indexed)?;
                stats.attestations_indexed += 1;
                log::debug!("Indexed attestation from ref: {}", name);
            }
            Err(e) => {
                log::warn!("Failed to extract attestation from ref {}: {}", name, e);
                stats.errors += 1;
            }
        }
    }

    Ok(stats)
}

/// Extracts attestation metadata from a Git ref.
fn extract_attestation_from_ref(
    repo: &Repository,
    ref_name: &str,
    blob_name: &str,
) -> Result<IndexedAttestation> {
    let reference = repo.find_reference(ref_name)?;
    let commit = reference.peel_to_commit()?;
    let tree = commit.tree()?;

    let entry = tree.get_name(blob_name).ok_or_else(|| {
        crate::error::IndexError::InvalidData(format!(
            "Attestation tree missing blob named '{}'",
            blob_name
        ))
    })?;

    let blob = repo.find_blob(entry.id())?;
    let content = blob.content();

    // Parse the attestation JSON to extract metadata
    let att: serde_json::Value = serde_json::from_slice(content)?;

    let rid = att
        .get("rid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| crate::error::IndexError::InvalidData("Missing rid field".to_string()))?
        .to_string();

    let issuer_did = att
        .get("issuer")
        .and_then(|v| v.as_str())
        .ok_or_else(|| crate::error::IndexError::InvalidData("Missing issuer field".to_string()))?
        .to_string();

    let device_did = att
        .get("subject")
        .and_then(|v| v.as_str())
        .ok_or_else(|| crate::error::IndexError::InvalidData("Missing subject field".to_string()))?
        .to_string();

    let revoked_at = att
        .get("revoked_at")
        .and_then(|v| v.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc));

    let expires_at = att
        .get("expires_at")
        .and_then(|v| v.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc));

    let updated_at = att
        .get("timestamp")
        .and_then(|v| v.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(Utc::now);

    #[allow(clippy::disallowed_methods)]
    // INVARIANT: issuer_did extracted from attestation JSON stored in a signed Git commit
    let issuer_did = IdentityDID::new_unchecked(&issuer_did);
    #[allow(clippy::disallowed_methods)]
    // INVARIANT: device_did extracted from attestation JSON stored in a signed Git commit
    let device_did = CanonicalDid::new_unchecked(&device_did);

    Ok(IndexedAttestation {
        rid: ResourceId::new(rid),
        issuer_did,
        device_did,
        git_ref: ref_name.to_string(),
        commit_oid: CommitOid::parse(&commit.id().to_string()).ok(),
        revoked_at,
        expires_at,
        updated_at,
    })
}

/// Statistics from a rebuild operation.
#[derive(Debug, Default)]
pub struct RebuildStats {
    /// Number of Git refs scanned
    pub refs_scanned: usize,
    /// Number of attestations successfully indexed
    pub attestations_indexed: usize,
    /// Number of errors encountered
    pub errors: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rebuild_stats_default() {
        let stats = RebuildStats::default();
        assert_eq!(stats.refs_scanned, 0);
        assert_eq!(stats.attestations_indexed, 0);
        assert_eq!(stats.errors, 0);
    }
}
