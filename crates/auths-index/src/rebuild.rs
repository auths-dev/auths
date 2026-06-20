use crate::error::{IndexError, Result};
use crate::index::{AttestationIndex, IndexedAttestation};
use auths_verifier::core::{CommitOid, ResourceId};
use auths_verifier::types::{CanonicalDid, IdentityDID};
use chrono::Utc;
use git2::Repository;
use std::path::Path;

/// Default attestation ref prefix to scan during rebuild. Subject-type-neutral:
/// attestations are keyed by their subject DID, whatever kind of DID that is.
pub const DEFAULT_ATTESTATION_PREFIX: &str = "refs/auths/attestations/nodes";

/// The deprecated pre-multi-device attestation prefix. Repos carrying
/// refs under this namespace were never shipped to end users; the
/// rebuild path hard-breaks instead of silently returning zero indexed
/// refs (which would look like a clean index to the caller).
pub const DEPRECATED_ATTESTATION_PREFIX: &str = "refs/auths/devices/nodes";

/// Guidance message returned when a rebuild encounters the deprecated
/// prefix. Pinned so the test asserting the exact text stays in sync.
pub const DEPRECATED_PREFIX_GUIDANCE: &str = "\
auths-index: repository holds refs under the deprecated prefix \
'refs/auths/devices/nodes/*' (pre-multi-device-identity layout). \
Reset with `rm -rf ~/.auths && auths init` and re-pair your devices. \
Pre-launch posture: no automatic migration is provided.";

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

    // Hard-break on the deprecated pre-multi-device-identity layout.
    // Pre-launch we never ship a silent migration; tell the user to reset.
    {
        let refs_scan = repo.references()?;
        for reference in refs_scan.filter_map(|r| r.ok()) {
            if let Ok(name) = reference.name()
                && name.starts_with(DEPRECATED_ATTESTATION_PREFIX)
            {
                return Err(IndexError::DeprecatedPrefix(
                    DEPRECATED_PREFIX_GUIDANCE.to_string(),
                ));
            }
        }
    }

    // Clear existing index before rebuild
    index.clear()?;

    // Iterate all refs matching the prefix pattern
    let refs = repo.references()?;

    for reference in refs.filter_map(|r| r.ok()) {
        let name = match reference.name() {
            Ok(name) => name,
            Err(_) => continue,
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

    let issuer_did = IdentityDID::parse(&issuer_did)?;
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

    #[test]
    fn deprecated_prefix_rebuild_hard_breaks() {
        // Seed a bare repo with a ref under the deprecated prefix and
        // assert the rebuilder returns DeprecatedPrefix with the pinned
        // guidance text.
        let tmp = tempfile::tempdir().expect("tempdir");
        let repo = Repository::init_bare(tmp.path()).expect("init_bare");
        // Write a throwaway blob + tree and point a ref at it so git2
        // surfaces the ref during iteration.
        let blob = repo.blob(b"legacy marker").expect("blob");
        let mut builder = repo.treebuilder(None).expect("treebuilder");
        builder.insert("marker", blob, 0o100644).expect("insert");
        let tree = builder.write().expect("write tree");
        let tree_obj = repo.find_tree(tree).expect("find tree");
        let sig = git2::Signature::now("test", "test@example.com").expect("sig");
        let commit_oid = repo
            .commit(None, &sig, &sig, "legacy", &tree_obj, &[])
            .expect("commit");
        let ref_name = format!("{}/legacy/signatures", DEPRECATED_ATTESTATION_PREFIX);
        repo.reference(&ref_name, commit_oid, true, "test")
            .expect("ref");

        let index = AttestationIndex::in_memory().expect("open index");
        let err = rebuild_attestations_from_git(
            &index,
            tmp.path(),
            DEFAULT_ATTESTATION_PREFIX,
            "attestation.json",
        )
        .expect_err("should hard-break on legacy prefix");
        match err {
            IndexError::DeprecatedPrefix(msg) => {
                assert_eq!(msg, DEPRECATED_PREFIX_GUIDANCE);
            }
            other => panic!("expected DeprecatedPrefix, got {other:?}"),
        }
    }

    fn seed_attestation_ref(repo: &Repository, leaf: &str, attestation_json: &[u8]) {
        let blob = repo.blob(attestation_json).expect("blob");
        let mut builder = repo.treebuilder(None).expect("treebuilder");
        builder
            .insert("attestation.json", blob, 0o100644)
            .expect("insert");
        let tree = builder.write().expect("write tree");
        let tree_obj = repo.find_tree(tree).expect("find tree");
        let sig = git2::Signature::now("test", "test@example.com").expect("sig");
        let commit_oid = repo
            .commit(None, &sig, &sig, "attestation", &tree_obj, &[])
            .expect("commit");
        let ref_name = format!("{}/{}/signatures", DEFAULT_ATTESTATION_PREFIX, leaf);
        repo.reference(&ref_name, commit_oid, true, "test")
            .expect("ref");
    }

    #[test]
    fn malformed_issuer_did_is_skipped_fail_closed() {
        // An attestation whose issuer is not a did:keri: identity must not
        // be indexed; the rebuild counts it as an error and indexes nothing.
        let tmp = tempfile::tempdir().expect("tempdir");
        let repo = Repository::init_bare(tmp.path()).expect("init_bare");
        let attestation = br#"{
            "rid": "rid1",
            "issuer": "not-a-did",
            "subject": "did:key:z6MkDevice1"
        }"#;
        seed_attestation_ref(&repo, "device1", attestation);

        let index = AttestationIndex::in_memory().expect("open index");
        let stats = rebuild_attestations_from_git(
            &index,
            tmp.path(),
            DEFAULT_ATTESTATION_PREFIX,
            "attestation.json",
        )
        .expect("rebuild should complete and skip the bad ref");

        assert_eq!(stats.refs_scanned, 1);
        assert_eq!(stats.attestations_indexed, 0);
        assert_eq!(stats.errors, 1);
        assert_eq!(index.count().expect("count"), 0);
    }
}
