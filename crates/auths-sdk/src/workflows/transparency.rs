//! SDK transparency verification workflows.

use std::path::Path;

use auths_transparency::{
    BundleVerificationReport, ConsistencyProof, OfflineBundle, SignedCheckpoint, TrustRoot,
};
use chrono::{DateTime, Utc};
use thiserror::Error;

/// Errors from transparency verification workflows.
#[derive(Debug, Error)]
pub enum TransparencyWorkflowError {
    /// Bundle verification found issues.
    #[error("bundle verification found issues")]
    VerificationFailed(Box<BundleVerificationReport>),

    /// Checkpoint consistency check failed.
    #[error("checkpoint inconsistent: {0}")]
    CheckpointInconsistent(String),

    /// Cache I/O error.
    #[error("cache I/O error: {0}")]
    CacheError(#[source] std::io::Error),

    /// JSON deserialization error.
    #[error("deserialization error: {0}")]
    DeserializationError(String),
}

/// Configuration for bundle verification.
pub struct BundleVerifyConfig {
    /// The offline bundle serialized as JSON.
    pub bundle_json: String,
    /// The trust root serialized as JSON.
    pub trust_root_json: String,
}

/// Result of a consistency check between cached and new checkpoints.
pub struct ConsistencyReport {
    /// Tree size of the previously cached checkpoint (0 if none).
    pub old_size: u64,
    /// Tree size of the newly cached checkpoint.
    pub new_size: u64,
    /// Whether consistency was verified.
    pub consistent: bool,
}

/// Verify an offline transparency bundle.
///
/// Deserializes the bundle and trust root from JSON, delegates to
/// `auths_transparency::verify_bundle`, and returns the report.
/// Returns `Err(VerificationFailed)` when the bundle does not pass
/// all verification checks.
///
/// Args:
/// * `config` — Bundle and trust root JSON strings.
/// * `now` — Injected wall-clock time.
///
/// Usage:
/// ```ignore
/// let report = verify_artifact_bundle(&config, now)?;
/// ```
pub fn verify_artifact_bundle(
    config: &BundleVerifyConfig,
    now: DateTime<Utc>,
) -> Result<BundleVerificationReport, TransparencyWorkflowError> {
    let bundle: OfflineBundle = serde_json::from_str(&config.bundle_json)
        .map_err(|e| TransparencyWorkflowError::DeserializationError(e.to_string()))?;
    let trust_root: TrustRoot = serde_json::from_str(&config.trust_root_json)
        .map_err(|e| TransparencyWorkflowError::DeserializationError(e.to_string()))?;

    let report = auths_transparency::verify_bundle(&bundle, &trust_root, now);

    if !report.is_valid() {
        return Err(TransparencyWorkflowError::VerificationFailed(Box::new(
            report,
        )));
    }

    Ok(report)
}

/// Update the local checkpoint cache after verifying consistency.
///
/// Loads the cached checkpoint from disk, verifies that the new checkpoint
/// is a consistent append-only extension of the cached one, and writes the
/// new checkpoint to disk.
///
/// **Note:** Uses blocking `std::fs` I/O (not `tokio::fs`). This is acceptable
/// for the current use case — a single small JSON file read/write from CLI context.
/// If called from a multi-threaded async server, wrap in `tokio::task::spawn_blocking`.
///
/// Args:
/// * `cache_path` — Path to the cached checkpoint JSON file.
/// * `new_checkpoint` — The newly received signed checkpoint.
/// * `consistency_proof` — Proof that old tree is a prefix of the new tree.
/// * `_trust_root` — Trust root for checkpoint signature verification (reserved for future use).
/// * `_now` — Injected wall-clock time (reserved for future use).
///
/// Usage:
/// ```ignore
/// let report = update_checkpoint_cache(
///     &cache_path,
///     &new_checkpoint,
///     &consistency_proof,
///     &trust_root,
///     now,
/// )?;
/// ```
#[allow(clippy::disallowed_methods)] // Filesystem I/O is intentional here — this is a top-level SDK workflow
pub fn update_checkpoint_cache(
    cache_path: &Path,
    new_checkpoint: &SignedCheckpoint,
    consistency_proof: &ConsistencyProof,
    _trust_root: &TrustRoot,
    _now: DateTime<Utc>,
) -> Result<ConsistencyReport, TransparencyWorkflowError> {
    let old_checkpoint = match std::fs::read_to_string(cache_path) {
        Ok(json) => {
            let cp: SignedCheckpoint = serde_json::from_str(&json)
                .map_err(|e| TransparencyWorkflowError::DeserializationError(e.to_string()))?;
            Some(cp)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(TransparencyWorkflowError::CacheError(e)),
    };

    if let Some(ref old) = old_checkpoint {
        auths_transparency::verify_consistency(
            old.checkpoint.size,
            new_checkpoint.checkpoint.size,
            &consistency_proof.hashes,
            &old.checkpoint.root,
            &new_checkpoint.checkpoint.root,
        )
        .map_err(|e| TransparencyWorkflowError::CheckpointInconsistent(e.to_string()))?;
    }

    let json = serde_json::to_string_pretty(new_checkpoint)
        .map_err(|e| TransparencyWorkflowError::DeserializationError(e.to_string()))?;

    if let Some(parent) = cache_path.parent() {
        std::fs::create_dir_all(parent).map_err(TransparencyWorkflowError::CacheError)?;
    }
    std::fs::write(cache_path, json.as_bytes()).map_err(TransparencyWorkflowError::CacheError)?;

    let old_size = old_checkpoint.map(|c| c.checkpoint.size).unwrap_or(0);

    Ok(ConsistencyReport {
        old_size,
        new_size: new_checkpoint.checkpoint.size,
        consistent: true,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]
mod tests {
    use super::*;
    use auths_transparency::checkpoint::{Checkpoint, SignedCheckpoint};
    use auths_transparency::entry::{Entry, EntryBody, EntryContent, EntryType};
    use auths_transparency::proof::InclusionProof;
    use auths_transparency::types::{LogOrigin, MerkleHash};
    use auths_verifier::{CanonicalDid, DeviceDID, Ed25519PublicKey, Ed25519Signature};

    fn dummy_signed_checkpoint(size: u64, root: MerkleHash) -> SignedCheckpoint {
        SignedCheckpoint {
            checkpoint: Checkpoint {
                origin: LogOrigin::new("test.dev/log").unwrap(),
                size,
                root,
                timestamp: chrono::DateTime::parse_from_rfc3339("2025-06-15T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
            },
            log_signature: Ed25519Signature::from_bytes([0u8; 64]),
            log_public_key: Ed25519PublicKey::from_bytes([0u8; 32]),
            witnesses: vec![],
        }
    }

    fn dummy_trust_root() -> TrustRoot {
        TrustRoot {
            log_public_key: Ed25519PublicKey::from_bytes([0u8; 32]),
            log_origin: LogOrigin::new("test.dev/log").unwrap(),
            witnesses: vec![],
        }
    }

    #[test]
    fn verify_artifact_bundle_invalid_bundle_json() {
        let config = BundleVerifyConfig {
            bundle_json: "not valid json".into(),
            trust_root_json: "{}".into(),
        };
        let now = chrono::DateTime::parse_from_rfc3339("2025-07-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let err = verify_artifact_bundle(&config, now).unwrap_err();
        assert!(matches!(
            err,
            TransparencyWorkflowError::DeserializationError(_)
        ));
    }

    fn dummy_bundle() -> OfflineBundle {
        let ts = chrono::DateTime::parse_from_rfc3339("2025-06-15T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let entry = Entry {
            sequence: 0,
            timestamp: ts,
            content: EntryContent {
                entry_type: EntryType::DeviceBind,
                body: EntryBody::DeviceBind {
                    device_did: DeviceDID::new_unchecked("did:key:z6MkTest"),
                    public_key: Ed25519PublicKey::from_bytes([0u8; 32]),
                },
                actor_did: CanonicalDid::new_unchecked("did:key:z6MkTest"),
            },
            actor_sig: Ed25519Signature::empty(),
        };
        let root = MerkleHash::from_bytes([0u8; 32]);
        OfflineBundle {
            entry,
            inclusion_proof: InclusionProof {
                index: 0,
                size: 1,
                root,
                hashes: vec![],
            },
            signed_checkpoint: dummy_signed_checkpoint(1, root),
            delegation_chain: vec![],
        }
    }

    #[test]
    fn verify_artifact_bundle_invalid_trust_root_json() {
        let bundle = dummy_bundle();
        let bundle_json = serde_json::to_string(&bundle).unwrap();

        let config = BundleVerifyConfig {
            bundle_json,
            trust_root_json: "not valid json".into(),
        };
        let now = chrono::DateTime::parse_from_rfc3339("2025-07-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let err = verify_artifact_bundle(&config, now).unwrap_err();
        assert!(matches!(
            err,
            TransparencyWorkflowError::DeserializationError(_)
        ));
    }

    #[test]
    fn update_checkpoint_cache_writes_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("checkpoint.json");

        let root = MerkleHash::from_bytes([0xaa; 32]);
        let new_cp = dummy_signed_checkpoint(10, root);
        let proof = ConsistencyProof {
            old_size: 0,
            new_size: 10,
            old_root: MerkleHash::from_bytes([0u8; 32]),
            new_root: root,
            hashes: vec![],
        };
        let trust_root = dummy_trust_root();
        let now = chrono::DateTime::parse_from_rfc3339("2025-07-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let report =
            update_checkpoint_cache(&cache_path, &new_cp, &proof, &trust_root, now).unwrap();

        assert_eq!(report.old_size, 0);
        assert_eq!(report.new_size, 10);
        assert!(report.consistent);
        assert!(cache_path.exists());

        let written: SignedCheckpoint =
            serde_json::from_str(&std::fs::read_to_string(&cache_path).unwrap()).unwrap();
        assert_eq!(written.checkpoint.size, 10);
    }

    #[test]
    fn update_checkpoint_cache_creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir
            .path()
            .join("nested")
            .join("dir")
            .join("checkpoint.json");

        let root = MerkleHash::from_bytes([0xbb; 32]);
        let new_cp = dummy_signed_checkpoint(5, root);
        let proof = ConsistencyProof {
            old_size: 0,
            new_size: 5,
            old_root: MerkleHash::from_bytes([0u8; 32]),
            new_root: root,
            hashes: vec![],
        };
        let trust_root = dummy_trust_root();
        let now = chrono::DateTime::parse_from_rfc3339("2025-07-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let report =
            update_checkpoint_cache(&cache_path, &new_cp, &proof, &trust_root, now).unwrap();

        assert!(report.consistent);
        assert!(cache_path.exists());
    }
}
