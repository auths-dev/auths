//! SDK transparency verification workflows.

use std::path::{Path, PathBuf};

use auths_core::ports::config_store::{ConfigStore, ConfigStoreError};
use auths_core::ports::network::{NetworkError, RegistryClient};
use auths_keri::witness::independence::{
    IndependencePolicy, Infrastructure, Jurisdiction, OperatorId, Organization, WitnessOperatorInfo,
};
use auths_transparency::{
    BundleVerificationReport, ConsistencyProof, FsTileStore, LogOrigin, LogWriter, MerkleHash,
    OfflineBundle, SignedCheckpoint, TransparencyError, TrustRoot, TrustRootWitness, hash_leaf,
};
use auths_verifier::Ed25519PublicKey;
use auths_verifier::evidence_pack::TransparencyInclusion;
use chrono::{DateTime, Utc};
use thiserror::Error;

use crate::domains::compliance::releases::ArtifactDigest;

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
    CacheError(#[from] ConfigStoreError),

    /// JSON deserialization error.
    #[error("deserialization error: {0}")]
    DeserializationError(String),

    /// Network error fetching trust root or other remote data.
    #[error("network error: {0}")]
    NetworkError(#[source] NetworkError),

    /// Invalid caller input — a malformed artifact digest or log origin.
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// No local transparency log exists at the given directory yet.
    #[error("no transparency log at {0} — append an artifact first")]
    LogNotFound(PathBuf),

    /// An underlying transparency-log operation (append, prove, key) failed.
    #[error("transparency log error: {0}")]
    Transparency(#[from] TransparencyError),
}

/// Wire-format response from the registry trust-root endpoint.
#[derive(Debug, serde::Deserialize)]
struct TrustRootResponse {
    log_origin: String,
    log_public_key: String,
    witnesses: Vec<TrustRootWitnessResponse>,
    #[allow(dead_code)]
    version: u32,
}

/// Wire-format witness entry from the trust-root response.
#[derive(Debug, serde::Deserialize)]
struct TrustRootWitnessResponse {
    name: String,
    public_key: String,
    #[allow(dead_code)]
    url: String,
    /// Operator-independence attributes. Carried through to the trust root so the
    /// diversity gate can evaluate the actual cosigners; absent ⇒ this witness
    /// cannot contribute to independence.
    #[serde(default)]
    organization: Option<String>,
    #[serde(default)]
    jurisdiction: Option<String>,
    #[serde(default)]
    infrastructure: Option<String>,
}

/// Build the operator-independence attributes for a wire witness entry, if all
/// three axes are present and valid. Returns `None` (not an error) when any axis
/// is missing — an untagged witness simply cannot prove independence.
fn operator_info_from_wire(w: &TrustRootWitnessResponse) -> Option<WitnessOperatorInfo> {
    Some(WitnessOperatorInfo {
        operator: OperatorId::new(w.name.clone()).ok()?,
        organization: Organization::new(w.organization.clone()?).ok()?,
        jurisdiction: Jurisdiction::new(w.jurisdiction.clone()?).ok()?,
        infrastructure: Infrastructure::new(w.infrastructure.clone()?).ok()?,
    })
}

/// Fetch the trust root from a registry URL.
///
/// Issues a GET to `{registry_url}/v1/trust-root`, parses the JSON
/// response, and converts it into a domain [`TrustRoot`].
///
/// Args:
/// * `registry_url` — Base URL of the auths registry.
/// * `client` — Network client for HTTP communication.
///
/// Usage:
/// ```ignore
/// let trust_root = fetch_trust_root("https://network.auths.dev", &http_client).await?;
/// ```
pub async fn fetch_trust_root(
    registry_url: &str,
    client: &impl RegistryClient,
) -> Result<TrustRoot, TransparencyWorkflowError> {
    let bytes = client
        .fetch_registry_data(registry_url, "v1/trust-root")
        .await
        .map_err(TransparencyWorkflowError::NetworkError)?;

    let resp: TrustRootResponse = serde_json::from_slice(&bytes)
        .map_err(|e| TransparencyWorkflowError::DeserializationError(e.to_string()))?;

    let log_public_key_bytes: [u8; 32] = hex::decode(&resp.log_public_key)
        .map_err(|e| {
            TransparencyWorkflowError::DeserializationError(format!(
                "invalid hex in log_public_key: {e}"
            ))
        })?
        .try_into()
        .map_err(|_| {
            TransparencyWorkflowError::DeserializationError(
                "log_public_key must be exactly 32 bytes".into(),
            )
        })?;

    let log_origin = LogOrigin::new(&resp.log_origin).map_err(|e| {
        TransparencyWorkflowError::DeserializationError(format!("invalid log origin: {e}"))
    })?;

    let witnesses = resp
        .witnesses
        .into_iter()
        .filter(|w| !w.public_key.is_empty())
        .filter_map(|w| {
            let pk_bytes: [u8; 32] = hex::decode(&w.public_key).ok()?.try_into().ok()?;
            let public_key = Ed25519PublicKey::from_bytes(pk_bytes);
            let witness_did = auths_verifier::CanonicalDid::from_public_key_did_key(
                public_key.as_bytes(),
                auths_crypto::CurveType::Ed25519,
            );
            let operator_info = operator_info_from_wire(&w);
            Some(TrustRootWitness {
                witness_did,
                name: w.name,
                public_key,
                operator_info,
            })
        })
        .collect();

    Ok(TrustRoot {
        log_public_key: Ed25519PublicKey::from_bytes(log_public_key_bytes),
        log_origin,
        witnesses,
        signature_algorithm: Default::default(),
        ecdsa_log_public_key_der: None,
        // The registry trust-root wire format does not yet carry diversity
        // thresholds; the pinned `witness_policy.json` is the enforcement source.
        independence_policy: IndependencePolicy::unconstrained(),
    })
}

/// Configuration for bundle verification.
pub struct BundleVerifyConfig {
    /// The offline bundle serialized as JSON.
    pub bundle_json: String,
    /// The trust root serialized as JSON.
    pub trust_root_json: String,
}

/// Result of a consistency check between cached and new checkpoints.
#[derive(Debug)]
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
/// Args:
/// * `store` — File-access port for the checkpoint cache file.
/// * `cache_path` — Path to the cached checkpoint JSON file.
/// * `new_checkpoint` — The newly received signed checkpoint.
/// * `consistency_proof` — Proof that old tree is a prefix of the new tree.
/// * `_trust_root` — Trust root for checkpoint signature verification (reserved for future use).
/// * `_now` — Injected wall-clock time (reserved for future use).
///
/// Usage:
/// ```ignore
/// let report = update_checkpoint_cache(
///     &store,
///     &cache_path,
///     &new_checkpoint,
///     &consistency_proof,
///     &trust_root,
///     now,
/// )?;
/// ```
pub fn update_checkpoint_cache(
    store: &dyn ConfigStore,
    cache_path: &Path,
    new_checkpoint: &SignedCheckpoint,
    consistency_proof: &ConsistencyProof,
    _trust_root: &TrustRoot,
    _now: DateTime<Utc>,
) -> Result<ConsistencyReport, TransparencyWorkflowError> {
    let old_checkpoint = load_cached_checkpoint(store, cache_path)?;

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

    write_cached_checkpoint(store, cache_path, new_checkpoint)?;

    let old_size = old_checkpoint.map(|c| c.checkpoint.size).unwrap_or(0);

    Ok(ConsistencyReport {
        old_size,
        new_size: new_checkpoint.checkpoint.size,
        consistent: true,
    })
}

/// Read and parse the cached checkpoint via the store, `None` when absent.
fn load_cached_checkpoint(
    store: &dyn ConfigStore,
    cache_path: &Path,
) -> Result<Option<SignedCheckpoint>, TransparencyWorkflowError> {
    match store.read(cache_path)? {
        Some(json) => serde_json::from_str(&json)
            .map(Some)
            .map_err(|e| TransparencyWorkflowError::DeserializationError(e.to_string())),
        None => Ok(None),
    }
}

/// Serialize and write the checkpoint via the store (parent dirs created by the store).
fn write_cached_checkpoint(
    store: &dyn ConfigStore,
    cache_path: &Path,
    checkpoint: &SignedCheckpoint,
) -> Result<(), TransparencyWorkflowError> {
    let json = serde_json::to_string_pretty(checkpoint)
        .map_err(|e| TransparencyWorkflowError::DeserializationError(e.to_string()))?;
    store.write(cache_path, &json)?;
    Ok(())
}

/// Cache a checkpoint using trust-on-first-use (TOFU) semantics.
///
/// If no cached checkpoint exists, the new checkpoint is accepted and written.
/// If a cached checkpoint exists with the same or smaller tree size and matching
/// root, the cache is left unchanged. If the cached checkpoint has the same size
/// but a different root, this is equivocation — returns a hard error.
/// If a consistency proof is provided, full Merkle consistency is verified.
///
/// Args:
/// * `store` — File-access port for the checkpoint cache file.
/// * `cache_path` — Path to the cached checkpoint JSON file (`~/.auths/log_checkpoint.json`).
/// * `new_checkpoint` — The checkpoint to cache.
/// * `consistency_proof` — Optional consistency proof for cache-hit cases.
///
/// Usage:
/// ```ignore
/// try_cache_checkpoint(
///     &store,
///     &Path::new("~/.auths/log_checkpoint.json"),
///     &bundle.signed_checkpoint,
///     None,
/// )?;
/// ```
pub fn try_cache_checkpoint(
    store: &dyn ConfigStore,
    cache_path: &Path,
    new_checkpoint: &SignedCheckpoint,
    consistency_proof: Option<&ConsistencyProof>,
) -> Result<ConsistencyReport, TransparencyWorkflowError> {
    let old_checkpoint = load_cached_checkpoint(store, cache_path)?;

    if let Some(ref old) = old_checkpoint {
        // Equivocation: same size, different root
        if old.checkpoint.size == new_checkpoint.checkpoint.size
            && old.checkpoint.root != new_checkpoint.checkpoint.root
        {
            return Err(TransparencyWorkflowError::CheckpointInconsistent(format!(
                "equivocation detected: same tree size {} but different roots",
                old.checkpoint.size
            )));
        }

        // New checkpoint must not be smaller
        if new_checkpoint.checkpoint.size < old.checkpoint.size {
            return Err(TransparencyWorkflowError::CheckpointInconsistent(format!(
                "new checkpoint size {} is smaller than cached size {}",
                new_checkpoint.checkpoint.size, old.checkpoint.size
            )));
        }

        // Same checkpoint — no update needed
        if old.checkpoint.size == new_checkpoint.checkpoint.size {
            return Ok(ConsistencyReport {
                old_size: old.checkpoint.size,
                new_size: new_checkpoint.checkpoint.size,
                consistent: true,
            });
        }

        // If we have a consistency proof, verify it
        if let Some(proof) = consistency_proof {
            auths_transparency::verify_consistency(
                old.checkpoint.size,
                new_checkpoint.checkpoint.size,
                &proof.hashes,
                &old.checkpoint.root,
                &new_checkpoint.checkpoint.root,
            )
            .map_err(|e| TransparencyWorkflowError::CheckpointInconsistent(e.to_string()))?;
        }
    }

    write_cached_checkpoint(store, cache_path, new_checkpoint)?;

    let old_size = old_checkpoint.map(|c| c.checkpoint.size).unwrap_or(0);

    Ok(ConsistencyReport {
        old_size,
        new_size: new_checkpoint.checkpoint.size,
        consistent: true,
    })
}

/// Outcome of appending an artifact digest to a local transparency log.
///
/// Carries the sequenced position and the fresh signed checkpoint so a
/// presentation layer can render or persist them; the raw leaf hash is
/// retained for callers that re-derive it (`hash_leaf(artifact_digest)`).
#[derive(Debug, Clone)]
pub struct AppendedArtifact {
    /// Canonical `sha256:<hex>` digest that was logged.
    pub artifact_digest: String,
    /// Merkle leaf hash the digest was stored under.
    pub leaf_hash: MerkleHash,
    /// Zero-based index the leaf was sequenced at.
    pub index: u64,
    /// The checkpoint signed over the tree that now includes the leaf.
    pub signed_checkpoint: SignedCheckpoint,
}

/// Open a writer over the local tile-backed log, validating the origin and
/// (when `create`) ensuring the log directory and signing key exist. The
/// filesystem work — creating the directory and loading or minting the signing
/// key — lives on [`FsTileStore`] so the workflow stays I/O-free.
fn open_log_writer(
    log_dir: &Path,
    origin: &str,
    create: bool,
) -> Result<LogWriter<FsTileStore>, TransparencyWorkflowError> {
    let origin = LogOrigin::new(origin)
        .map_err(|e| TransparencyWorkflowError::InvalidInput(format!("invalid log origin: {e}")))?;
    let store = FsTileStore::new(log_dir.to_path_buf());
    if create {
        store.ensure_base_dir()?;
    }
    let key = store
        .load_or_create_key(create)?
        .ok_or_else(|| TransparencyWorkflowError::LogNotFound(log_dir.to_path_buf()))?;
    Ok(LogWriter::new(store, key, origin))
}

/// Append an artifact digest to a local tile-backed transparency log.
///
/// Validates the digest, creates the log directory and signing key on first
/// use, hashes the canonical digest string into a leaf, appends it, and
/// returns the sequenced position plus the newly signed checkpoint. The log
/// is append-only: repeated calls grow the tree.
///
/// Args:
/// * `log_dir` — Directory holding the tile store and `log.key`.
/// * `origin` — Log origin string (non-empty ASCII) written into checkpoints.
/// * `artifact_digest` — Artifact digest to log (`sha256:<64 hex>`).
/// * `now` — Injected wall-clock time stamped into the checkpoint.
///
/// Usage:
/// ```ignore
/// let appended =
///     append_artifact_digest(&log_dir, "acme.dev/releases", "sha256:ab..cd", now).await?;
/// ```
pub async fn append_artifact_digest(
    log_dir: &Path,
    origin: &str,
    artifact_digest: &str,
    now: DateTime<Utc>,
) -> Result<AppendedArtifact, TransparencyWorkflowError> {
    let digest = ArtifactDigest::parse(artifact_digest).map_err(|e| {
        TransparencyWorkflowError::InvalidInput(format!("invalid artifact digest: {e}"))
    })?;
    let writer = open_log_writer(log_dir, origin, true)?;

    let leaf_hash = hash_leaf(digest.as_str().as_bytes());
    let appended = writer.append(leaf_hash, now).await?;

    Ok(AppendedArtifact {
        artifact_digest: digest.into_inner(),
        leaf_hash,
        index: appended.index,
        signed_checkpoint: appended.signed_checkpoint,
    })
}

/// Emit offline inclusion evidence for an artifact digest already appended to
/// a local transparency log.
///
/// Validates the digest, re-derives its leaf, and proves the leaf against the
/// current signed checkpoint. Errors when no log exists yet ([`TransparencyWorkflowError::LogNotFound`])
/// or the leaf was never appended (an [`TransparencyWorkflowError::Transparency`]
/// invalid-proof error). The returned evidence is re-verifiable offline.
///
/// Args:
/// * `log_dir` — Directory holding the tile store and `log.key`.
/// * `origin` — Log origin string (must match the one used to append).
/// * `artifact_digest` — Artifact digest to prove (`sha256:<64 hex>`).
///
/// Usage:
/// ```ignore
/// let evidence = prove_artifact_digest(&log_dir, "acme.dev/releases", "sha256:ab..cd").await?;
/// ```
pub async fn prove_artifact_digest(
    log_dir: &Path,
    origin: &str,
    artifact_digest: &str,
) -> Result<TransparencyInclusion, TransparencyWorkflowError> {
    let digest = ArtifactDigest::parse(artifact_digest).map_err(|e| {
        TransparencyWorkflowError::InvalidInput(format!("invalid artifact digest: {e}"))
    })?;
    let writer = open_log_writer(log_dir, origin, false)?;

    let leaf_hash = hash_leaf(digest.as_str().as_bytes());
    let inclusion = writer.prove(&leaf_hash).await?;
    Ok(inclusion)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]
mod tests {
    use super::*;
    use auths_transparency::checkpoint::{Checkpoint, SignedCheckpoint};

    struct FsStore;

    impl ConfigStore for FsStore {
        fn read(&self, path: &Path) -> Result<Option<String>, ConfigStoreError> {
            match std::fs::read_to_string(path) {
                Ok(content) => Ok(Some(content)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(ConfigStoreError::Read {
                    path: path.to_path_buf(),
                    source: e,
                }),
            }
        }

        fn write(&self, path: &Path, content: &str) -> Result<(), ConfigStoreError> {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| ConfigStoreError::Write {
                    path: path.to_path_buf(),
                    source: e,
                })?;
            }
            std::fs::write(path, content).map_err(|e| ConfigStoreError::Write {
                path: path.to_path_buf(),
                source: e,
            })
        }
    }
    use auths_transparency::entry::{Entry, EntryBody, EntryContent, EntryType};
    use auths_transparency::proof::InclusionProof;
    use auths_transparency::types::{LogOrigin, MerkleHash};
    use auths_verifier::{CanonicalDid, Ed25519PublicKey, Ed25519Signature};

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
            ecdsa_checkpoint_signature: None,
            ecdsa_checkpoint_key: None,
        }
    }

    fn dummy_trust_root() -> TrustRoot {
        TrustRoot {
            log_public_key: Ed25519PublicKey::from_bytes([0u8; 32]),
            log_origin: LogOrigin::new("test.dev/log").unwrap(),
            witnesses: vec![],
            signature_algorithm: Default::default(),
            ecdsa_log_public_key_der: None,
            independence_policy: IndependencePolicy::unconstrained(),
        }
    }

    /// A registry client that returns a fixed trust-root document.
    struct CannedRegistry {
        trust_root_json: Vec<u8>,
    }

    impl RegistryClient for CannedRegistry {
        async fn fetch_registry_data(
            &self,
            _registry_url: &str,
            _path: &str,
        ) -> Result<Vec<u8>, NetworkError> {
            Ok(self.trust_root_json.clone())
        }

        async fn push_registry_data(
            &self,
            _registry_url: &str,
            _path: &str,
            _data: &[u8],
        ) -> Result<(), NetworkError> {
            Ok(())
        }

        async fn post_json(
            &self,
            _registry_url: &str,
            _path: &str,
            _json_body: &[u8],
        ) -> Result<auths_core::ports::network::RegistryResponse, NetworkError> {
            Ok(auths_core::ports::network::RegistryResponse {
                status: 200,
                body: vec![],
                rate_limit: None,
            })
        }
    }

    #[tokio::test]
    async fn fetch_trust_root_round_trips_independence_attributes() {
        let log_pk = hex::encode([0u8; 32]);
        let w_pk = hex::encode([7u8; 32]);
        let json = format!(
            r#"{{"version":1,"log_origin":"test.dev/log","log_public_key":"{log_pk}","witnesses":[{{"name":"w1","public_key":"{w_pk}","url":"http://w1","organization":"org-a","jurisdiction":"US","infrastructure":"aws/us-east-1"}}]}}"#
        );
        let client = CannedRegistry {
            trust_root_json: json.into_bytes(),
        };

        let trust_root = fetch_trust_root("https://registry.test", &client)
            .await
            .unwrap();

        assert_eq!(trust_root.witnesses.len(), 1);
        let attrs = trust_root.witnesses[0]
            .operator_attributes()
            .expect("operator attributes survive ingestion");
        assert_eq!(attrs.organization.as_str(), "org-a");
        assert_eq!(attrs.jurisdiction.as_str(), "US");
        assert_eq!(attrs.infrastructure.as_str(), "aws/us-east-1");
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
                    device_did: CanonicalDid::new_unchecked("did:key:z6MkTest"),
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
            update_checkpoint_cache(&FsStore, &cache_path, &new_cp, &proof, &trust_root, now)
                .unwrap();

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
            update_checkpoint_cache(&FsStore, &cache_path, &new_cp, &proof, &trust_root, now)
                .unwrap();

        assert!(report.consistent);
        assert!(cache_path.exists());
    }

    #[test]
    fn try_cache_checkpoint_tofu_writes_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("log_checkpoint.json");

        let root = MerkleHash::from_bytes([0xaa; 32]);
        let cp = dummy_signed_checkpoint(10, root);

        let report = try_cache_checkpoint(&FsStore, &cache_path, &cp, None).unwrap();
        assert_eq!(report.old_size, 0);
        assert_eq!(report.new_size, 10);
        assert!(report.consistent);
        assert!(cache_path.exists());
    }

    #[test]
    fn try_cache_checkpoint_same_checkpoint_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("log_checkpoint.json");

        let root = MerkleHash::from_bytes([0xaa; 32]);
        let cp = dummy_signed_checkpoint(10, root);

        try_cache_checkpoint(&FsStore, &cache_path, &cp, None).unwrap();
        let report = try_cache_checkpoint(&FsStore, &cache_path, &cp, None).unwrap();
        assert_eq!(report.old_size, 10);
        assert_eq!(report.new_size, 10);
        assert!(report.consistent);
    }

    #[test]
    fn try_cache_checkpoint_detects_equivocation() {
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("log_checkpoint.json");

        let root1 = MerkleHash::from_bytes([0xaa; 32]);
        let cp1 = dummy_signed_checkpoint(10, root1);
        try_cache_checkpoint(&FsStore, &cache_path, &cp1, None).unwrap();

        let root2 = MerkleHash::from_bytes([0xbb; 32]);
        let cp2 = dummy_signed_checkpoint(10, root2);
        let err = try_cache_checkpoint(&FsStore, &cache_path, &cp2, None).unwrap_err();
        assert!(matches!(
            err,
            TransparencyWorkflowError::CheckpointInconsistent(_)
        ));
    }

    #[test]
    fn try_cache_checkpoint_rejects_smaller_size() {
        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("log_checkpoint.json");

        let cp1 = dummy_signed_checkpoint(10, MerkleHash::from_bytes([0xaa; 32]));
        try_cache_checkpoint(&FsStore, &cache_path, &cp1, None).unwrap();

        let cp2 = dummy_signed_checkpoint(5, MerkleHash::from_bytes([0xbb; 32]));
        let err = try_cache_checkpoint(&FsStore, &cache_path, &cp2, None).unwrap_err();
        assert!(matches!(
            err,
            TransparencyWorkflowError::CheckpointInconsistent(_)
        ));
    }

    // ---- local-log append / prove workflow ----

    const TEST_DIGEST: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const TEST_DIGEST_2: &str =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn fixed_now() -> DateTime<Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-07-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[tokio::test]
    async fn append_creates_log_and_returns_sequenced_leaf() {
        let dir = tempfile::tempdir().unwrap();

        let appended = append_artifact_digest(dir.path(), "test.dev/log", TEST_DIGEST, fixed_now())
            .await
            .unwrap();

        assert_eq!(appended.index, 0);
        assert_eq!(appended.artifact_digest, TEST_DIGEST);
        assert_eq!(appended.signed_checkpoint.checkpoint.size, 1);
        assert_eq!(appended.leaf_hash, hash_leaf(TEST_DIGEST.as_bytes()));
        assert!(dir.path().join("log.key").exists());
    }

    #[tokio::test]
    async fn append_normalizes_uppercase_hex() {
        let dir = tempfile::tempdir().unwrap();
        let upper = TEST_DIGEST
            .to_ascii_uppercase()
            .replace("SHA256:", "sha256:");

        let appended = append_artifact_digest(dir.path(), "test.dev/log", &upper, fixed_now())
            .await
            .unwrap();

        assert_eq!(appended.artifact_digest, TEST_DIGEST);
        assert_eq!(appended.leaf_hash, hash_leaf(TEST_DIGEST.as_bytes()));
    }

    #[tokio::test]
    async fn append_is_append_only_and_grows_the_tree() {
        let dir = tempfile::tempdir().unwrap();

        let a = append_artifact_digest(dir.path(), "test.dev/log", TEST_DIGEST, fixed_now())
            .await
            .unwrap();
        let b = append_artifact_digest(dir.path(), "test.dev/log", TEST_DIGEST_2, fixed_now())
            .await
            .unwrap();

        assert_eq!(a.index, 0);
        assert_eq!(b.index, 1);
        assert_eq!(b.signed_checkpoint.checkpoint.size, 2);
    }

    #[tokio::test]
    async fn append_then_prove_round_trips_and_proof_verifies() {
        let dir = tempfile::tempdir().unwrap();
        append_artifact_digest(dir.path(), "test.dev/log", TEST_DIGEST, fixed_now())
            .await
            .unwrap();

        let inclusion = prove_artifact_digest(dir.path(), "test.dev/log", TEST_DIGEST)
            .await
            .unwrap();

        assert_eq!(inclusion.inclusion_proof.index, 0);
        assert_eq!(inclusion.inclusion_proof.size, 1);
        assert_eq!(inclusion.leaf_hash, hash_leaf(TEST_DIGEST.as_bytes()));
        inclusion
            .inclusion_proof
            .verify(&inclusion.leaf_hash)
            .unwrap();
    }

    #[tokio::test]
    async fn prove_without_any_log_errors() {
        let dir = tempfile::tempdir().unwrap();
        let err = prove_artifact_digest(dir.path(), "test.dev/log", TEST_DIGEST)
            .await
            .unwrap_err();
        assert!(matches!(err, TransparencyWorkflowError::LogNotFound(_)));
    }

    #[tokio::test]
    async fn prove_absent_leaf_errors() {
        let dir = tempfile::tempdir().unwrap();
        append_artifact_digest(dir.path(), "test.dev/log", TEST_DIGEST, fixed_now())
            .await
            .unwrap();

        let err = prove_artifact_digest(dir.path(), "test.dev/log", TEST_DIGEST_2)
            .await
            .unwrap_err();
        assert!(matches!(err, TransparencyWorkflowError::Transparency(_)));
    }

    #[tokio::test]
    async fn append_rejects_malformed_digest() {
        let dir = tempfile::tempdir().unwrap();
        let err = append_artifact_digest(dir.path(), "test.dev/log", "not-a-digest", fixed_now())
            .await
            .unwrap_err();
        assert!(matches!(err, TransparencyWorkflowError::InvalidInput(_)));
    }

    #[tokio::test]
    async fn append_rejects_empty_origin() {
        let dir = tempfile::tempdir().unwrap();
        let err = append_artifact_digest(dir.path(), "", TEST_DIGEST, fixed_now())
            .await
            .unwrap_err();
        assert!(matches!(err, TransparencyWorkflowError::InvalidInput(_)));
    }
}
