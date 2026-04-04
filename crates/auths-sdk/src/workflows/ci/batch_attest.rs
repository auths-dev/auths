//! Batch artifact signing and attestation collection workflow.
//!
//! Provides the domain logic for CI attestation pipelines: sign multiple
//! artifacts in one pass, collect attestation files to a target directory,
//! and report per-file results. Used by the CLI `artifact batch-sign` command
//! and the `auths-dev/attest-action` GitHub Action.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::context::AuthsContext;
use crate::domains::ci::error::CiError;
use crate::domains::signing::service::{ArtifactSigningParams, SigningKeyMaterial, sign_artifact};
use crate::ports::artifact::ArtifactSource;
use auths_core::storage::keychain::KeyAlias;

/// A single artifact to sign in a batch operation.
///
/// Args:
/// * `source`: The artifact data source (implements digest/metadata).
/// * `output_path`: Where to write the `.auths.json` attestation file.
///
/// Usage:
/// ```ignore
/// let entry = BatchEntry {
///     source: Arc::new(my_artifact),
///     output_path: PathBuf::from("release.tar.gz.auths.json"),
/// };
/// ```
pub struct BatchEntry {
    /// Artifact source providing digest and metadata.
    pub source: Arc<dyn ArtifactSource>,
    /// Destination path for the attestation JSON file.
    pub output_path: PathBuf,
}

/// Configuration for a batch signing operation.
///
/// Args:
/// * `entries`: List of artifacts to sign with their output paths.
/// * `device_key`: Device key alias used for dual-signing.
/// * `identity_key`: Optional identity key alias (omit for device-only CI signing).
/// * `expires_in`: Optional TTL in seconds for attestation expiry.
/// * `note`: Optional annotation embedded in each attestation.
/// * `attestation_dir`: If set, attestation files are also copied here.
///
/// Usage:
/// ```ignore
/// let config = BatchSignConfig {
///     entries: vec![entry1, entry2],
///     device_key: "ci-release-device".to_string(),
///     identity_key: None,
///     expires_in: None,
///     note: Some("release v1.0".to_string()),
///     attestation_dir: Some(PathBuf::from(".auths/releases")),
/// };
/// ```
pub struct BatchSignConfig {
    /// Artifacts to sign.
    pub entries: Vec<BatchEntry>,
    /// Device key alias for signing.
    pub device_key: String,
    /// Optional identity key alias.
    pub identity_key: Option<String>,
    /// Optional TTL in seconds.
    pub expires_in: Option<u64>,
    /// Optional note for all attestations.
    pub note: Option<String>,
    /// Git commit SHA for provenance binding (shared across all artifacts in batch).
    pub commit_sha: Option<String>,
}

/// Outcome for a single artifact in a batch.
#[derive(Debug)]
pub enum BatchEntryResult {
    /// Signing succeeded.
    Signed(SignedArtifact),
    /// Signing failed for this artifact (other artifacts may still succeed).
    Failed(FailedArtifact),
}

/// A successfully signed artifact.
///
/// Usage:
/// ```ignore
/// println!("Signed {} (sha256:{})", result.rid, result.digest);
/// ```
#[derive(Debug)]
pub struct SignedArtifact {
    /// Intended output path for the attestation file.
    pub output_path: PathBuf,
    /// Canonical JSON of the signed attestation.
    pub attestation_json: String,
    /// Resource identifier from the attestation.
    pub rid: String,
    /// Hex-encoded SHA-256 digest of the artifact.
    pub digest: String,
}

/// An artifact that failed to sign.
#[derive(Debug)]
pub struct FailedArtifact {
    /// Output path that would have been written.
    pub output_path: PathBuf,
    /// The error that prevented signing.
    pub error: String,
}

/// Result of a batch signing operation.
///
/// Usage:
/// ```ignore
/// let result = batch_sign_artifacts(config, &ctx)?;
/// println!("{} signed, {} failed", result.signed_count(), result.failed_count());
/// ```
#[derive(Debug)]
pub struct BatchSignResult {
    /// Per-artifact outcomes.
    pub results: Vec<BatchEntryResult>,
}

impl BatchSignResult {
    /// Number of successfully signed artifacts.
    pub fn signed_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| matches!(r, BatchEntryResult::Signed(_)))
            .count()
    }

    /// Number of failed artifacts.
    pub fn failed_count(&self) -> usize {
        self.results
            .iter()
            .filter(|r| matches!(r, BatchEntryResult::Failed(_)))
            .count()
    }

    /// Whether all artifacts were signed successfully.
    pub fn all_succeeded(&self) -> bool {
        self.failed_count() == 0
    }
}

// Errors are defined in crate::domains::ci::error::CiError

/// Derive the default attestation output path for an artifact.
///
/// Args:
/// * `artifact_path`: Path to the original artifact file.
///
/// Usage:
/// ```ignore
/// let out = default_attestation_path(Path::new("release.tar.gz"));
/// assert_eq!(out, PathBuf::from("release.tar.gz.auths.json"));
/// ```
pub fn default_attestation_path(artifact_path: &Path) -> PathBuf {
    let mut p = artifact_path.to_path_buf();
    let new_name = format!(
        "{}.auths.json",
        p.file_name().unwrap_or_default().to_string_lossy()
    );
    p.set_file_name(new_name);
    p
}

/// Sign multiple artifacts in a single batch and optionally collect attestations.
///
/// Each artifact is signed independently — a failure on one does not prevent
/// signing the others. Results are returned per-artifact so callers can decide
/// how to handle partial failures.
///
/// Args:
/// * `config`: Batch configuration with artifact entries, keys, and options.
/// * `ctx`: Runtime context providing identity storage, keychain, and clock.
///
/// Usage:
/// ```ignore
/// let result = batch_sign_artifacts(config, &ctx)?;
/// for entry in &result.results {
///     match entry {
///         BatchEntryResult::Signed(s) => println!("OK: {}", s.output_path.display()),
///         BatchEntryResult::Failed(f) => eprintln!("FAIL: {}: {}", f.output_path.display(), f.error),
///     }
/// }
/// ```
pub fn batch_sign_artifacts(
    config: BatchSignConfig,
    ctx: &AuthsContext,
) -> Result<BatchSignResult, CiError> {
    if config.entries.is_empty() {
        return Err(CiError::NoArtifacts);
    }

    let mut results = Vec::with_capacity(config.entries.len());

    for entry in &config.entries {
        let params = ArtifactSigningParams {
            artifact: Arc::clone(&entry.source),
            identity_key: config
                .identity_key
                .as_ref()
                .map(|k| SigningKeyMaterial::Alias(KeyAlias::new_unchecked(k))),
            device_key: SigningKeyMaterial::Alias(KeyAlias::new_unchecked(&config.device_key)),
            expires_in: config.expires_in,
            note: config.note.clone(),
            commit_sha: config.commit_sha.clone(),
        };

        match sign_artifact(params, ctx) {
            Ok(result) => results.push(BatchEntryResult::Signed(SignedArtifact {
                output_path: entry.output_path.clone(),
                attestation_json: result.attestation_json,
                rid: result.rid.to_string(),
                digest: result.digest,
            })),
            Err(e) => results.push(BatchEntryResult::Failed(FailedArtifact {
                output_path: entry.output_path.clone(),
                error: e.to_string(),
            })),
        }
    }

    Ok(BatchSignResult { results })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_attestation_path_appends_suffix() {
        let p = default_attestation_path(Path::new("/tmp/release.tar.gz"));
        assert_eq!(p, PathBuf::from("/tmp/release.tar.gz.auths.json"));
    }

    #[test]
    fn default_attestation_path_handles_bare_name() {
        let p = default_attestation_path(Path::new("artifact.bin"));
        assert_eq!(p, PathBuf::from("artifact.bin.auths.json"));
    }

    #[test]
    fn batch_sign_result_counts() {
        let result = BatchSignResult {
            results: vec![
                BatchEntryResult::Signed(SignedArtifact {
                    output_path: PathBuf::from("a.auths.json"),
                    attestation_json: "{}".to_string(),
                    rid: "sha256:abc".to_string(),
                    digest: "abc".to_string(),
                }),
                BatchEntryResult::Failed(FailedArtifact {
                    output_path: PathBuf::from("b.auths.json"),
                    error: "test error".to_string(),
                }),
                BatchEntryResult::Signed(SignedArtifact {
                    output_path: PathBuf::from("c.auths.json"),
                    attestation_json: "{}".to_string(),
                    rid: "sha256:def".to_string(),
                    digest: "def".to_string(),
                }),
            ],
        };

        assert_eq!(result.signed_count(), 2);
        assert_eq!(result.failed_count(), 1);
        assert!(!result.all_succeeded());
    }

    #[test]
    fn batch_sign_result_all_succeeded() {
        let result = BatchSignResult {
            results: vec![BatchEntryResult::Signed(SignedArtifact {
                output_path: PathBuf::from("a.auths.json"),
                attestation_json: "{}".to_string(),
                rid: "sha256:abc".to_string(),
                digest: "abc".to_string(),
            })],
        };

        assert!(result.all_succeeded());
    }
}
