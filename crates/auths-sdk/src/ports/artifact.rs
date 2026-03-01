//! Artifact source port for computing digests and metadata.
//!
//! Abstracts artifact access so implementations can read from files,
//! S3, network sockets, or in-memory buffers.

use serde::{Deserialize, Serialize};

/// Content-addressed digest of an artifact.
///
/// Usage:
/// ```ignore
/// let digest = ArtifactDigest {
///     algorithm: DigestAlgorithm::Sha256,
///     hex: "b94d27b9...".to_string(),
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactDigest {
    /// The hash algorithm used (e.g. `"sha256"`).
    pub algorithm: String,
    /// The hex-encoded digest value.
    pub hex: String,
}

/// Metadata describing an artifact.
///
/// Usage:
/// ```ignore
/// let meta = ArtifactMetadata {
///     artifact_type: "file".to_string(),
///     digest: digest.clone(),
///     name: Some("release.tar.gz".to_string()),
///     size: Some(1024),
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactMetadata {
    /// The artifact type name (e.g. `"file"`, `"container"`).
    pub artifact_type: String,
    /// Content-addressed digest of the artifact.
    pub digest: ArtifactDigest,
    /// Optional human-readable name of the artifact.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Optional size in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

/// Errors from artifact operations.
#[derive(Debug, thiserror::Error)]
pub enum ArtifactError {
    /// An I/O error occurred reading the artifact.
    #[error("IO error reading artifact: {0}")]
    Io(String),
    /// Artifact metadata could not be retrieved.
    #[error("metadata unavailable: {0}")]
    Metadata(String),
}

/// Port for computing artifact digests and metadata.
///
/// Usage:
/// ```ignore
/// let digest = source.digest()?;
/// let meta = source.metadata()?;
/// ```
pub trait ArtifactSource: Send + Sync {
    /// Compute the content-addressed digest of the artifact.
    fn digest(&self) -> Result<ArtifactDigest, ArtifactError>;

    /// Retrieve metadata about the artifact.
    fn metadata(&self) -> Result<ArtifactMetadata, ArtifactError>;
}
