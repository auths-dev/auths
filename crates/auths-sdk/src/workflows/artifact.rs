//! Artifact digest computation workflow.

use crate::ports::artifact::{ArtifactDigest, ArtifactError, ArtifactSource};

/// Compute the digest of an artifact source.
///
/// Args:
/// * `source`: Any implementation of `ArtifactSource`.
///
/// Usage:
/// ```ignore
/// let digest = compute_digest(&file_artifact)?;
/// println!("sha256:{}", digest.hex);
/// ```
pub fn compute_digest(source: &dyn ArtifactSource) -> Result<ArtifactDigest, ArtifactError> {
    source.digest()
}
