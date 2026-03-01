//! Local filesystem artifact adapter.

use auths_sdk::ports::artifact::{ArtifactDigest, ArtifactError, ArtifactMetadata, ArtifactSource};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Artifact source backed by a local file.
///
/// Usage:
/// ```ignore
/// let artifact = LocalFileArtifact::new("path/to/file.tar.gz");
/// let digest = artifact.digest()?;
/// ```
pub struct LocalFileArtifact {
    path: PathBuf,
}

impl LocalFileArtifact {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl ArtifactSource for LocalFileArtifact {
    fn digest(&self) -> Result<ArtifactDigest, ArtifactError> {
        let mut file = std::fs::File::open(&self.path)
            .map_err(|e| ArtifactError::Io(format!("{}: {}", self.path.display(), e)))?;

        let mut hasher = Sha256::new();
        let mut buf = [0u8; 8192];

        loop {
            let n = file
                .read(&mut buf)
                .map_err(|e| ArtifactError::Io(e.to_string()))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }

        Ok(ArtifactDigest {
            algorithm: "sha256".to_string(),
            hex: hex::encode(hasher.finalize()),
        })
    }

    fn metadata(&self) -> Result<ArtifactMetadata, ArtifactError> {
        let digest = self.digest()?;
        let file_meta = std::fs::metadata(&self.path)
            .map_err(|e| ArtifactError::Metadata(format!("{}: {}", self.path.display(), e)))?;

        Ok(ArtifactMetadata {
            artifact_type: "file".to_string(),
            digest,
            name: self
                .path
                .file_name()
                .map(|n| n.to_string_lossy().to_string()),
            size: Some(file_meta.len()),
        })
    }
}
