use std::sync::Mutex;

use crate::ports::artifact::{ArtifactDigest, ArtifactError, ArtifactMetadata, ArtifactSource};

/// Configurable fake for [`ArtifactSource`].
///
/// Returns canned digest/metadata or configurable errors for failure-path testing.
///
/// Usage:
/// ```ignore
/// let fake = FakeArtifactSource::new("release.tar.gz", "sha256", "abcdef...", 1024);
/// let fake = FakeArtifactSource::digest_fails_with("read error");
/// ```
pub struct FakeArtifactSource {
    digest: ArtifactDigest,
    name: String,
    size: u64,
    fail_digest: Mutex<Option<String>>,
    fail_metadata: Mutex<Option<String>>,
}

impl FakeArtifactSource {
    /// Create a fake that returns the given digest and metadata.
    pub fn new(name: &str, algorithm: &str, hex: &str, size: u64) -> Self {
        Self {
            digest: ArtifactDigest {
                algorithm: algorithm.to_string(),
                hex: hex.to_string(),
            },
            name: name.to_string(),
            size,
            fail_digest: Mutex::new(None),
            fail_metadata: Mutex::new(None),
        }
    }

    /// Create a fake where `digest()` always returns an error.
    pub fn digest_fails_with(msg: &str) -> Self {
        Self {
            digest: ArtifactDigest {
                algorithm: String::new(),
                hex: String::new(),
            },
            name: String::new(),
            size: 0,
            fail_digest: Mutex::new(Some(msg.to_string())),
            fail_metadata: Mutex::new(None),
        }
    }

    /// Create a fake where `metadata()` always returns an error.
    pub fn metadata_fails_with(msg: &str) -> Self {
        Self {
            digest: ArtifactDigest {
                algorithm: String::new(),
                hex: String::new(),
            },
            name: String::new(),
            size: 0,
            fail_digest: Mutex::new(None),
            fail_metadata: Mutex::new(Some(msg.to_string())),
        }
    }
}

impl ArtifactSource for FakeArtifactSource {
    fn digest(&self) -> Result<ArtifactDigest, ArtifactError> {
        if let Some(msg) = self
            .fail_digest
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            return Err(ArtifactError::Io(msg.clone()));
        }
        Ok(self.digest.clone())
    }

    fn metadata(&self) -> Result<ArtifactMetadata, ArtifactError> {
        if let Some(msg) = self
            .fail_metadata
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            return Err(ArtifactError::Metadata(msg.clone()));
        }
        Ok(ArtifactMetadata {
            artifact_type: "memory".to_string(),
            digest: self.digest.clone(),
            name: Some(self.name.clone()),
            size: Some(self.size),
        })
    }
}
