//! CI domain errors shared across CI workflows.

use std::path::PathBuf;

/// Errors from CI domain operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CiError {
    /// No CI platform could be detected from environment variables.
    #[error("CI environment not detected")]
    EnvironmentNotDetected,

    /// The identity bundle at the given path is not a valid git repository.
    #[error("identity bundle invalid at {path}: {reason}")]
    IdentityBundleInvalid {
        /// Path to the invalid identity bundle.
        path: PathBuf,
        /// What was wrong with it.
        reason: String,
    },

    /// No artifacts were provided to sign.
    #[error("no artifacts to sign")]
    NoArtifacts,

    /// Failed to create the attestation collection directory.
    #[error("failed to create attestation directory {path}: {reason}")]
    CollectionDirFailed {
        /// Path that could not be created.
        path: PathBuf,
        /// Underlying error.
        reason: String,
    },

    /// Failed to copy an attestation file to the collection directory.
    #[error("failed to collect attestation {src} → {dst}: {reason}")]
    CollectionCopyFailed {
        /// Source attestation file.
        src: PathBuf,
        /// Destination path.
        dst: PathBuf,
        /// Underlying error.
        reason: String,
    },
}

impl auths_core::error::AuthsErrorInfo for CiError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::EnvironmentNotDetected => "AUTHS-E7001",
            Self::IdentityBundleInvalid { .. } => "AUTHS-E7002",
            Self::NoArtifacts => "AUTHS-E7003",
            Self::CollectionDirFailed { .. } => "AUTHS-E7004",
            Self::CollectionCopyFailed { .. } => "AUTHS-E7005",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::EnvironmentNotDetected => {
                Some("Set CI-specific environment variables or pass --ci-environment explicitly")
            }
            Self::IdentityBundleInvalid { .. } => {
                Some("Re-run `just ci-setup` to regenerate the identity bundle secret")
            }
            Self::NoArtifacts => Some("Check your glob pattern matches at least one file"),
            Self::CollectionDirFailed { .. } => {
                Some("Check directory permissions and that the path is writable")
            }
            Self::CollectionCopyFailed { .. } => {
                Some("Check file permissions and available disk space")
            }
        }
    }
}
