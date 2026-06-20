use auths_verifier::types::DidParseError;
use thiserror::Error;

/// Errors that can occur when working with the attestation index.
#[derive(Error, Debug)]
pub enum IndexError {
    #[error("Database error: {0}")]
    Database(#[from] sqlite::Error),

    #[error("Invalid DID in index data: {0}")]
    InvalidDid(#[from] DidParseError),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Git error: {0}")]
    Git(#[from] git2::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Index not found at path: {0}")]
    NotFound(String),

    #[error("Invalid attestation data: {0}")]
    InvalidData(String),

    /// Repo holds refs under the deprecated `refs/auths/devices/nodes/*`
    /// namespace. Pre-launch we hard-break; the message suggests a reset.
    #[error("{0}")]
    DeprecatedPrefix(String),
}

pub type Result<T> = std::result::Result<T, IndexError>;
