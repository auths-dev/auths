use thiserror::Error;

/// Errors that can occur when working with the attestation index.
#[derive(Error, Debug)]
pub enum IndexError {
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

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
}

pub type Result<T> = std::result::Result<T, IndexError>;
