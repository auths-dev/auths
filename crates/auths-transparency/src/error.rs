/// Errors from transparency log operations.
#[derive(Debug, Clone, thiserror::Error)]
#[allow(missing_docs)]
pub enum TransparencyError {
    /// Invalid Merkle proof structure.
    #[error("invalid proof: {0}")]
    InvalidProof(String),

    /// Merkle root mismatch during verification.
    #[error("root mismatch: expected {expected}, got {actual}")]
    RootMismatch { expected: String, actual: String },

    /// Invalid signed note format.
    #[error("invalid note: {0}")]
    InvalidNote(String),

    /// Signature verification failed on a checkpoint note.
    #[error("invalid checkpoint signature")]
    InvalidCheckpointSignature,

    /// Tile path encoding error.
    #[error("invalid tile path: {0}")]
    InvalidTilePath(String),

    /// Invalid log origin string.
    #[error("invalid log origin: {0}")]
    InvalidOrigin(String),

    /// Entry serialization or deserialization failure.
    #[error("entry error: {0}")]
    EntryError(String),

    /// Consistency proof verification failed.
    #[error("consistency check failed: {0}")]
    ConsistencyError(String),

    /// Storage backend error.
    #[error("store error: {0}")]
    StoreError(String),
}

/// Convenience alias for transparency operations.
pub type Result<T> = std::result::Result<T, TransparencyError>;
