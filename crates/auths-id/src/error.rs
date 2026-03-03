use thiserror::Error;

#[derive(Debug, Error)]
pub enum FreezeError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("failed to parse freeze state: {0}")]
    Deserialization(#[from] serde_json::Error),
    #[error("invalid duration format: {0}")]
    InvalidDuration(String),
    #[error("duration must be greater than zero")]
    ZeroDuration,
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[cfg(feature = "git-storage")]
    #[error(transparent)]
    Git(#[from] git2::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("{0}")]
    InvalidData(String),
    #[error("schema validation failed: {0}")]
    SchemaValidation(String),
    #[error("index error: {0}")]
    Index(String),
}

#[derive(Debug, Error)]
pub enum InitError {
    #[cfg(feature = "git-storage")]
    #[error(transparent)]
    Git(#[from] git2::Error),
    #[error("KERI operation failed: {0}")]
    Keri(String),
    #[error("key operation failed: {0}")]
    Key(#[from] auths_core::error::AgentError),
    #[error("{0}")]
    InvalidData(String),
    #[error("storage operation failed: {0}")]
    Storage(#[from] StorageError),
    #[error("registry error: {0}")]
    Registry(String),
    #[error("crypto operation failed: {0}")]
    Crypto(String),
    #[error("identity error: {0}")]
    Identity(#[from] crate::identity::helpers::IdentityError),
}
