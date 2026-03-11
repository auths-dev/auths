use auths_core::error::AuthsErrorInfo;
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
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
#[non_exhaustive]
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
#[non_exhaustive]
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

impl AuthsErrorInfo for FreezeError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::Io(_) => "AUTHS-E4001",
            Self::Deserialization(_) => "AUTHS-E4002",
            Self::InvalidDuration(_) => "AUTHS-E4003",
            Self::ZeroDuration => "AUTHS-E4004",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::Io(_) => Some("Check file permissions and disk space"),
            Self::Deserialization(_) => {
                Some("The freeze state file may be corrupted; try deleting it")
            }
            Self::InvalidDuration(_) => {
                Some("Use a valid duration format (e.g. '30m', '2h', '7d')")
            }
            Self::ZeroDuration => Some("Specify a positive duration"),
        }
    }
}

impl AuthsErrorInfo for StorageError {
    fn error_code(&self) -> &'static str {
        match self {
            #[cfg(feature = "git-storage")]
            Self::Git(_) => "AUTHS-E4101",
            Self::Serialization(_) => "AUTHS-E4102",
            Self::Io(_) => "AUTHS-E4103",
            Self::NotFound(_) => "AUTHS-E4104",
            Self::InvalidData(_) => "AUTHS-E4105",
            Self::SchemaValidation(_) => "AUTHS-E4106",
            Self::Index(_) => "AUTHS-E4107",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            #[cfg(feature = "git-storage")]
            Self::Git(_) => Some("Check that the Git repository is not corrupted"),
            Self::Serialization(_) => None,
            Self::Io(_) => Some("Check file permissions and disk space"),
            Self::NotFound(_) => Some("Verify the identity or resource exists"),
            Self::InvalidData(_) => Some("The stored data may be corrupted; try re-initializing"),
            Self::SchemaValidation(_) => Some("Ensure data matches the expected schema version"),
            Self::Index(_) => Some("Try rebuilding the index"),
        }
    }
}

impl AuthsErrorInfo for InitError {
    fn error_code(&self) -> &'static str {
        match self {
            #[cfg(feature = "git-storage")]
            Self::Git(_) => "AUTHS-E4201",
            Self::Keri(_) => "AUTHS-E4202",
            Self::Key(_) => "AUTHS-E4203",
            Self::InvalidData(_) => "AUTHS-E4204",
            Self::Storage(_) => "AUTHS-E4205",
            Self::Registry(_) => "AUTHS-E4206",
            Self::Crypto(_) => "AUTHS-E4207",
            Self::Identity(_) => "AUTHS-E4208",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            #[cfg(feature = "git-storage")]
            Self::Git(_) => Some("Check that the Git repository is accessible"),
            Self::Keri(_) => Some("KERI event processing failed; check identity state"),
            Self::Key(_) => Some("Check keychain access and passphrase"),
            Self::InvalidData(_) => None,
            Self::Storage(_) => Some("Check storage backend connectivity"),
            Self::Registry(_) => Some("Check registry backend configuration"),
            Self::Crypto(_) => None,
            Self::Identity(_) => None,
        }
    }
}
