use auths_core::error::AuthsErrorInfo;
use thiserror::Error;

/// Errors from identity setup operations (developer, CI, agent).
///
/// Usage:
/// ```ignore
/// match sdk_result {
///     Err(SetupError::IdentityAlreadyExists { did }) => { /* reuse or abort */ }
///     Err(e) => return Err(e.into()),
///     Ok(result) => { /* success */ }
/// }
/// ```
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SetupError {
    /// An identity already exists at the configured path.
    #[error("identity already exists: {did}")]
    IdentityAlreadyExists {
        /// The DID of the existing identity.
        did: String,
    },

    /// The platform keychain is unavailable or inaccessible.
    #[error("keychain unavailable ({backend}): {reason}")]
    KeychainUnavailable {
        /// The keychain backend name (e.g. "macOS Keychain").
        backend: String,
        /// The reason the keychain is unavailable.
        reason: String,
    },

    /// A cryptographic operation failed.
    #[error("crypto error: {0}")]
    CryptoError(#[source] auths_core::AgentError),

    /// A storage operation failed.
    #[error("storage error: {0}")]
    StorageError(#[source] crate::error::SdkStorageError),

    /// Setting a git configuration key failed.
    #[error("git config error: {0}")]
    GitConfigError(#[source] crate::ports::git_config::GitConfigError),

    /// Setup configuration parameters are invalid.
    #[error("invalid setup config: {0}")]
    InvalidSetupConfig(String),

    /// Remote registry registration failed.
    #[error("registration failed: {0}")]
    RegistrationFailed(#[source] RegistrationError),

    /// Platform identity verification failed.
    #[error("platform verification failed: {0}")]
    PlatformVerificationFailed(String),
}

/// Errors from identity rotation operations.
///
/// Usage:
/// ```ignore
/// match rotate_result {
///     Err(RotationError::KelHistoryFailed(msg)) => { /* no prior events */ }
///     Err(e) => return Err(e.into()),
///     Ok(result) => { /* success */ }
/// }
/// ```
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RotationError {
    /// The identity was not found at the expected path.
    #[error("identity not found at {path}")]
    IdentityNotFound {
        /// The filesystem path where the identity was expected.
        path: std::path::PathBuf,
    },

    /// The requested key alias was not found in the keychain.
    #[error("key not found: {0}")]
    KeyNotFound(String),

    /// Decrypting the key material failed (e.g. wrong passphrase).
    #[error("key decryption failed: {0}")]
    KeyDecryptionFailed(String),

    /// Reading or validating the KEL history failed.
    #[error("KEL history error: {0}")]
    KelHistoryFailed(String),

    /// The rotation operation failed.
    #[error("rotation failed: {0}")]
    RotationFailed(String),

    /// KEL event was written but the new key could not be persisted to the keychain.
    /// Recovery: re-run rotation with the same new key to replay the keychain write.
    #[error(
        "rotation event committed to KEL but keychain write failed — manual recovery required: {0}"
    )]
    PartialRotation(String),
}

/// Errors from remote registry operations.
///
/// Usage:
/// ```ignore
/// match register_result {
///     Err(RegistrationError::AlreadyRegistered) => { /* skip */ }
///     Err(RegistrationError::QuotaExceeded) => { /* retry later */ }
///     Err(e) => return Err(e.into()),
///     Ok(outcome) => { /* success */ }
/// }
/// ```
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RegistrationError {
    /// The identity is already registered at the target registry.
    #[error("identity already registered at this registry")]
    AlreadyRegistered,

    /// The registration rate limit has been exceeded.
    #[error("registration quota exceeded — try again later")]
    QuotaExceeded,

    /// A network error occurred during registration.
    #[error("network error: {0}")]
    NetworkError(#[source] auths_core::ports::network::NetworkError),

    /// The local DID format is invalid.
    #[error("invalid DID format: {did}")]
    InvalidDidFormat {
        /// The DID that failed validation.
        did: String,
    },

    /// Loading the local identity failed.
    #[error("identity load error: {0}")]
    IdentityLoadError(#[source] auths_id::error::StorageError),

    /// Reading from the local registry failed.
    #[error("registry read error: {0}")]
    RegistryReadError(#[source] auths_id::storage::registry::backend::RegistryError),

    /// Serialization of identity data failed.
    #[error("serialization error: {0}")]
    SerializationError(#[source] serde_json::Error),
}

impl From<auths_core::AgentError> for SetupError {
    fn from(err: auths_core::AgentError) -> Self {
        SetupError::CryptoError(err)
    }
}

impl From<RegistrationError> for SetupError {
    fn from(err: RegistrationError) -> Self {
        SetupError::RegistrationFailed(err)
    }
}

impl From<auths_core::ports::network::NetworkError> for RegistrationError {
    fn from(err: auths_core::ports::network::NetworkError) -> Self {
        RegistrationError::NetworkError(err)
    }
}

impl AuthsErrorInfo for SetupError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::IdentityAlreadyExists { .. } => "AUTHS-E5001",
            Self::KeychainUnavailable { .. } => "AUTHS-E5002",
            Self::CryptoError(e) => e.error_code(),
            Self::StorageError(_) => "AUTHS-E5003",
            Self::GitConfigError(_) => "AUTHS-E5004",
            Self::InvalidSetupConfig(_) => "AUTHS-E5007",
            Self::RegistrationFailed(_) => "AUTHS-E5005",
            Self::PlatformVerificationFailed(_) => "AUTHS-E5006",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::IdentityAlreadyExists { .. } => {
                Some("Use `auths id show` to inspect the existing identity")
            }
            Self::KeychainUnavailable { .. } => {
                Some("Run `auths doctor` to diagnose keychain issues")
            }
            Self::CryptoError(e) => e.suggestion(),
            Self::StorageError(_) => Some("Check file permissions and disk space"),
            Self::GitConfigError(_) => {
                Some("Ensure Git is configured: git config --global user.name/email")
            }
            Self::InvalidSetupConfig(_) => Some("Check identity setup configuration parameters"),
            Self::RegistrationFailed(_) => Some("Check network connectivity and try again"),
            Self::PlatformVerificationFailed(_) => Some(
                "Platform identity verification failed; check your platform credentials and network connectivity",
            ),
        }
    }
}

impl AuthsErrorInfo for RotationError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::IdentityNotFound { .. } => "AUTHS-E5301",
            Self::KeyNotFound(_) => "AUTHS-E5302",
            Self::KeyDecryptionFailed(_) => "AUTHS-E5303",
            Self::KelHistoryFailed(_) => "AUTHS-E5304",
            Self::RotationFailed(_) => "AUTHS-E5305",
            Self::PartialRotation(_) => "AUTHS-E5306",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::IdentityNotFound { .. } => Some("Run `auths init` to create an identity first"),
            Self::KeyNotFound(_) => Some("Run `auths key list` to see available keys"),
            Self::KeyDecryptionFailed(_) => Some("Check your passphrase and try again"),
            Self::KelHistoryFailed(_) => Some("Run `auths doctor` to check KEL integrity"),
            Self::RotationFailed(_) => Some(
                "Key rotation failed; verify your current key is accessible with `auths key list`",
            ),
            Self::PartialRotation(_) => {
                Some("Re-run the rotation with the same new key to complete the keychain write")
            }
        }
    }
}

impl AuthsErrorInfo for RegistrationError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::AlreadyRegistered => "AUTHS-E5401",
            Self::QuotaExceeded => "AUTHS-E5402",
            Self::NetworkError(e) => e.error_code(),
            Self::InvalidDidFormat { .. } => "AUTHS-E5403",
            Self::IdentityLoadError(_) => "AUTHS-E5404",
            Self::RegistryReadError(_) => "AUTHS-E5405",
            Self::SerializationError(_) => "AUTHS-E5406",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::AlreadyRegistered => Some(
                "This identity is already registered; use `auths id show` to see registration details",
            ),
            Self::QuotaExceeded => Some("Wait a few minutes and try again"),
            Self::NetworkError(e) => e.suggestion(),
            Self::InvalidDidFormat { .. } => {
                Some("Run `auths doctor` to check local identity data")
            }
            Self::IdentityLoadError(_) => Some("Run `auths doctor` to check local identity data"),
            Self::RegistryReadError(_) => Some("Run `auths doctor` to check local identity data"),
            Self::SerializationError(_) => Some("Run `auths doctor` to check local identity data"),
        }
    }
}
