//! Error types for agent and core operations.

use thiserror::Error;

pub use auths_crypto::AuthsErrorInfo;

/// Errors from the Auths agent and core operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AgentError {
    /// The requested key was not found.
    #[error("Key not found")]
    KeyNotFound,

    /// The provided passphrase is incorrect.
    #[error("Incorrect passphrase")]
    IncorrectPassphrase,

    /// A passphrase is required but was not provided.
    #[error("Missing Passphrase")]
    MissingPassphrase,

    /// A platform security framework error occurred.
    #[error("Security error: {0}")]
    SecurityError(String),

    /// A cryptographic operation failed.
    #[error("Crypto error: {0}")]
    CryptoError(String),

    /// Failed to deserialize a key.
    #[error("Key deserialization error: {0}")]
    KeyDeserializationError(String),

    /// Signing operation failed.
    #[error("Signing failed: {0}")]
    SigningFailed(String),

    /// A protocol error occurred.
    #[error("Protocol error: {0}")]
    Proto(String),

    /// An I/O error occurred.
    #[error("IO error: {0}")]
    IO(#[from] std::io::Error),

    /// A Git operation failed.
    #[error("git error: {0}")]
    GitError(String),

    /// Invalid input was provided.
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// A mutex lock was poisoned.
    #[error("Mutex lock poisoned: {0}")]
    MutexError(String),

    /// A storage operation failed.
    #[error("Storage error: {0}")]
    StorageError(String),

    /// The user cancelled an interactive prompt.
    #[error("User input cancelled")]
    UserInputCancelled,

    // --- Platform backend errors ---
    /// Backend is not available on this platform or configuration
    #[error("Keychain backend unavailable: {backend} - {reason}")]
    BackendUnavailable {
        /// Name of the failing backend.
        backend: &'static str,
        /// Reason the backend is unavailable.
        reason: String,
    },

    /// Storage is locked and requires authentication
    #[error("Storage is locked, authentication required")]
    StorageLocked,

    /// Backend initialization failed
    #[error("Failed to initialize keychain backend: {backend} - {error}")]
    BackendInitFailed {
        /// Name of the failing backend.
        backend: &'static str,
        /// Initialization error message.
        error: String,
    },

    /// Credential size exceeds platform limit
    #[error("Credential too large for backend (max {max_bytes} bytes, got {actual_bytes})")]
    CredentialTooLarge {
        /// Maximum credential size in bytes.
        max_bytes: usize,
        /// Actual credential size in bytes.
        actual_bytes: usize,
    },

    /// Agent is locked due to idle timeout
    #[error("Agent is locked. Unlock with 'auths agent unlock' or restart the agent.")]
    AgentLocked,

    /// The passphrase does not meet strength requirements.
    #[error("Passphrase too weak: {0}")]
    WeakPassphrase(String),

    // --- HSM / PKCS#11 errors ---
    /// HSM PIN is locked after too many failed attempts.
    #[error("HSM PIN is locked — reset required")]
    HsmPinLocked,

    /// HSM device was removed during operation.
    #[error("HSM device removed")]
    HsmDeviceRemoved,

    /// HSM session expired or was closed unexpectedly.
    #[error("HSM session expired")]
    HsmSessionExpired,

    /// HSM does not support the requested cryptographic mechanism.
    #[error("HSM does not support mechanism: {0}")]
    HsmUnsupportedMechanism(String),
}

impl AuthsErrorInfo for AgentError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::KeyNotFound => "AUTHS_KEY_NOT_FOUND",
            Self::IncorrectPassphrase => "AUTHS_INCORRECT_PASSPHRASE",
            Self::MissingPassphrase => "AUTHS_MISSING_PASSPHRASE",
            Self::SecurityError(_) => "AUTHS_SECURITY_ERROR",
            Self::CryptoError(_) => "AUTHS_CRYPTO_ERROR",
            Self::KeyDeserializationError(_) => "AUTHS_KEY_DESERIALIZATION_ERROR",
            Self::SigningFailed(_) => "AUTHS_SIGNING_FAILED",
            Self::Proto(_) => "AUTHS_PROTOCOL_ERROR",
            Self::IO(_) => "AUTHS_IO_ERROR",
            Self::GitError(_) => "AUTHS_GIT_ERROR",
            Self::InvalidInput(_) => "AUTHS_INVALID_INPUT",
            Self::MutexError(_) => "AUTHS_MUTEX_ERROR",
            Self::StorageError(_) => "AUTHS_STORAGE_ERROR",
            Self::UserInputCancelled => "AUTHS_USER_CANCELLED",
            Self::BackendUnavailable { .. } => "AUTHS_BACKEND_UNAVAILABLE",
            Self::StorageLocked => "AUTHS_STORAGE_LOCKED",
            Self::BackendInitFailed { .. } => "AUTHS_BACKEND_INIT_FAILED",
            Self::CredentialTooLarge { .. } => "AUTHS_CREDENTIAL_TOO_LARGE",
            Self::AgentLocked => "AUTHS_AGENT_LOCKED",
            Self::WeakPassphrase(_) => "AUTHS_WEAK_PASSPHRASE",
            Self::HsmPinLocked => "AUTHS_HSM_PIN_LOCKED",
            Self::HsmDeviceRemoved => "AUTHS_HSM_DEVICE_REMOVED",
            Self::HsmSessionExpired => "AUTHS_HSM_SESSION_EXPIRED",
            Self::HsmUnsupportedMechanism(_) => "AUTHS_HSM_UNSUPPORTED_MECHANISM",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::KeyNotFound => Some("Run `auths key list` to see available keys"),
            Self::IncorrectPassphrase => Some("Check your passphrase and try again"),
            Self::MissingPassphrase => {
                Some("Provide a passphrase with --passphrase or set AUTHS_PASSPHRASE")
            }
            Self::BackendUnavailable { .. } => {
                Some("Run `auths doctor` to diagnose keychain issues")
            }
            Self::StorageLocked => Some("Authenticate with your platform keychain"),
            Self::BackendInitFailed { .. } => {
                Some("Run `auths doctor` to diagnose keychain issues")
            }
            Self::GitError(_) => Some("Ensure you're in a Git repository"),
            Self::AgentLocked => {
                Some("Run `auths agent unlock` or restart with `auths agent start`")
            }
            Self::UserInputCancelled => {
                Some("Run the command again and provide the required input")
            }
            Self::StorageError(_) => Some("Check file permissions and disk space"),
            // These errors typically don't have actionable suggestions
            Self::SecurityError(_)
            | Self::CryptoError(_)
            | Self::KeyDeserializationError(_)
            | Self::SigningFailed(_)
            | Self::Proto(_)
            | Self::IO(_)
            | Self::InvalidInput(_)
            | Self::MutexError(_)
            | Self::CredentialTooLarge { .. } => None,
            Self::WeakPassphrase(_) => {
                Some("Use at least 12 characters with uppercase, lowercase, and a digit or symbol")
            }
            Self::HsmPinLocked => Some("Reset the HSM PIN using your HSM vendor's admin tools"),
            Self::HsmDeviceRemoved => Some("Reconnect the HSM device and try again"),
            Self::HsmSessionExpired => Some("Retry the operation — a new session will be opened"),
            Self::HsmUnsupportedMechanism(_) => {
                Some("Check that your HSM supports Ed25519 (CKM_EDDSA)")
            }
        }
    }
}

/// Errors from trust resolution and identity pinning.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TrustError {
    /// An I/O error occurred.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Invalid data encountered (corrupt pin, bad hex, wrong format).
    #[error("{0}")]
    InvalidData(String),
    /// A required resource was not found.
    #[error("not found: {0}")]
    NotFound(String),
    /// JSON serialization/deserialization failed.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    /// Attempted to create something that already exists.
    #[error("already exists: {0}")]
    AlreadyExists(String),
    /// Advisory file lock could not be acquired.
    #[error("lock acquisition failed: {0}")]
    Lock(String),
    /// Trust policy rejected the identity.
    #[error("policy rejected: {0}")]
    PolicyRejected(String),
}

impl AuthsErrorInfo for TrustError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::Io(_) => "AUTHS_TRUST_IO_ERROR",
            Self::InvalidData(_) => "AUTHS_TRUST_INVALID_DATA",
            Self::NotFound(_) => "AUTHS_TRUST_NOT_FOUND",
            Self::Serialization(_) => "AUTHS_TRUST_SERIALIZATION_ERROR",
            Self::AlreadyExists(_) => "AUTHS_TRUST_ALREADY_EXISTS",
            Self::Lock(_) => "AUTHS_TRUST_LOCK_FAILED",
            Self::PolicyRejected(_) => "AUTHS_TRUST_POLICY_REJECTED",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::NotFound(_) => Some("Run `auths trust list` to see pinned identities"),
            Self::PolicyRejected(_) => Some("Run `auths trust add` to pin this identity"),
            Self::Lock(_) => Some("Check file permissions and try again"),
            Self::Io(_) => Some("Check disk space and file permissions"),
            Self::AlreadyExists(_) => Some("Run `auths trust list` to see existing entries"),
            Self::InvalidData(_) | Self::Serialization(_) => None,
        }
    }
}

impl From<AgentError> for ssh_agent_lib::error::AgentError {
    fn from(err: AgentError) -> Self {
        match err {
            AgentError::KeyNotFound => Self::Failure,
            AgentError::IncorrectPassphrase => Self::Failure,
            _ => Self::Failure,
        }
    }
}
