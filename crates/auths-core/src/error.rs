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
            Self::KeyNotFound => "AUTHS-E3001",
            Self::IncorrectPassphrase => "AUTHS-E3002",
            Self::MissingPassphrase => "AUTHS-E3003",
            Self::SecurityError(_) => "AUTHS-E3004",
            Self::CryptoError(_) => "AUTHS-E3005",
            Self::KeyDeserializationError(_) => "AUTHS-E3006",
            Self::SigningFailed(_) => "AUTHS-E3007",
            Self::Proto(_) => "AUTHS-E3008",
            Self::IO(_) => "AUTHS-E3009",
            Self::GitError(_) => "AUTHS-E3010",
            Self::InvalidInput(_) => "AUTHS-E3011",
            Self::MutexError(_) => "AUTHS-E3012",
            Self::StorageError(_) => "AUTHS-E3013",
            Self::UserInputCancelled => "AUTHS-E3014",
            Self::BackendUnavailable { .. } => "AUTHS-E3015",
            Self::StorageLocked => "AUTHS-E3016",
            Self::BackendInitFailed { .. } => "AUTHS-E3017",
            Self::CredentialTooLarge { .. } => "AUTHS-E3018",
            Self::AgentLocked => "AUTHS-E3019",
            Self::WeakPassphrase(_) => "AUTHS-E3020",
            Self::HsmPinLocked => "AUTHS-E3021",
            Self::HsmDeviceRemoved => "AUTHS-E3022",
            Self::HsmSessionExpired => "AUTHS-E3023",
            Self::HsmUnsupportedMechanism(_) => "AUTHS-E3024",
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
            Self::SecurityError(_) => Some(
                "Run `auths doctor` to check system keychain access and security configuration",
            ),
            Self::CryptoError(_) => {
                Some("A cryptographic operation failed; check key material with `auths key list`")
            }
            Self::KeyDeserializationError(_) => {
                Some("The stored key is corrupted; re-import with `auths key import`")
            }
            Self::SigningFailed(_) => Some(
                "The signing operation failed; verify your key is accessible with `auths key list`",
            ),
            Self::Proto(_) => Some(
                "A protocol error occurred; check that both sides are running compatible versions",
            ),
            Self::IO(_) => Some("Check file permissions and that the filesystem is not read-only"),
            Self::InvalidInput(_) => Some("Check the command arguments and try again"),
            Self::MutexError(_) => Some("A concurrency error occurred; restart the operation"),
            Self::CredentialTooLarge { .. } => Some(
                "Reduce the credential size or use file-based storage with AUTHS_KEYCHAIN_BACKEND=file",
            ),
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
            Self::Io(_) => "AUTHS-E3101",
            Self::InvalidData(_) => "AUTHS-E3102",
            Self::NotFound(_) => "AUTHS-E3103",
            Self::Serialization(_) => "AUTHS-E3104",
            Self::AlreadyExists(_) => "AUTHS-E3105",
            Self::Lock(_) => "AUTHS-E3106",
            Self::PolicyRejected(_) => "AUTHS-E3107",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::NotFound(_) => Some("Run `auths trust list` to see pinned identities"),
            Self::PolicyRejected(_) => Some("Run `auths trust add` to pin this identity"),
            Self::Lock(_) => Some("Check file permissions and try again"),
            Self::Io(_) => Some("Check disk space and file permissions"),
            Self::AlreadyExists(_) => Some("Run `auths trust list` to see existing entries"),
            Self::InvalidData(_) => {
                Some("The trust store may be corrupted; delete and re-pin with `auths trust add`")
            }
            Self::Serialization(_) => {
                Some("The trust store data is corrupted; delete and re-pin with `auths trust add`")
            }
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
