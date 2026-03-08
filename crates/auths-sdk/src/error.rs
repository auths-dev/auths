use auths_core::error::AuthsErrorInfo;
use thiserror::Error;

/// Typed storage errors originating from the `auths-id` layer.
///
/// Usage:
/// ```ignore
/// storage.save(data)
///     .map_err(|e| SetupError::StorageError(e.into()))?;
/// ```
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SdkStorageError {
    /// Identity or attestation storage operation failed (identity layer).
    #[error(transparent)]
    Identity(#[from] auths_id::error::StorageError),

    /// Identity initialization failed.
    #[error(transparent)]
    Init(#[from] auths_id::error::InitError),

    /// Agent provisioning failed.
    #[error(transparent)]
    AgentProvisioning(#[from] auths_id::agent_identity::AgentProvisioningError),

    /// Driver-level storage operation failed.
    #[error(transparent)]
    Driver(#[from] auths_id::storage::StorageError),

    /// Attestation creation failed.
    #[error(transparent)]
    Attestation(#[from] auths_verifier::error::AttestationError),
}

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
    StorageError(#[source] SdkStorageError),

    /// Setting a git configuration key failed.
    #[error("git config error: {0}")]
    GitConfigError(String),

    /// Remote registry registration failed.
    #[error("registration failed: {0}")]
    RegistrationFailed(#[source] RegistrationError),

    /// Platform identity verification failed.
    #[error("platform verification failed: {0}")]
    PlatformVerificationFailed(String),
}

/// Errors from device linking and revocation operations.
///
/// Usage:
/// ```ignore
/// match link_result {
///     Err(DeviceError::IdentityNotFound { did }) => { /* identity missing */ }
///     Err(e) => return Err(e.into()),
///     Ok(result) => { /* success */ }
/// }
/// ```
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DeviceError {
    /// The identity could not be found in storage.
    #[error("identity not found: {did}")]
    IdentityNotFound {
        /// The DID that was not found.
        did: String,
    },

    /// The device could not be found in attestation records.
    #[error("device not found: {did}")]
    DeviceNotFound {
        /// The DID of the missing device.
        did: String,
    },

    /// Attestation creation or validation failed.
    #[error("attestation error: {0}")]
    AttestationError(String),

    /// A cryptographic operation failed.
    #[error("crypto error: {0}")]
    CryptoError(#[source] auths_core::AgentError),

    /// A storage operation failed.
    #[error("storage error: {0}")]
    StorageError(#[source] SdkStorageError),
}

/// Errors from device authorization extension operations.
///
/// Usage:
/// ```ignore
/// match extend_result {
///     Err(DeviceExtensionError::AlreadyRevoked { device_did }) => { /* already gone */ }
///     Err(e) => return Err(e.into()),
///     Ok(result) => { /* success */ }
/// }
/// ```
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DeviceExtensionError {
    /// The identity could not be found in storage.
    #[error("identity not found")]
    IdentityNotFound,

    /// No attestation exists for the specified device.
    #[error("no attestation found for device {device_did}")]
    NoAttestationFound {
        /// The DID of the device with no attestation.
        device_did: String,
    },

    /// The device has already been revoked.
    #[error("device {device_did} is already revoked")]
    AlreadyRevoked {
        /// The DID of the revoked device.
        device_did: String,
    },

    /// Creating a new attestation failed.
    #[error("attestation creation failed: {0}")]
    AttestationFailed(String),

    /// A storage operation failed.
    #[error("storage error: {0}")]
    StorageError(#[source] SdkStorageError),
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

    /// Local identity or attestation data is invalid.
    #[error("local data error: {0}")]
    LocalDataError(String),
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

impl From<auths_core::AgentError> for DeviceError {
    fn from(err: auths_core::AgentError) -> Self {
        DeviceError::CryptoError(err)
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
            Self::IdentityAlreadyExists { .. } => "AUTHS_IDENTITY_ALREADY_EXISTS",
            Self::KeychainUnavailable { .. } => "AUTHS_KEYCHAIN_UNAVAILABLE",
            Self::CryptoError(e) => e.error_code(),
            Self::StorageError(_) => "AUTHS_SETUP_STORAGE_ERROR",
            Self::GitConfigError(_) => "AUTHS_GIT_CONFIG_ERROR",
            Self::RegistrationFailed(_) => "AUTHS_REGISTRATION_FAILED",
            Self::PlatformVerificationFailed(_) => "AUTHS_PLATFORM_VERIFICATION_FAILED",
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
            Self::RegistrationFailed(_) => Some("Check network connectivity and try again"),
            Self::PlatformVerificationFailed(_) => None,
        }
    }
}

impl AuthsErrorInfo for DeviceError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::IdentityNotFound { .. } => "AUTHS_IDENTITY_NOT_FOUND",
            Self::DeviceNotFound { .. } => "AUTHS_DEVICE_NOT_FOUND",
            Self::AttestationError(_) => "AUTHS_ATTESTATION_ERROR",
            Self::CryptoError(e) => e.error_code(),
            Self::StorageError(_) => "AUTHS_DEVICE_STORAGE_ERROR",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::IdentityNotFound { .. } => Some("Run `auths init` to create an identity first"),
            Self::DeviceNotFound { .. } => Some("Run `auths device list` to see linked devices"),
            Self::AttestationError(_) => None,
            Self::CryptoError(e) => e.suggestion(),
            Self::StorageError(_) => Some("Check file permissions and disk space"),
        }
    }
}

/// Errors from MCP token exchange operations.
///
/// Usage:
/// ```ignore
/// match result {
///     Err(McpAuthError::BridgeUnreachable(msg)) => { /* retry later */ }
///     Err(McpAuthError::InsufficientCapabilities { .. }) => { /* request fewer caps */ }
///     Err(e) => return Err(e.into()),
///     Ok(token) => { /* use token */ }
/// }
/// ```
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum McpAuthError {
    /// The OIDC bridge is unreachable.
    #[error("bridge unreachable: {0}")]
    BridgeUnreachable(String),

    /// The bridge returned a non-success status.
    #[error("token exchange failed (HTTP {status}): {body}")]
    TokenExchangeFailed {
        /// HTTP status code from the bridge.
        status: u16,
        /// Response body.
        body: String,
    },

    /// The bridge response could not be parsed.
    #[error("invalid response: {0}")]
    InvalidResponse(String),

    /// The bridge rejected the requested capabilities.
    #[error("insufficient capabilities: requested {requested:?}")]
    InsufficientCapabilities {
        /// The capabilities that were requested.
        requested: Vec<String>,
        /// Detail from the bridge error response.
        detail: String,
    },
}

/// Errors from organization member management workflows.
///
/// Usage:
/// ```ignore
/// match result {
///     Err(OrgError::AdminNotFound { .. }) => { /* 403 Forbidden */ }
///     Err(OrgError::MemberNotFound { .. }) => { /* 404 Not Found */ }
///     Err(e) => return Err(e.into()),
///     Ok(att) => { /* proceed */ }
/// }
/// ```
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum OrgError {
    /// No admin matching the given public key was found in the organization.
    #[error("no admin with the given public key found in organization '{org}'")]
    AdminNotFound {
        /// The organization identifier.
        org: String,
    },

    /// The specified member was not found in the organization.
    #[error("member '{did}' not found in organization '{org}'")]
    MemberNotFound {
        /// The organization identifier.
        org: String,
        /// The DID of the member that was not found.
        did: String,
    },

    /// The member has already been revoked.
    #[error("member '{did}' is already revoked")]
    AlreadyRevoked {
        /// The DID of the already-revoked member.
        did: String,
    },

    /// The capability string could not be parsed.
    #[error("invalid capability '{cap}': {reason}")]
    InvalidCapability {
        /// The invalid capability string.
        cap: String,
        /// The reason parsing failed.
        reason: String,
    },

    /// The organization DID is malformed.
    #[error("invalid organization DID: {0}")]
    InvalidDid(String),

    /// The hex-encoded public key is invalid.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    /// A signing operation failed while creating or revoking an attestation.
    #[error("signing error: {0}")]
    Signing(String),

    /// The identity could not be loaded from storage.
    #[error("identity error: {0}")]
    Identity(String),

    /// A key storage operation failed.
    #[error("key storage error: {0}")]
    KeyStorage(String),

    // TECH-DEBT(fn-33): migrate Storage(String) to typed SdkStorageError variant
    // (call sites in workflows/org.rs, not in the fn-33.1 scope)
    /// A storage operation failed.
    #[error("storage error: {0}")]
    Storage(String),
}

/// Re-export from `auths-core` — defined there to avoid a circular dependency with
/// `auths-infra-http` (which implements the platform port traits).
pub use auths_core::ports::platform::PlatformError;

/// Errors from approval workflow operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ApprovalError {
    /// The decision is not RequiresApproval.
    #[error("decision is not RequiresApproval")]
    NotApprovalRequired,

    /// Approval request not found.
    #[error("approval request not found: {hash}")]
    RequestNotFound {
        /// The hex-encoded request hash.
        hash: String,
    },

    /// Approval request expired.
    #[error("approval request expired at {expires_at}")]
    RequestExpired {
        /// When the request expired.
        expires_at: chrono::DateTime<chrono::Utc>,
    },

    /// Approval JTI already used (replay attempt).
    #[error("approval already used (JTI: {jti})")]
    ApprovalAlreadyUsed {
        /// The consumed JTI.
        jti: String,
    },

    /// Approval partially applied — attestation stored but nonce/cleanup failed.
    #[error("approval partially applied — attestation stored but nonce/cleanup failed: {0}")]
    PartialApproval(String),

    // TECH-DEBT(fn-33): migrate ApprovalStorage(String) to typed SdkStorageError variant
    /// A storage operation failed.
    #[error("storage error: {0}")]
    ApprovalStorage(String),
}
