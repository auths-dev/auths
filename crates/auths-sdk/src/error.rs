use auths_core::error::AuthsErrorInfo;
use auths_verifier::types::DeviceDID;
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
    AttestationError(#[source] auths_verifier::error::AttestationError),

    /// The device DID derived from the key does not match the expected DID.
    #[error("device DID mismatch: expected {expected}, got {actual}")]
    DeviceDidMismatch {
        /// The expected device DID.
        expected: String,
        /// The actual device DID derived from the key.
        actual: String,
    },

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
        device_did: DeviceDID,
    },

    /// The device has already been revoked.
    #[error("device {device_did} is already revoked")]
    AlreadyRevoked {
        /// The DID of the revoked device.
        device_did: DeviceDID,
    },

    /// Creating a new attestation failed.
    #[error("attestation creation failed: {0}")]
    AttestationFailed(#[source] auths_verifier::error::AttestationError),

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

impl AuthsErrorInfo for DeviceError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::IdentityNotFound { .. } => "AUTHS-E5101",
            Self::DeviceNotFound { .. } => "AUTHS-E5102",
            Self::AttestationError(_) => "AUTHS-E5103",
            Self::DeviceDidMismatch { .. } => "AUTHS-E5105",
            Self::CryptoError(e) => e.error_code(),
            Self::StorageError(_) => "AUTHS-E5104",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::IdentityNotFound { .. } => Some("Run `auths init` to create an identity first"),
            Self::DeviceNotFound { .. } => Some("Run `auths device list` to see linked devices"),
            Self::AttestationError(_) => Some(
                "The attestation operation failed; run `auths device list` to check device status",
            ),
            Self::DeviceDidMismatch { .. } => Some("Check that --device-did matches the key alias"),
            Self::CryptoError(e) => e.suggestion(),
            Self::StorageError(_) => Some("Check file permissions and disk space"),
        }
    }
}

impl AuthsErrorInfo for DeviceExtensionError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::IdentityNotFound => "AUTHS-E5201",
            Self::NoAttestationFound { .. } => "AUTHS-E5202",
            Self::AlreadyRevoked { .. } => "AUTHS-E5203",
            Self::AttestationFailed(_) => "AUTHS-E5204",
            Self::StorageError(_) => "AUTHS-E5205",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::IdentityNotFound => Some("Run `auths init` to create an identity first"),
            Self::NoAttestationFound { .. } => {
                Some("Run `auths device link` to create an attestation for this device")
            }
            Self::AlreadyRevoked { .. } => Some(
                "This device has been revoked and cannot be extended; link a new device with `auths device link`",
            ),
            Self::AttestationFailed(_) => {
                Some("Failed to create the extension attestation; check key access and try again")
            }
            Self::StorageError(_) => Some("Check file permissions and disk space"),
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

impl AuthsErrorInfo for McpAuthError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::BridgeUnreachable(_) => "AUTHS-E5501",
            Self::TokenExchangeFailed { .. } => "AUTHS-E5502",
            Self::InvalidResponse(_) => "AUTHS-E5503",
            Self::InsufficientCapabilities { .. } => "AUTHS-E5504",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::BridgeUnreachable(_) => Some("Check network connectivity to the OIDC bridge"),
            Self::TokenExchangeFailed { .. } => Some("Verify your credentials and try again"),
            Self::InvalidResponse(_) => Some(
                "The OIDC bridge returned an unexpected response; verify the bridge URL and try again",
            ),
            Self::InsufficientCapabilities { .. } => {
                Some("Request fewer capabilities or contact your administrator")
            }
        }
    }
}

impl AuthsErrorInfo for OrgError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::AdminNotFound { .. } => "AUTHS-E5601",
            Self::MemberNotFound { .. } => "AUTHS-E5602",
            Self::AlreadyRevoked { .. } => "AUTHS-E5603",
            Self::InvalidCapability { .. } => "AUTHS-E5604",
            Self::InvalidDid(_) => "AUTHS-E5605",
            Self::InvalidPublicKey(_) => "AUTHS-E5606",
            Self::Signing(_) => "AUTHS-E5607",
            Self::Identity(_) => "AUTHS-E5608",
            Self::KeyStorage(_) => "AUTHS-E5609",
            Self::Storage(_) => "AUTHS-E5610",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::AdminNotFound { .. } => {
                Some("Verify you are using the correct admin key for this organization")
            }
            Self::MemberNotFound { .. } => {
                Some("Run `auths org list-members` to see current members")
            }
            Self::AlreadyRevoked { .. } => {
                Some("This member has already been revoked from the organization")
            }
            Self::InvalidCapability { .. } => {
                Some("Use a valid capability (e.g., 'sign_commit', 'manage_members', 'admin')")
            }
            Self::InvalidDid(_) => Some("Organization DIDs must be valid did:keri identifiers"),
            Self::InvalidPublicKey(_) => Some("Public keys must be hex-encoded Ed25519 keys"),
            Self::Signing(_) => {
                Some("The signing operation failed; check your key access with `auths key list`")
            }
            Self::Identity(_) => {
                Some("Failed to load identity; run `auths id show` to check identity status")
            }
            Self::KeyStorage(_) => {
                Some("Failed to access key storage; run `auths doctor` to diagnose")
            }
            Self::Storage(_) => {
                Some("Failed to access organization storage; check repository permissions")
            }
        }
    }
}

impl AuthsErrorInfo for ApprovalError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::NotApprovalRequired => "AUTHS-E5701",
            Self::RequestNotFound { .. } => "AUTHS-E5702",
            Self::RequestExpired { .. } => "AUTHS-E5703",
            Self::ApprovalAlreadyUsed { .. } => "AUTHS-E5704",
            Self::PartialApproval(_) => "AUTHS-E5705",
            Self::ApprovalStorage(_) => "AUTHS-E5706",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::NotApprovalRequired => Some(
                "This operation does not require approval; run it directly without the --approve flag",
            ),
            Self::RequestNotFound { .. } => {
                Some("Run `auths approval list` to see pending requests")
            }
            Self::RequestExpired { .. } => Some("Submit a new approval request"),
            Self::ApprovalAlreadyUsed { .. } => Some("Submit a new approval request"),
            Self::PartialApproval(_) => Some("Check approval status and retry if needed"),
            Self::ApprovalStorage(_) => Some("Check file permissions and disk space"),
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

    /// A storage operation failed.
    #[error("storage error: {0}")]
    Storage(#[source] auths_id::storage::registry::backend::RegistryError),
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

    /// A storage operation failed.
    #[error("storage error: {0}")]
    ApprovalStorage(#[source] SdkStorageError),
}
