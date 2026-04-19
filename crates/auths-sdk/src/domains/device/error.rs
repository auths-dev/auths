use auths_core::error::AuthsErrorInfo;
use auths_verifier::types::DeviceDID;
use thiserror::Error;

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
    StorageError(#[source] crate::error::SdkStorageError),

    /// Anchoring the attestation in the KEL failed.
    #[error("anchor error: {0}")]
    AnchorError(#[from] auths_id::keri::AnchorError),
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
    StorageError(#[source] crate::error::SdkStorageError),

    /// Anchoring the attestation in the KEL failed.
    #[error("anchor error: {0}")]
    AnchorError(#[from] auths_id::keri::AnchorError),
}

impl From<auths_core::AgentError> for DeviceError {
    fn from(err: auths_core::AgentError) -> Self {
        DeviceError::CryptoError(err)
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
            Self::StorageError(e) => e.error_code(),
            Self::AnchorError(e) => e.error_code(),
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::IdentityNotFound { .. } => Some("Run `auths init` to create an identity first"),
            Self::DeviceNotFound { .. } => Some("Run `auths device list` to see linked devices"),
            Self::AttestationError(_) => Some(
                "The attestation operation failed; run `auths device list` to check device status",
            ),
            Self::DeviceDidMismatch { .. } => Some("Check that --device matches the key name"),
            Self::CryptoError(e) => e.suggestion(),
            Self::StorageError(e) => e.suggestion(),
            Self::AnchorError(e) => e.suggestion(),
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
            Self::StorageError(e) => e.error_code(),
            Self::AnchorError(e) => e.error_code(),
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
            Self::StorageError(e) => e.suggestion(),
            Self::AnchorError(e) => e.suggestion(),
        }
    }
}
