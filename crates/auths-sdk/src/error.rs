pub use auths_core::error::AuthsErrorInfo;
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

impl AuthsErrorInfo for SdkStorageError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::Identity(e) => e.error_code(),
            Self::Init(e) => e.error_code(),
            Self::AgentProvisioning(e) => e.error_code(),
            Self::Driver(e) => e.error_code(),
            Self::Attestation(e) => e.error_code(),
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::Identity(e) => e.suggestion(),
            Self::Init(e) => e.suggestion(),
            Self::AgentProvisioning(e) => e.suggestion(),
            Self::Driver(e) => e.suggestion(),
            Self::Attestation(e) => e.suggestion(),
        }
    }
}

/// Re-export identity domain errors for backwards compatibility.
pub use crate::domains::identity::error::{RegistrationError, RotationError, SetupError};

/// Re-export device domain errors for backwards compatibility.
pub use crate::domains::device::error::{DeviceError, DeviceExtensionError};

/// Re-export auth domain errors for backwards compatibility.
pub use crate::domains::auth::error::{McpAuthError, TrustError};

/// Re-export org domain errors for backwards compatibility.
pub use crate::domains::org::error::OrgError;

/// Re-export compliance domain errors for backwards compatibility.
pub use crate::domains::compliance::error::ApprovalError;

/// Re-export from `auths-core` — defined there to avoid a circular dependency with
/// `auths-infra-http` (which implements the platform port traits).
pub use auths_core::ports::platform::PlatformError;

// Re-exported error types from auths-core for CLI error rendering
pub use auths_core::error::AgentError;
pub use auths_core::error::TrustError as CoreTrustError;
pub use auths_core::pairing::PairingError;

// Re-exported error types from auths-id for CLI error rendering
pub use auths_id::error::FreezeError;
pub use auths_id::error::InitError;
pub use auths_id::error::StorageError as IdStorageError;
pub use auths_id::storage::StorageError as IdDriverStorageError;
