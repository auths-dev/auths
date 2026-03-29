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
