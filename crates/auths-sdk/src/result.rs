//! Re-exports of domain result types for backwards compatibility.

// Re-export identity result types
pub use crate::domains::identity::types::{
    AgentIdentityResult, CiIdentityResult, DeveloperIdentityResult, IdentityRotationResult,
    InitializeResult, RegistrationOutcome,
};

// Re-export signing result types
pub use crate::domains::signing::types::PlatformClaimResult;

// Re-export device result types
pub use crate::domains::device::types::{
    DeviceExtensionResult, DeviceLinkResult, DeviceReadiness, DeviceStatus,
};

// Re-export diagnostics result types
pub use crate::domains::diagnostics::types::{AgentStatus, IdentityStatus, NextStep, StatusReport};
