//! Re-exports of domain configuration types for backwards compatibility.

// Re-export all identity config types
pub use crate::domains::ci::types::{CiEnvironment, CiIdentityConfig};
pub use crate::domains::identity::types::{
    CreateAgentIdentityConfig, CreateAgentIdentityConfigBuilder, CreateDeveloperIdentityConfig,
    CreateDeveloperIdentityConfigBuilder, IdentityConfig, IdentityConflictPolicy,
    IdentityRotationConfig,
};

// Re-export signing types
pub use crate::domains::signing::types::{GitSigningScope, PlatformVerification};

// Re-export device config types
pub use crate::domains::device::types::{DeviceExtensionConfig, DeviceLinkConfig};
