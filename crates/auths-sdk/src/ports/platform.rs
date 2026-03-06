//! Platform claim port traits — re-exported from `auths-core`.
//!
//! Defined in `auths-core::ports::platform` to keep the HTTP infrastructure
//! layer free of an `auths-sdk` dependency (which would create a circular
//! dependency via `auths-id/witness-client`).

pub use auths_core::ports::platform::{
    ClaimResponse, DeviceCodeResponse, OAuthDeviceFlowProvider, PlatformError,
    PlatformProofPublisher, PlatformUserProfile, RegistryClaimClient,
};
