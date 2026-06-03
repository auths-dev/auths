//! Domain services for device.

/// Delegated device workflows (Model D — KERI delegation)
pub mod delegation;
/// Device errors
pub mod error;
/// Device services
pub mod service;
/// Device types and configuration
pub mod types;

pub use delegation::{DeviceDelegationResult, add_device};
pub use error::*;
pub use types::*;
