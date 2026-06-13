//! Identity domain services
//!
//! Provisions, rotates, and manages developer, CI, and agent identities.

/// Identity errors
pub mod error;
/// Local signer-identity resolution (root + delegate machines)
pub mod local;
/// Identity provisioning workflows
pub mod provision;
/// Identity registration on remote registries
pub mod registration;
/// Identity key rotation
pub mod rotation;
/// Identity services
pub mod service;
/// Apply a co-authored shared-KEL rotation received from a paired device
pub mod shared_rot;
/// Identity types and configuration
pub mod types;

pub use error::*;
pub use types::*;
