//! Identity domain types and errors.
//!
//! Manages developer, CI, and agent identities.

/// Identity errors
pub mod error;
/// Identity provisioning workflows
pub mod provision;
/// Identity registration on remote registries
pub mod registration;
/// Identity key rotation
pub mod rotation;
/// Identity service setup functions
pub mod service;
/// Identity types and configuration
pub mod types;

pub use error::*;
pub use types::*;
