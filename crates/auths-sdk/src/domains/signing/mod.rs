//! Domain services for signing.

pub mod ci_env;
pub mod error;
/// Export-authorization policy (plaintext private-key export requires interactive confirmation).
pub mod export_policy;
/// Platform-specific signing implementations
pub mod platform;
pub mod service;
pub mod types;
