//! Typed domain error types for `auths-witness-node`.

use thiserror::Error;

/// Error types emitted during witness node operation.
#[derive(Debug, Error)]
pub enum WitnessNodeError {
    /// HSM hardware signing call failed.
    #[error("HSM signing failed: {0}")]
    HsmSigningFailed(String),

    /// Invalid checkpoint payload structure or encoding.
    #[error("Invalid checkpoint encoding: {0}")]
    InvalidCheckpoint(String),

    /// Duplicity attempt detected; request refused.
    #[error("Duplicity detected: {0}")]
    DuplicityRefused(String),
}
