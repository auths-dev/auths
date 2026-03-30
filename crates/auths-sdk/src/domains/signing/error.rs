//! error for signing domain

use crate::ports::agent::AgentSigningError;
use auths_core::error::AuthsErrorInfo;
use thiserror::Error;

/// Errors from artifact signing operations
#[derive(Debug, Error)]
pub enum ArtifactSigningError {
    /// Artifact digest computation failed
    #[error("failed to compute artifact digest: {0}")]
    DigestFailed(String),
    /// Signing with identity key failed
    #[error("identity key signing failed: {0}")]
    IdentitySigningFailed(String),
    /// Signing with device key failed
    #[error("device key signing failed: {0}")]
    DeviceSigningFailed(String),
    /// Attestation serialization failed
    #[error("attestation serialization failed: {0}")]
    SerializationFailed(String),
    /// Registry publishing failed
    #[error("failed to publish attestation: {0}")]
    PublishFailed(String),
}

impl AuthsErrorInfo for ArtifactSigningError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::DigestFailed(_) => "AUTHS-E6010",
            Self::IdentitySigningFailed(_) => "AUTHS-E6011",
            Self::DeviceSigningFailed(_) => "AUTHS-E6012",
            Self::SerializationFailed(_) => "AUTHS-E6013",
            Self::PublishFailed(_) => "AUTHS-E6014",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::PublishFailed(_) => Some("Check your registry configuration and connection"),
            _ => None,
        }
    }
}

/// Errors from signing operations
#[derive(Debug, Error)]
pub enum SigningError {
    /// Signing failed
    #[error("signing failed: {0}")]
    SigningFailed(String),
    /// Key not found
    #[error("key not found: {0}")]
    KeyNotFound(String),
    /// Agent is unavailable
    #[error("agent unavailable: {0}")]
    AgentUnavailable(String),
    /// Key decryption failed
    #[error("key decryption failed: {0}")]
    KeyDecryptionFailed(String),
    /// Agent signing failed
    #[error("agent signing failed: {0}")]
    AgentSigningFailed(#[source] AgentSigningError),
    /// Keychain is unavailable
    #[error("keychain unavailable: {0}")]
    KeychainUnavailable(String),
    /// Passphrase exhausted
    #[error("passphrase exhausted after {attempts} attempts")]
    PassphraseExhausted {
        /// Number of failed passphrase attempts
        attempts: usize,
    },
    /// Identity is frozen
    #[error("identity is frozen: {0}")]
    IdentityFrozen(String),
    /// Invalid passphrase
    #[error("invalid passphrase")]
    InvalidPassphrase,
}

impl AuthsErrorInfo for SigningError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::SigningFailed(_) => "AUTHS-E6001",
            Self::KeyNotFound(_) => "AUTHS-E6002",
            Self::AgentUnavailable(_) => "AUTHS-E6003",
            Self::KeyDecryptionFailed(_) => "AUTHS-E6004",
            Self::AgentSigningFailed(_) => "AUTHS-E6005",
            Self::KeychainUnavailable(_) => "AUTHS-E6006",
            Self::PassphraseExhausted { .. } => "AUTHS-E6007",
            Self::IdentityFrozen(_) => "AUTHS-E6008",
            Self::InvalidPassphrase => "AUTHS-E6009",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::IdentityFrozen(_) => Some("Run `auths emergency unfreeze` to lift the freeze"),
            Self::PassphraseExhausted { .. } => Some("Try again with the correct passphrase"),
            Self::AgentUnavailable(_) => Some("Start the auths agent with `auths agent start`"),
            _ => None,
        }
    }
}
