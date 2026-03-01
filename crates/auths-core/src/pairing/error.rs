//! Pairing protocol error types.

use thiserror::Error;

/// Errors that can occur during the pairing protocol.
#[derive(Debug, Error)]
pub enum PairingError {
    /// Random number generation failed.
    #[error("RNG failed: {0}")]
    RngFailed(String),

    /// Key generation failed.
    #[error("Key generation failed: {0}")]
    KeyGenFailed(String),

    /// The pairing token has expired.
    #[error("Pairing token expired")]
    Expired,

    /// Invalid signature in the pairing response.
    #[error("Invalid signature")]
    InvalidSignature,

    /// Invalid pairing URI format.
    #[error("Invalid URI format: {0}")]
    InvalidUri(String),

    /// Invalid short code format.
    #[error("Invalid short code: {0}")]
    InvalidShortCode(String),

    /// QR code generation failed.
    #[error("QR code generation failed: {0}")]
    QrCodeFailed(String),

    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// X25519 key exchange failed.
    #[error("Key exchange failed: {0}")]
    KeyExchangeFailed(String),

    /// Ephemeral secret already consumed (one-time use).
    #[error("Session ephemeral secret already consumed")]
    SessionConsumed,

    /// Short code not found in registry.
    #[error("Short code not found: {0}")]
    ShortCodeNotFound(String),

    /// Network error during relay communication.
    #[error("Relay error: {0}")]
    RelayError(String),

    /// Local LAN server error.
    #[error("Local server error: {0}")]
    LocalServerError(String),

    /// mDNS advertisement or discovery error.
    #[error("mDNS error: {0}")]
    MdnsError(String),

    /// No peer found on the local network.
    #[error("No peer found on local network")]
    NoPeerFound,

    /// LAN pairing timed out waiting for a response.
    #[error("LAN pairing timed out")]
    LanTimeout,
}

impl From<serde_json::Error> for PairingError {
    fn from(e: serde_json::Error) -> Self {
        PairingError::Serialization(e.to_string())
    }
}
