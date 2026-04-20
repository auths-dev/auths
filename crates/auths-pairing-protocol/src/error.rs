use thiserror::Error;

/// Protocol-level errors for the pairing exchange.
///
/// Transport-specific errors (relay, mDNS, LAN timeout) are NOT included —
/// they belong in the transport layer (CLI, server).
#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("pairing token expired")]
    Expired,

    #[error("invalid signature")]
    InvalidSignature,

    #[error("session already consumed")]
    SessionConsumed,

    #[error("key exchange failed: {0}")]
    KeyExchangeFailed(String),

    #[error("key generation failed: {0}")]
    KeyGenFailed(String),

    #[error("invalid pairing URI: {0}")]
    InvalidUri(String),

    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("serialization error: {0}")]
    Serialization(String),
}

impl From<serde_json::Error> for ProtocolError {
    fn from(e: serde_json::Error) -> Self {
        ProtocolError::Serialization(e.to_string())
    }
}
