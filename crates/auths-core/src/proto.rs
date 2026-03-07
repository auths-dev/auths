//! Protocol message types.

use thiserror::Error;

/// Protocol encoding and decoding errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ProtoError {
    /// Unknown message type byte.
    #[error("Invalid message type: {0}")]
    InvalidMessageType(u8),

    /// Message format is malformed.
    #[error("Invalid message format: {0}")]
    InvalidFormat(String),

    /// A required field is absent.
    #[error("Missing required field: {0}")]
    MissingField(&'static str),

    /// Protocol version is not supported.
    #[error("Unsupported protocol version: {0}")]
    UnsupportedVersion(u32),

    /// Other protocol error.
    #[error("Protocol error: {0}")]
    Other(String),
}
