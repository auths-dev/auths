use thiserror::Error;

/// Errors surfaced by the API presentation layer.
///
/// The agent-/Redis-/bearer-token-specific variants were removed in Epic E along
/// with the legacy agent API. Kept minimal for the current server skeleton.
#[derive(Debug, Error)]
pub enum ApiError {
    /// A request signature failed verification.
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// The request timestamp fell outside the accepted clock-skew window.
    #[error("Clock skew too large (request timestamp outside 5-minute window)")]
    ClockSkew,

    /// JSON (de)serialization of a request/response failed.
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    /// An unexpected internal error.
    #[error("Internal server error")]
    InternalError,
}
