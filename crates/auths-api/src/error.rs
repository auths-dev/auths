use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Clock skew too large (request timestamp outside 5-minute window)")]
    ClockSkew,

    #[error("Delegator not found: {0}")]
    DelegatorNotFound(String),

    #[error("Delegation constraint violated: {0}")]
    DelegationConstraintViolated(String),

    #[error("Agent not found: {0}")]
    AgentNotFound(String),

    #[error("Agent revoked: {0}")]
    AgentRevoked(String),

    #[error("Agent expired: {0}")]
    AgentExpired(String),

    #[error("Capability not granted: {0}")]
    CapabilityNotGranted(String),

    #[error("Redis error: {0}")]
    RedisError(String),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("UUID error: {0}")]
    UuidError(String),

    #[error("Internal server error")]
    InternalError,
}
