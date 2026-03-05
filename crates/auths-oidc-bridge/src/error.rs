//! Error types for the OIDC bridge.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use thiserror::Error;

/// Bridge error type.
#[derive(Debug, Error)]
pub enum BridgeError {
    /// Attestation chain verification failed.
    #[error("chain verification failed: {0}")]
    ChainVerificationFailed(String),

    /// Invalid attestation chain structure.
    #[error("invalid chain: {0}")]
    InvalidChain(String),

    /// Invalid root public key.
    #[error("invalid root key: {0}")]
    InvalidRootKey(String),

    /// Requested audience is not in the allowlist.
    #[error("audience not allowed: {0}")]
    AudienceNotAllowed(String),

    /// Requested TTL exceeds the configured maximum.
    #[error("TTL exceeds maximum: requested {requested}s, max {max}s")]
    TtlExceedsMax { requested: u64, max: u64 },

    /// Invalid request body.
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// JWT signing failed.
    #[error("signing failed: {0}")]
    SigningFailed(String),

    /// RSA key error.
    #[error("key error: {0}")]
    KeyError(String),

    /// Witness quorum not met.
    #[error("insufficient witnesses: {verified}/{required}")]
    InsufficientWitnesses { required: usize, verified: usize },

    /// Requested capabilities not granted by the attestation chain.
    #[error("insufficient capabilities: requested {requested:?}, granted {granted:?}")]
    InsufficientCapabilities {
        requested: Vec<String>,
        granted: Vec<String>,
    },

    /// Rate limit exceeded for a KERI prefix.
    #[error("rate limited: prefix {prefix}, retry after {retry_after_secs}s")]
    RateLimited {
        prefix: String,
        retry_after_secs: u64,
    },

    /// Unauthorized (bad or missing admin token).
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    /// Internal server error.
    #[error("internal error: {0}")]
    Internal(String),

    /// GitHub OIDC token validation failed.
    #[cfg(feature = "github-oidc")]
    #[error("GitHub token invalid: {0}")]
    GitHubTokenInvalid(String),

    /// Failed to fetch GitHub JWKS endpoint.
    #[cfg(feature = "github-oidc")]
    #[error("GitHub JWKS fetch failed: {0}")]
    GitHubJwksFetchFailed(String),

    /// GitHub actor does not match expected KERI identity.
    #[cfg(feature = "github-oidc")]
    #[error("actor mismatch: expected {expected}, got {actual}")]
    ActorMismatch { expected: String, actual: String },
}

/// Error response body.
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub code: String,
}

impl IntoResponse for BridgeError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            BridgeError::ChainVerificationFailed(_) => {
                (StatusCode::UNAUTHORIZED, "CHAIN_VERIFICATION_FAILED")
            }
            BridgeError::InvalidChain(_) => (StatusCode::BAD_REQUEST, "INVALID_CHAIN"),
            BridgeError::InvalidRootKey(_) => (StatusCode::BAD_REQUEST, "INVALID_ROOT_KEY"),
            BridgeError::AudienceNotAllowed(_) => (StatusCode::FORBIDDEN, "AUDIENCE_NOT_ALLOWED"),
            BridgeError::TtlExceedsMax { .. } => (StatusCode::BAD_REQUEST, "TTL_EXCEEDS_MAX"),
            BridgeError::InvalidRequest(_) => (StatusCode::BAD_REQUEST, "INVALID_REQUEST"),
            BridgeError::SigningFailed(_) => (StatusCode::INTERNAL_SERVER_ERROR, "SIGNING_FAILED"),
            BridgeError::KeyError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "KEY_ERROR"),
            BridgeError::InsufficientWitnesses { .. } => {
                (StatusCode::UNAUTHORIZED, "INSUFFICIENT_WITNESSES")
            }
            BridgeError::InsufficientCapabilities { .. } => {
                (StatusCode::FORBIDDEN, "INSUFFICIENT_CAPABILITIES")
            }
            BridgeError::RateLimited { .. } => (StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED"),
            BridgeError::Unauthorized(_) => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED"),
            BridgeError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR"),
            #[cfg(feature = "github-oidc")]
            BridgeError::GitHubTokenInvalid(_) => {
                (StatusCode::UNAUTHORIZED, "GITHUB_TOKEN_INVALID")
            }
            #[cfg(feature = "github-oidc")]
            BridgeError::GitHubJwksFetchFailed(_) => {
                (StatusCode::BAD_GATEWAY, "GITHUB_JWKS_FETCH_FAILED")
            }
            #[cfg(feature = "github-oidc")]
            BridgeError::ActorMismatch { .. } => (StatusCode::FORBIDDEN, "ACTOR_MISMATCH"),
        };

        let retry_after = if let BridgeError::RateLimited {
            retry_after_secs, ..
        } = &self
        {
            Some(*retry_after_secs)
        } else {
            None
        };

        let body = ErrorResponse {
            error: self.to_string(),
            code: code.to_string(),
        };

        let mut response = (status, Json(body)).into_response();
        if let Some(secs) = retry_after {
            response.headers_mut().insert(
                axum::http::header::RETRY_AFTER,
                // INVARIANT: u64.to_string() always produces valid header value chars
                #[allow(clippy::unwrap_used)]
                axum::http::HeaderValue::from_str(&secs.to_string()).unwrap(),
            );
        }

        response
    }
}

/// Result type alias for bridge operations.
pub type BridgeResult<T> = Result<T, BridgeError>;
