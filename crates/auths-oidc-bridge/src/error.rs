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

    /// RFC 8693 unsupported grant type.
    #[error("unsupported grant type: {0}")]
    UnsupportedGrantType(String),

    /// RFC 8693 invalid grant (subject_token or actor_token failed validation).
    #[error("invalid grant: {0}")]
    InvalidGrant(String),

    /// RFC 8693 delegation depth exceeded.
    #[error("delegation depth exceeded: depth {depth}, max {max}")]
    DelegationDepthExceeded { depth: u32, max: u32 },

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

    /// OIDC provider not found in trust registry.
    #[cfg(feature = "oidc-trust")]
    #[error("OIDC provider not in trust registry: {provider}")]
    ProviderNotTrusted { provider: String },

    /// Repository not allowed for this provider.
    #[cfg(feature = "oidc-trust")]
    #[error("repository not allowed for provider {provider}: {repo}")]
    RepositoryNotAllowed { repo: String, provider: String },

    /// Requested capabilities not allowed by trust registry.
    #[cfg(feature = "oidc-trust")]
    #[error("no allowed capabilities match request")]
    CapabilityNotAllowed {
        requested: Vec<String>,
        allowed: Vec<String>,
    },

    /// SPIFFE SVID verification failed.
    #[cfg(feature = "spiffe")]
    #[error("SPIFFE error: {0}")]
    SpiffeError(String),

    /// SPIFFE trust domain not in allowlist.
    #[cfg(feature = "spiffe")]
    #[error("trust domain '{domain}' not allowed (allowed: {allowed:?})")]
    SpiffeTrustDomainNotAllowed {
        domain: String,
        allowed: Vec<String>,
    },

    /// Workload policy denied the token exchange.
    #[cfg(feature = "oidc-policy")]
    #[error("policy denied: {0}")]
    PolicyDenied(String),

    /// Policy compilation failed at startup.
    #[cfg(feature = "oidc-policy")]
    #[error("policy compilation failed: {0}")]
    PolicyCompilationFailed(String),
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
            BridgeError::UnsupportedGrantType(_) => {
                (StatusCode::BAD_REQUEST, "UNSUPPORTED_GRANT_TYPE")
            }
            BridgeError::InvalidGrant(_) => (StatusCode::BAD_REQUEST, "INVALID_GRANT"),
            BridgeError::DelegationDepthExceeded { .. } => {
                (StatusCode::BAD_REQUEST, "DELEGATION_DEPTH_EXCEEDED")
            }
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
            #[cfg(feature = "oidc-trust")]
            BridgeError::ProviderNotTrusted { .. } => {
                (StatusCode::FORBIDDEN, "PROVIDER_NOT_TRUSTED")
            }
            #[cfg(feature = "oidc-trust")]
            BridgeError::RepositoryNotAllowed { .. } => {
                (StatusCode::FORBIDDEN, "REPOSITORY_NOT_ALLOWED")
            }
            #[cfg(feature = "oidc-trust")]
            BridgeError::CapabilityNotAllowed { .. } => {
                (StatusCode::FORBIDDEN, "CAPABILITY_NOT_ALLOWED")
            }
            #[cfg(feature = "spiffe")]
            BridgeError::SpiffeError(_) => (StatusCode::UNAUTHORIZED, "SPIFFE_ERROR"),
            #[cfg(feature = "spiffe")]
            BridgeError::SpiffeTrustDomainNotAllowed { .. } => {
                (StatusCode::FORBIDDEN, "SPIFFE_TRUST_DOMAIN_NOT_ALLOWED")
            }
            #[cfg(feature = "oidc-policy")]
            BridgeError::PolicyDenied(_) => (StatusCode::FORBIDDEN, "POLICY_DENIED"),
            #[cfg(feature = "oidc-policy")]
            BridgeError::PolicyCompilationFailed(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "POLICY_COMPILATION_FAILED",
            ),
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
