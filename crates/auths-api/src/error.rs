use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use thiserror::Error;

use auths_sdk::domains::agents::AgentError;
use auths_sdk::domains::org::error::OrgError;

/// Errors surfaced by the API presentation layer, mapped to HTTP status codes at the
/// boundary (the SDK keeps typed `thiserror` errors; this is the translation layer).
#[derive(Debug, Error)]
pub enum ApiError {
    /// The request was malformed or violated a typed precondition (400).
    #[error("{0}")]
    BadRequest(String),

    /// The requested resource was not found (404).
    #[error("{0}")]
    NotFound(String),

    /// The request conflicts with current state, e.g. a reused alias or an idempotency
    /// key replayed with a different body (409).
    #[error("{0}")]
    Conflict(String),

    /// The authenticated principal lacks authority for the operation (403).
    #[error("{0}")]
    Forbidden(String),

    /// An agent-domain workflow failed; mapped to a status by variant.
    #[error("agent error: {0}")]
    Agent(#[from] AgentError),

    /// An org-domain workflow failed; mapped to a status by variant.
    #[error("org error: {0}")]
    Org(#[from] OrgError),

    /// JSON (de)serialization of a request/response failed (500).
    #[error("serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    /// An unexpected internal error (500).
    #[error("internal server error")]
    InternalError,
}

impl ApiError {
    /// The HTTP status this error maps to.
    fn status(&self) -> StatusCode {
        match self {
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::NotFound(_) => StatusCode::NOT_FOUND,
            ApiError::Conflict(_) => StatusCode::CONFLICT,
            ApiError::Forbidden(_) => StatusCode::FORBIDDEN,
            ApiError::Agent(e) => agent_status(e),
            ApiError::Org(e) => org_status(e),
            ApiError::SerializationError(_) | ApiError::InternalError => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        (
            status,
            Json(serde_json::json!({ "error": self.to_string() })),
        )
            .into_response()
    }
}

/// Map an [`AgentError`] to an HTTP status (client errors are 4xx, internal 5xx).
fn agent_status(e: &AgentError) -> StatusCode {
    match e {
        AgentError::AlreadyDelegated { .. } | AgentError::Revoked { .. } => StatusCode::CONFLICT,
        AgentError::AgentNotFound { .. } | AgentError::IdentityNotFound { .. } => {
            StatusCode::NOT_FOUND
        }
        AgentError::OutsideDelegatorScope { .. } => StatusCode::BAD_REQUEST,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// Map an [`OrgError`] to an HTTP status. A `kt≥2` org is a clean 4xx (the control
/// plane is single-author), not an internal error.
fn org_status(e: &OrgError) -> StatusCode {
    match e {
        OrgError::OrgThresholdDelegationUnsupported { .. } | OrgError::PolicyCompile { .. } => {
            StatusCode::BAD_REQUEST
        }
        OrgError::MemberKeyExists { .. } | OrgError::AlreadyRevoked { .. } => StatusCode::CONFLICT,
        OrgError::MemberNotFound { .. } | OrgError::MemberNotDelegable { .. } => {
            StatusCode::NOT_FOUND
        }
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}
