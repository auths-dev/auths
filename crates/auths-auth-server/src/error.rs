//! API error types for the auth server.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use thiserror::Error;

/// API error type.
#[derive(Debug, Error)]
pub enum AuthApiError {
    /// Session not found.
    #[error("session not found: {0}")]
    SessionNotFound(String),

    /// Session has expired.
    #[error("session expired: {0}")]
    SessionExpired(String),

    /// Session is already verified (conflict).
    #[error("session already verified: {0}")]
    SessionAlreadyVerified(String),

    /// Invalid request body.
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// Identity resolution failed.
    #[error("identity resolution failed: {0}")]
    ResolutionFailed(String),

    /// Signature verification failed.
    #[error("verification failed: {0}")]
    VerificationFailed(String),

    /// Internal server error.
    #[error("internal error: {0}")]
    Internal(String),
}

/// RFC 9457 Problem Details error response body.
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    #[serde(rename = "type")]
    pub error_type: String,
    pub title: String,
    pub status: u16,
    pub detail: String,
    pub code: String,
}

impl IntoResponse for AuthApiError {
    fn into_response(self) -> Response {
        let (status, code, title) = match &self {
            AuthApiError::SessionNotFound(_) => (
                StatusCode::NOT_FOUND,
                "SESSION_NOT_FOUND",
                "Session Not Found",
            ),
            AuthApiError::SessionExpired(_) => {
                (StatusCode::GONE, "SESSION_EXPIRED", "Session Expired")
            }
            AuthApiError::SessionAlreadyVerified(_) => {
                (StatusCode::CONFLICT, "ALREADY_VERIFIED", "Already Verified")
            }
            AuthApiError::InvalidRequest(_) => (
                StatusCode::BAD_REQUEST,
                "INVALID_REQUEST",
                "Invalid Request",
            ),
            AuthApiError::ResolutionFailed(_) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "RESOLUTION_FAILED",
                "Resolution Failed",
            ),
            AuthApiError::VerificationFailed(_) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "VERIFICATION_FAILED",
                "Verification Failed",
            ),
            AuthApiError::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Internal Error",
            ),
        };

        let error_message = if matches!(self, AuthApiError::Internal(_)) {
            tracing::error!(error = %self, "internal server error");
            "Internal Server Error".to_string()
        } else {
            self.to_string()
        };

        let error_type = format!("urn:auths:error:{}", code.to_lowercase().replace('_', "-"));

        let body = ErrorResponse {
            error_type,
            title: title.to_string(),
            status: status.as_u16(),
            detail: error_message,
            code: code.to_string(),
        };

        (
            status,
            [(
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("application/problem+json"),
            )],
            Json(body),
        )
            .into_response()
    }
}

/// Result type alias for auth API handlers.
pub type AuthApiResult<T> = Result<T, AuthApiError>;
