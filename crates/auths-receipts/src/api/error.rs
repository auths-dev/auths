//! The HTTP error envelope: `{ "error": { "code", "message", "details" } }` with
//! stable machine codes and correct status mapping (plan RC-E3.3.6).

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

/// The API's typed errors — each maps to one status + stable code.
#[derive(Debug, Error)]
pub enum ApiError {
    /// 400 — malformed request.
    #[error("{0}")]
    BadRequest(String),
    /// 401 — missing/invalid/revoked credentials.
    #[error("{0}")]
    Unauthorized(String),
    /// 403 — authenticated but out of scope.
    #[error("{0}")]
    Forbidden(String),
    /// 404 — not found (including cross-tenant rows — no enumeration oracle).
    #[error("not found")]
    NotFound,
    /// 409 — idempotency conflict (same key, different body).
    #[error("{0}")]
    IdempotencyConflict(String),
    /// 422 — well-formed but unresolvable input (bad paymentRef, unverifiable bundle).
    #[error("{0}")]
    Unprocessable(String),
    /// 429 — over the per-key rate limit.
    #[error("rate limit exceeded")]
    RateLimited,
    /// 502 — the upstream registry fetch failed.
    #[error("{0}")]
    UpstreamFetch(String),
    /// 500 — internal.
    #[error("{0}")]
    Internal(String),
}

impl ApiError {
    fn status(&self) -> StatusCode {
        match self {
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            ApiError::Forbidden(_) => StatusCode::FORBIDDEN,
            ApiError::NotFound => StatusCode::NOT_FOUND,
            ApiError::IdempotencyConflict(_) => StatusCode::CONFLICT,
            ApiError::Unprocessable(_) => StatusCode::UNPROCESSABLE_ENTITY,
            ApiError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            ApiError::UpstreamFetch(_) => StatusCode::BAD_GATEWAY,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            ApiError::BadRequest(_) => "bad_request",
            ApiError::Unauthorized(_) => "unauthorized",
            ApiError::Forbidden(_) => "forbidden",
            ApiError::NotFound => "not_found",
            ApiError::IdempotencyConflict(_) => "idempotency_conflict",
            ApiError::Unprocessable(_) => "unprocessable",
            ApiError::RateLimited => "rate_limited",
            ApiError::UpstreamFetch(_) => "upstream_fetch_failed",
            ApiError::Internal(_) => "internal",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({
            "error": { "code": self.code(), "message": self.to_string(), "details": {} }
        });
        (self.status(), Json(body)).into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        match e {
            sqlx::Error::RowNotFound => ApiError::NotFound,
            other => ApiError::Internal(format!("database: {other}")),
        }
    }
}

impl From<auths_evidence::EvidenceError> for ApiError {
    fn from(e: auths_evidence::EvidenceError) -> Self {
        use auths_evidence::EvidenceError as E;
        match e {
            E::Fetch(m) => ApiError::UpstreamFetch(m),
            E::Input(m) | E::CallNotFound(m) | E::AnchorLagging(m) => ApiError::Unprocessable(m),
            E::SpendLog(m) | E::Registry(m) | E::Counter(m) | E::Treasury(m) => {
                ApiError::Unprocessable(m)
            }
            E::AnchorInvalid { code, detail } => {
                ApiError::Unprocessable(format!("embedded anchor invalid ({code}): {detail}"))
            }
            E::Canonical(m) | E::Signing(m) => ApiError::Internal(m),
        }
    }
}
