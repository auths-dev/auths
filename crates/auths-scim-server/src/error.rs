//! SCIM server error type with axum response conversion.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use auths_scim::{ScimError, ScimErrorResponse};

/// Server-level error wrapping SCIM protocol errors and infrastructure errors.
#[derive(Debug, thiserror::Error)]
pub enum ScimServerError {
    #[error(transparent)]
    Scim(#[from] ScimError),

    #[error("Database error: {0}")]
    Database(String),

    #[error("SDK error: {0}")]
    Sdk(String),

    #[error("Timeout: {0}")]
    Timeout(String),
}

impl From<deadpool_postgres::PoolError> for ScimServerError {
    fn from(e: deadpool_postgres::PoolError) -> Self {
        Self::Database(e.to_string())
    }
}

impl ScimServerError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Scim(e) => {
                StatusCode::from_u16(e.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
            }
            Self::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Sdk(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Timeout(_) => StatusCode::GATEWAY_TIMEOUT,
        }
    }

    fn to_scim_response(&self) -> ScimErrorResponse {
        match self {
            Self::Scim(e) => e.to_response(),
            _ => {
                let scim_err = ScimError::Internal {
                    message: self.to_string(),
                };
                scim_err.to_response()
            }
        }
    }
}

impl IntoResponse for ScimServerError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let body = self.to_scim_response();
        let json = serde_json::to_string(&body).unwrap_or_default();
        (
            status,
            [(
                axum::http::header::CONTENT_TYPE,
                auths_scim::SCIM_CONTENT_TYPE,
            )],
            json,
        )
            .into_response()
    }
}
