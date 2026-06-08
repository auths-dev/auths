//! HTTP error mapping for the SCIM server.
//!
//! Wraps the domain [`auths_scim::ScimError`] and renders it as the RFC 7644
//! `urn:ietf:params:scim:api:messages:2.0:Error` envelope with the correct
//! `scimType` and HTTP status — the SCIM analogue of `auths-api`'s `ApiError`.

use auths_scim::ScimError;
use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// Presentation-layer SCIM error: a domain [`ScimError`] plus its HTTP rendering.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct ScimServerError(#[from] ScimError);

impl IntoResponse for ScimServerError {
    fn into_response(self) -> Response {
        // Domain error owns the status + scimType mapping (RFC 7644 §3.12).
        let status =
            StatusCode::from_u16(self.0.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (status, Json(self.0.to_response())).into_response()
    }
}

impl ScimServerError {
    /// Borrow the underlying domain error.
    pub fn inner(&self) -> &ScimError {
        &self.0
    }
}
