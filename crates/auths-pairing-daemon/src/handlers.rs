//! Axum route handlers for the pairing daemon.
//!
//! Each handler extracts HTTP parameters and delegates to business logic
//! methods on [`DaemonState`]. Handlers only map between HTTP and domain types.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};

use auths_core::pairing::types::{
    GetConfirmationResponse, GetSessionResponse, SubmitConfirmationRequest, SubmitResponseRequest,
    SuccessResponse,
};

use crate::DaemonState;
use crate::token::validate_pairing_token;

/// Health check endpoint.
///
/// Usage:
/// ```ignore
/// GET /health → "ok"
/// ```
pub async fn handle_health() -> &'static str {
    "ok"
}

/// Look up a session by its short code.
///
/// Args:
/// * `code`: Path parameter — the 6-character pairing code.
///
/// Usage:
/// ```ignore
/// GET /v1/pairing/sessions/by-code/ABC-123
/// ```
pub async fn handle_lookup_by_code(
    Path(code): Path<String>,
    State(state): State<Arc<DaemonState>>,
) -> Result<Json<GetSessionResponse>, StatusCode> {
    state
        .lookup_by_code(&code)
        .await
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

/// Get session details by ID.
///
/// Args:
/// * `id`: Path parameter — the session ID.
///
/// Usage:
/// ```ignore
/// GET /v1/pairing/sessions/{id}
/// ```
pub async fn handle_get_session(
    Path(id): Path<String>,
    State(state): State<Arc<DaemonState>>,
) -> Result<Json<GetSessionResponse>, StatusCode> {
    state
        .get_session(&id)
        .await
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

/// Submit a pairing response (requires `X-Pairing-Token`).
///
/// Args:
/// * `id`: Path parameter — the session ID.
/// * `headers`: Must include `X-Pairing-Token` header.
/// * `request`: JSON body with device ECDH + signing keys.
///
/// Usage:
/// ```ignore
/// POST /v1/pairing/sessions/{id}/response
/// ```
pub async fn handle_submit_response(
    Path(id): Path<String>,
    State(state): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(request): Json<SubmitResponseRequest>,
) -> Result<Json<SuccessResponse>, StatusCode> {
    if !validate_pairing_token(&headers, state.pairing_token()) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    state
        .submit_response(&id, request)
        .await
        .map(Json)
        .map_err(|_| StatusCode::CONFLICT)
}

/// Submit a SAS confirmation or abort (requires `X-Pairing-Token`).
///
/// Args:
/// * `id`: Path parameter — the session ID.
/// * `headers`: Must include `X-Pairing-Token` header.
/// * `request`: JSON body with confirmation or abort flag.
///
/// Usage:
/// ```ignore
/// POST /v1/pairing/sessions/{id}/confirm
/// ```
pub async fn handle_submit_confirmation(
    Path(id): Path<String>,
    State(state): State<Arc<DaemonState>>,
    headers: HeaderMap,
    Json(request): Json<SubmitConfirmationRequest>,
) -> Result<Json<SuccessResponse>, StatusCode> {
    if !validate_pairing_token(&headers, state.pairing_token()) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    state
        .submit_confirmation(&id, request)
        .await
        .map(Json)
        .map_err(|_| StatusCode::CONFLICT)
}

/// Get current confirmation state (requires `X-Pairing-Token`).
///
/// Args:
/// * `id`: Path parameter — the session ID.
/// * `headers`: Must include `X-Pairing-Token` header.
///
/// Usage:
/// ```ignore
/// GET /v1/pairing/sessions/{id}/confirmation
/// ```
pub async fn handle_get_confirmation(
    Path(id): Path<String>,
    State(state): State<Arc<DaemonState>>,
    headers: HeaderMap,
) -> Result<Json<GetConfirmationResponse>, StatusCode> {
    if !validate_pairing_token(&headers, state.pairing_token()) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    state
        .get_confirmation(&id)
        .await
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}
