//! Axum route handlers for the pairing daemon.
//!
//! Each handler extracts HTTP parameters and delegates to business logic
//! methods on [`DaemonState`]. Handlers only map between HTTP and domain
//! types — every error path returns a typed [`DaemonError`] and the
//! status-code mapping lives in a single `IntoResponse` impl (see
//! `src/error.rs`). Centralizing that mapping is what lets the
//! middleware stack (421 / 413 / 429 / 503) share one error path.

use std::sync::Arc;
use std::time::Instant;

use axum::{
    Json,
    extract::{ConnectInfo, Path, State},
    http::HeaderMap,
};

use auths_core::pairing::types::{
    GetConfirmationResponse, GetSessionResponse, SubmitConfirmationRequest, SubmitResponseRequest,
    SuccessResponse,
};

use crate::DaemonState;
use crate::error::DaemonError;
use crate::rate_limiter::{TieredRateLimiter, uniform_time_floor};
use crate::request_limits::LimitedJson;
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
    axum::extract::Extension(limiter): axum::extract::Extension<Arc<TieredRateLimiter>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
) -> Result<Json<GetSessionResponse>, DaemonError> {
    // Equal-time: compute the floor deadline at the top of the
    // handler and sleep until it on both the hit and the miss paths.
    // Otherwise an attacker can enumerate short codes by measuring
    // response time.
    let start = Instant::now();
    let floor = limiter.config().uniform_miss_floor;

    let result = state.lookup_by_code(&code).await;
    limiter.record_lookup_outcome(addr.ip(), result.is_some());
    uniform_time_floor(start, floor).await;

    result.map(Json).ok_or(DaemonError::NotFound)
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
) -> Result<Json<GetSessionResponse>, DaemonError> {
    state
        .get_session(&id)
        .await
        .map(Json)
        .ok_or(DaemonError::NotFound)
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
    LimitedJson(request): LimitedJson<SubmitResponseRequest>,
) -> Result<Json<SuccessResponse>, DaemonError> {
    if !validate_pairing_token(&headers, state.pairing_token()) {
        return Err(DaemonError::Unauthorized);
    }

    state
        .submit_response(&id, request)
        .await
        .map(Json)
        .map_err(|_| DaemonError::Conflict)
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
    LimitedJson(request): LimitedJson<SubmitConfirmationRequest>,
) -> Result<Json<SuccessResponse>, DaemonError> {
    if !validate_pairing_token(&headers, state.pairing_token()) {
        return Err(DaemonError::Unauthorized);
    }

    state
        .submit_confirmation(&id, request)
        .await
        .map(Json)
        .map_err(|_| DaemonError::Conflict)
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
) -> Result<Json<GetConfirmationResponse>, DaemonError> {
    if !validate_pairing_token(&headers, state.pairing_token()) {
        return Err(DaemonError::Unauthorized);
    }

    state
        .get_confirmation(&id)
        .await
        .map(Json)
        .ok_or(DaemonError::NotFound)
}
