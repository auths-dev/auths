//! Axum route handlers for the pairing daemon.
//!
//! Each handler extracts HTTP parameters and delegates to business logic
//! methods on [`DaemonState`]. Handlers only map between HTTP and domain
//! types — every error path returns a typed [`DaemonError`] and the
//! status-code mapping lives in a single `IntoResponse` impl (see
//! `src/error.rs`).
//!
//! # Auth model
//!
//! - `GET /v1/pairing/sessions/lookup` — HMAC-over-short-code via the
//!   `Authorization: Auths-HMAC …` header. The phone holds only the
//!   short code at this stage, so HMAC is the strongest authenticator
//!   available.
//! - `GET /v1/pairing/sessions/{id}` — public (status enum only).
//! - All other session-scoped endpoints — Ed25519 / P-256 signature
//!   via `Authorization: Auths-Sig …`. First successful verify binds
//!   the pubkey; all subsequent requests must use the same key.
//!
//! Legacy `X-Pairing-Token` bearer auth is removed — bearer tokens
//! leak via URL, Referer, HPACK, and logs; signatures don't.

use std::sync::Arc;
use std::time::Instant;

use axum::{
    Json,
    body::Bytes,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, Method},
};

use auths_core::pairing::types::{
    GetConfirmationResponse, GetSessionResponse, SubmitConfirmationRequest, SubmitResponseRequest,
    SuccessResponse,
};

use crate::DaemonState;
use crate::auth::{
    AuthError, AuthScheme, ParsedAuth, parse_authorization, pubkey_kid, verify_hmac, verify_sig,
};
use crate::error::DaemonError;
use crate::rate_limiter::{TieredRateLimiter, uniform_time_floor};
use crate::request_limits::LimitedJson;

/// Health check endpoint.
pub async fn handle_health() -> &'static str {
    "ok"
}

/// Lookup the active session via the HMAC-authenticated bootstrap
/// path. The short code is NOT in the URL; it's bound into the
/// `Authorization: Auths-HMAC` header's kid + HMAC signature.
pub async fn handle_lookup_hmac(
    State(state): State<Arc<DaemonState>>,
    axum::extract::Extension(limiter): axum::extract::Extension<Arc<TieredRateLimiter>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<GetSessionResponse>, DaemonError> {
    // Uniform-time floor: both hit and miss paths exit at the same
    // wall time to prevent short-code enumeration via response timing.
    let start = Instant::now();
    let floor = limiter.config().uniform_miss_floor;

    let result = verify_and_lookup_hmac(&state, &headers, &body).await;
    let was_hit = result.is_ok();
    limiter.record_lookup_outcome(addr.ip(), was_hit);
    uniform_time_floor(start, floor).await;
    result.map(Json)
}

async fn verify_and_lookup_hmac(
    state: &DaemonState,
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<GetSessionResponse, DaemonError> {
    if state.is_expired(tokio::time::Instant::now()) {
        return Err(DaemonError::SessionExpired);
    }
    let parsed = extract_auth(headers, AuthScheme::Hmac)?;
    let now = current_unix();
    verify_hmac(
        &parsed,
        Method::GET.as_str(),
        "/v1/pairing/sessions/lookup",
        body,
        &state.session.short_code,
        now,
    )
    .map_err(auth_to_daemon_error)?;
    state
        .nonce_cache
        .check_and_insert(&parsed.kid, &parsed.nonce)
        .map_err(auth_to_daemon_error)?;

    let status = *state.status.lock().await;
    Ok(GetSessionResponse {
        session_id: state.session.session_id.clone(),
        status,
        ttl_seconds: 300,
        token: Some(state.session.clone()),
        response: None,
    })
}

/// Public status endpoint — no auth required. Returns only the
/// non-secret session-status enum. Used by a paired phone to poll
/// readiness between steps of the pairing handshake.
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

/// Submit a pairing response. This is the first authenticated
/// session-scoped request from the phone. It carries the device's
/// signing pubkey in the body AND a signature in the `Auths-Sig`
/// header; we verify the signature using the body's pubkey and bind
/// it to the session for all subsequent requests.
pub async fn handle_submit_response(
    Path(id): Path<String>,
    State(state): State<Arc<DaemonState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<SuccessResponse>, DaemonError> {
    if state.is_expired(tokio::time::Instant::now()) {
        return Err(DaemonError::SessionExpired);
    }
    let path = format!("/v1/pairing/sessions/{id}/response");

    // Body-level validation runs first — cheap byte-level checks that
    // can reject obviously-malformed traffic without touching the
    // (mutex-locked) auth state.
    let request: SubmitResponseRequest = parse_json_body(&body)?;

    let parsed = extract_auth(&headers, AuthScheme::Sig)?;
    let pubkey = decode_device_pubkey(&request)?;

    // kid check: the header's kid must match this pubkey's kid.
    let expected_kid = pubkey_kid(&pubkey);
    if parsed.kid != expected_kid {
        return Err(DaemonError::UnauthorizedSig);
    }

    let now = current_unix();
    verify_sig(&parsed, Method::POST.as_str(), &path, &body, &pubkey, now)
        .map_err(auth_to_daemon_error)?;
    state
        .nonce_cache
        .check_and_insert(&parsed.kid, &parsed.nonce)
        .map_err(auth_to_daemon_error)?;
    state
        .pubkey_binding
        .bind_or_match(&pubkey)
        .map_err(auth_to_daemon_error)?;

    state
        .submit_response(&id, request)
        .await
        .map(Json)
        .map_err(|_| DaemonError::Conflict)
}

/// Submit SAS confirmation. Requires `Auths-Sig` under the pubkey
/// bound by `submit_response`.
pub async fn handle_submit_confirmation(
    Path(id): Path<String>,
    State(state): State<Arc<DaemonState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<SuccessResponse>, DaemonError> {
    if state.is_expired(tokio::time::Instant::now()) {
        return Err(DaemonError::SessionExpired);
    }
    let path = format!("/v1/pairing/sessions/{id}/confirm");
    let parsed = extract_auth(&headers, AuthScheme::Sig)?;
    let pubkey = state
        .pubkey_binding
        .current()
        .ok_or(DaemonError::UnauthorizedSig)?;
    let expected_kid = pubkey_kid(&pubkey);
    if parsed.kid != expected_kid {
        return Err(DaemonError::UnauthorizedSig);
    }
    let now = current_unix();
    verify_sig(&parsed, Method::POST.as_str(), &path, &body, &pubkey, now)
        .map_err(auth_to_daemon_error)?;
    state
        .nonce_cache
        .check_and_insert(&parsed.kid, &parsed.nonce)
        .map_err(auth_to_daemon_error)?;

    let request: SubmitConfirmationRequest = parse_json_body(&body)?;
    state
        .submit_confirmation(&id, request)
        .await
        .map(Json)
        .map_err(|_| DaemonError::Conflict)
}

/// Get confirmation state. Requires `Auths-Sig` under the bound pubkey.
pub async fn handle_get_confirmation(
    Path(id): Path<String>,
    State(state): State<Arc<DaemonState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<GetConfirmationResponse>, DaemonError> {
    if state.is_expired(tokio::time::Instant::now()) {
        return Err(DaemonError::SessionExpired);
    }
    let path = format!("/v1/pairing/sessions/{id}/confirmation");
    let parsed = extract_auth(&headers, AuthScheme::Sig)?;
    let pubkey = state
        .pubkey_binding
        .current()
        .ok_or(DaemonError::UnauthorizedSig)?;
    let expected_kid = pubkey_kid(&pubkey);
    if parsed.kid != expected_kid {
        return Err(DaemonError::UnauthorizedSig);
    }
    let now = current_unix();
    verify_sig(&parsed, Method::GET.as_str(), &path, &body, &pubkey, now)
        .map_err(auth_to_daemon_error)?;
    state
        .nonce_cache
        .check_and_insert(&parsed.kid, &parsed.nonce)
        .map_err(auth_to_daemon_error)?;

    state
        .get_confirmation(&id)
        .await
        .map(Json)
        .ok_or(DaemonError::NotFound)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn extract_auth(
    headers: &HeaderMap,
    expected_scheme: AuthScheme,
) -> Result<ParsedAuth, DaemonError> {
    let header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(match expected_scheme {
            AuthScheme::Hmac => DaemonError::UnauthorizedHmac,
            AuthScheme::Sig => DaemonError::UnauthorizedSig,
        })?;
    let parsed = parse_authorization(header).map_err(auth_to_daemon_error)?;
    if parsed.scheme != expected_scheme {
        return Err(match expected_scheme {
            AuthScheme::Hmac => DaemonError::UnauthorizedHmac,
            AuthScheme::Sig => DaemonError::UnauthorizedSig,
        });
    }
    Ok(parsed)
}

fn auth_to_daemon_error(e: AuthError) -> DaemonError {
    match e {
        AuthError::MissingHeader
        | AuthError::MalformedHeader
        | AuthError::UnknownScheme
        | AuthError::BadKid
        | AuthError::TimestampSkew
        | AuthError::BadSignature
        | AuthError::KeyBindingMismatch => DaemonError::UnauthorizedSig,
        AuthError::ReplayedNonce => DaemonError::NonceReplay,
    }
}

fn parse_json_body<T: serde::de::DeserializeOwned>(body: &Bytes) -> Result<T, DaemonError> {
    // The body-limit + depth-scan middleware already ran via
    // `LimitedJson` extractor when the handler declared it. Here we
    // parse manually because the body bytes are also the signing
    // input — we need both forms.
    if body.len() > crate::request_limits::MAX_BODY_BYTES {
        return Err(DaemonError::PayloadTooLarge);
    }
    crate::request_limits::check_json_depth(body, crate::request_limits::MAX_JSON_DEPTH)?;
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| DaemonError::JsonDepthExceeded)?;
    crate::request_limits::check_string_lengths(&value)?;
    serde_json::from_value(value).map_err(|_| DaemonError::JsonDepthExceeded)
}

fn decode_device_pubkey(
    req: &SubmitResponseRequest,
) -> Result<auths_keri::KeriPublicKey, DaemonError> {
    // `SubmitResponseRequest.device_signing_pubkey` is a base64url-
    // encoded wire value. The curve is carried via a sibling `curve`
    // field (CLAUDE.md wire-format rule). For this daemon path we
    // accept either Ed25519 (32 B) or P-256 compressed (33 B).
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let bytes = URL_SAFE_NO_PAD
        .decode(req.device_signing_pubkey.as_str())
        .map_err(|_| DaemonError::UnauthorizedSig)?;
    match bytes.len() {
        32 => {
            let arr: [u8; 32] = bytes.try_into().map_err(|_| DaemonError::UnauthorizedSig)?;
            Ok(auths_keri::KeriPublicKey::Ed25519(arr))
        }
        33 => {
            let arr: [u8; 33] = bytes.try_into().map_err(|_| DaemonError::UnauthorizedSig)?;
            Ok(auths_keri::KeriPublicKey::P256(arr))
        }
        _ => Err(DaemonError::UnauthorizedSig),
    }
}

#[allow(clippy::disallowed_methods)] // INVARIANT: daemon is a server process — wall-clock time for auth header validation is appropriate
fn current_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// Silence dead-code warnings when feature combinations change.
#[allow(dead_code)]
fn _limited_json_reference<T>() -> Option<LimitedJson<T>> {
    None
}
