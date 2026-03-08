//! Router construction for the pairing daemon.

use std::sync::Arc;

use axum::{
    Extension, Router, middleware,
    routing::{get, post},
};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::DaemonState;
use crate::RateLimiter;
use crate::handlers::{
    handle_get_confirmation, handle_get_session, handle_health, handle_lookup_by_code,
    handle_submit_confirmation, handle_submit_response,
};
use crate::rate_limiter::middleware::rate_limit_middleware;

/// Build the Axum router for pairing session endpoints.
///
/// Attaches all route handlers, rate limiting middleware (via `Extension`),
/// CORS, and tracing layers. The caller is responsible for binding to a
/// `TcpListener` and serving.
///
/// Args:
/// * `state`: Shared daemon state for this pairing session.
/// * `rate_limiter`: Per-IP rate limiter.
///
/// Usage:
/// ```ignore
/// let router = build_pairing_router(state, rate_limiter);
/// let listener = TcpListener::bind("0.0.0.0:0").await?;
/// axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await?;
/// ```
pub fn build_pairing_router(state: Arc<DaemonState>, rate_limiter: Arc<RateLimiter>) -> Router {
    Router::new()
        .route("/health", get(handle_health))
        .route(
            "/v1/pairing/sessions/by-code/{code}",
            get(handle_lookup_by_code),
        )
        .route("/v1/pairing/sessions/{id}", get(handle_get_session))
        .route(
            "/v1/pairing/sessions/{id}/response",
            post(handle_submit_response),
        )
        .route(
            "/v1/pairing/sessions/{id}/confirm",
            post(handle_submit_confirmation),
        )
        .route(
            "/v1/pairing/sessions/{id}/confirmation",
            get(handle_get_confirmation),
        )
        .layer(middleware::from_fn(rate_limit_middleware))
        .layer(Extension(rate_limiter))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state)
}
