//! Router construction for the pairing daemon.
//!
//! # CORS policy
//!
//! There is **no** `CorsLayer` on this router. The pairing daemon is a
//! strictly app-to-daemon LAN service: the only legitimate peer is the
//! paired mobile app over the loopback or LAN socket. A browser reaching
//! this endpoint is evidence of DNS rebinding, a proxy misconfiguration,
//! or a bug — never a legitimate flow we want to unblock. An
//! `Access-Control-Allow-Origin: *` + credentials-allowed layer would
//! make rebinding trivially profitable.
//!
//! # Host / Origin / Referer allowlist
//!
//! The middleware chain rejects any request whose `Host`, `Origin`, or
//! `Referer` header does not match the daemon's bound addresses. See
//! [`host_allowlist`] for the full attack-model writeup. The allowlist
//! sits OUTSIDE rate-limit so a rebinding-driven flood costs an
//! attacker no token-bucket budget from us:
//!
//! ```text
//! TraceLayer → host_allowlist → rate_limit → handler
//! ```

use std::sync::Arc;

use axum::{
    Extension, Router, middleware,
    routing::{get, post},
};
use std::time::Duration;

use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::DaemonState;
use crate::handlers::{
    handle_get_confirmation, handle_get_session, handle_health, handle_lookup_hmac,
    handle_submit_confirmation, handle_submit_response,
};
use crate::host_allowlist::{HostAllowlist, host_allowlist_middleware};
use crate::rate_limiter::{TieredRateLimiter, middleware::tiered_rate_limit_middleware};
use crate::request_limits::body_limit_layer;

/// Build the Axum router for pairing session endpoints.
///
/// Attaches all route handlers, the host/origin/referer allowlist
/// middleware, rate limiting middleware (via `Extension`),
/// and tracing layers. Does NOT attach any CORS layer — see module-
/// level docs for why.
///
/// Args:
/// * `state`: Shared daemon state for this pairing session.
/// * `rate_limiter`: Per-IP rate limiter.
/// * `host_allowlist`: Allowlist of accepted Host authorities. Pass
///   [`HostAllowlist::for_bound_addr`] in production (after `bind`),
///   [`HostAllowlist::allow_any_for_tests`] in test code.
///
/// Usage:
/// ```ignore
/// let allowlist = Arc::new(HostAllowlist::for_bound_addr(addr, None));
/// let router = build_pairing_router(state, rate_limiter, allowlist);
/// let listener = TcpListener::bind("0.0.0.0:0").await?;
/// axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await?;
/// ```
pub fn build_pairing_router(
    state: Arc<DaemonState>,
    tiered_limiter: Arc<TieredRateLimiter>,
    host_allowlist: Arc<HostAllowlist>,
) -> Router {
    Router::new()
        .route("/health", get(handle_health))
        .route("/v1/pairing/sessions/lookup", get(handle_lookup_hmac))
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
        // Per-request deadline — protects against slow-write clients
        // that hold a connection open indefinitely (a Slowloris
        // variant that targets the response write side). 30s is
        // well above any legitimate pairing round-trip.
        .layer(TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(30),
        ))
        // 64 KiB global body-size cap. Sits innermost so handlers and
        // the `LimitedJson` extractor see a byte-limited body; placing
        // it ABOVE rate-limit would let floods of 70 KiB POSTs burn
        // token-bucket budget before rejection.
        .layer(body_limit_layer())
        .layer(middleware::from_fn(tiered_rate_limit_middleware))
        // Attach the tiered limiter as an Extension so both the
        // middleware (tier-quota check) and the lookup handler
        // (miss tracking + uniform-time floor) can reach it.
        .layer(Extension(tiered_limiter))
        .layer(middleware::from_fn_with_state(
            host_allowlist.clone(),
            host_allowlist_middleware,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
