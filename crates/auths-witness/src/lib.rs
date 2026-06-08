//! Slim, hardened KERI rct-witness server over the shared `auths-core` library.
//!
//! No forked logic: the routes, handlers, receipt signing, duplicity detection,
//! and the W.1.1 stable identity all live in `auths-core`. This crate adds only
//! the binary entrypoint and the application-level DoS hardening an
//! internet-facing event ingest needs (the endpoint accepts untrusted POST
//! bodies, so OS sandboxing alone is not enough).

use std::time::Duration;

use auths_core::witness::{WitnessServerState, witness_router};
use axum::Router;
use axum::extract::DefaultBodyLimit;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::timeout::TimeoutLayer;

/// Maximum accepted request body. A KERI inception event is well under 1 KiB, so
/// cap hard — a hostile client must not be able to stream an unbounded body into
/// memory before validation.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

/// Global in-flight request cap. Bursts beyond this are shed rather than allowed
/// to exhaust CPU/memory (a bounded-concurrency backstop; per-IP rate limiting
/// terminates at the reverse proxy).
pub const MAX_CONCURRENT_REQUESTS: usize = 256;

/// Per-request timeout — guards against slow-write (Slowloris) clients holding
/// connections open.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Build the hardened witness app: the shared `auths-core` router wrapped with a
/// body-size cap, a global concurrency cap, and a per-request timeout.
///
/// Args:
/// * `state`: The witness server state (stable identity + receipt storage).
///
/// Usage:
/// ```ignore
/// let app = hardened_witness_app(state);
/// axum::serve(listener, app).await?;
/// ```
pub fn hardened_witness_app(state: WitnessServerState) -> Router {
    witness_router(state)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(ConcurrencyLimitLayer::new(MAX_CONCURRENT_REQUESTS))
        .layer(TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test(flavor = "multi_thread")]
    async fn oversize_body_is_rejected_without_buffering() {
        let state = WitnessServerState::in_memory_generated().expect("state");
        let app = hardened_witness_app(state);

        let oversized = vec![b'x'; MAX_BODY_BYTES + 1];
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/witness/EPrefix/event")
                    .header("content-type", "application/json")
                    .body(Body::from(oversized))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn within_limit_body_is_accepted_by_the_layer() {
        // A small body passes the body-limit layer (and reaches the handler,
        // which then rejects the malformed event — not a 413).
        let state = WitnessServerState::in_memory_generated().expect("state");
        let app = hardened_witness_app(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/witness/EPrefix/event")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_ne!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
}
