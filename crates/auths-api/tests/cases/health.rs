//! Smoke test for the API server skeleton.
//!
//! The legacy bearer-token agent flow was removed in Epic E; this asserts the
//! reduced server still composes a working router and serves its health probe.

use auths_api::app::{build_router, AppState};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

#[tokio::test]
async fn health_endpoint_returns_ok() {
    let app = build_router(AppState::default());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("router responds");
    assert_eq!(response.status(), StatusCode::OK);
}
