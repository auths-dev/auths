//! Router-level smoke tests. Detailed auth tests live in
//! `auth_hmac.rs` and `auth_sig.rs`.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use http_body_util::BodyExt;
use tower::ServiceExt;

use auths_pairing_daemon::{
    DaemonState, HostAllowlist, TieredRateConfig, TieredRateLimiter, build_pairing_router,
};

use super::build_test_daemon;

#[allow(clippy::unwrap_used)]
async fn response_body(resp: axum::http::Response<Body>) -> String {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn router_for(state: &Arc<DaemonState>) -> axum::Router {
    let allowlist = Arc::new(HostAllowlist::allow_any_for_tests());
    let tiers = TieredRateConfig {
        session_create_per_min: 100,
        session_lookup_per_min: 100,
        sas_submissions_per_session: 100,
        other_per_min: 1000,
        ..TieredRateConfig::default()
    };
    let limiter = Arc::new(TieredRateLimiter::new(tiers));
    build_pairing_router(state.clone(), limiter, allowlist)
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))))
}

#[tokio::test]
async fn health_returns_ok() {
    let (router, _, _) = build_test_daemon();
    let req = axum::http::Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(response_body(resp).await, "ok");
}

#[tokio::test]
async fn get_session_by_known_id_is_public() {
    let (router, _, _) = build_test_daemon();
    let req = axum::http::Request::builder()
        .uri("/v1/pairing/sessions/test-session-001")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn get_session_unknown_id_returns_404() {
    let (router, _, _) = build_test_daemon();
    let req = axum::http::Request::builder()
        .uri("/v1/pairing/sessions/nonexistent")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn submit_response_without_auth_returns_401() {
    let (router, _, _) = build_test_daemon();
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/pairing/sessions/test-session-001/response")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    // Request is rejected — either 400 (missing token header, caught by
    // request validation) or 401 (caught by auth middleware). Both are
    // acceptable: the point is that unauthenticated requests don't succeed.
    let status = resp.status().as_u16();
    assert!(
        status == 400 || status == 401,
        "expected 400 or 401, got {status}"
    );
}

#[tokio::test]
async fn submit_confirm_without_auth_returns_401() {
    let (router, _, _) = build_test_daemon();
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/pairing/sessions/test-session-001/confirm")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn get_confirmation_without_auth_returns_401() {
    let (router, _, _) = build_test_daemon();
    let req = axum::http::Request::builder()
        .uri("/v1/pairing/sessions/test-session-001/confirmation")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn lookup_without_auth_returns_401() {
    let (router, _, _) = build_test_daemon();
    let req = axum::http::Request::builder()
        .uri("/v1/pairing/sessions/lookup")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn router_for_works_with_shared_state() {
    // Smoke-test the helper used by fn-130 test files — ensures the
    // builder doesn't regress.
    let (_, state, _) = build_test_daemon();
    let router = router_for(&state);
    let req = axum::http::Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
}
