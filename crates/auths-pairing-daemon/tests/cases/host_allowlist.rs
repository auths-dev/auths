//! Host / Origin / Referer allowlist middleware — integration tests.
//!
//! The unit tests in `src/host_allowlist.rs` cover the pure header-
//! checking logic. These integration tests exercise the middleware
//! end-to-end through the Axum router — including that the 421 flows
//! through the [`DaemonError::MisdirectedHost`] → `IntoResponse` path.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Method, Request};
use tower::ServiceExt;

use auths_core::pairing::types::{Base64UrlEncoded, CreateSessionRequest, SessionMode};
use auths_pairing_daemon::{
    DaemonState, HostAllowlist, TieredRateConfig, TieredRateLimiter, build_pairing_router,
};

/// Build a router whose allowlist is scoped to a specific bound
/// authority. Port 0 is still a valid authority for testing — the
/// matching is string-level.
fn router_with_allowlist(allowlist: HostAllowlist) -> axum::Router {
    let session = CreateSessionRequest {
        session_id: "test-session-t3".to_string(),
        controller_did: "did:keri:test".to_string(),
        ephemeral_pubkey: Base64UrlEncoded::from_raw("dGVzdC1wdWJrZXk".to_string()),
        short_code: "ABC123".to_string(),
        capabilities: vec![],
        expires_at: 9999999999,
        mode: SessionMode::Pair,
    };
    let token_bytes = b"test-token-bytes-16".to_vec();
    let (tx, _rx) = tokio::sync::oneshot::channel();
    let state = Arc::new(DaemonState::new(session, token_bytes, tx));
    let tiers = TieredRateConfig {
        session_create_per_min: 100,
        session_lookup_per_min: 100,
        sas_submissions_per_session: 100,
        other_per_min: 1000,
        ..TieredRateConfig::default()
    };
    let limiter = Arc::new(TieredRateLimiter::new(tiers));
    build_pairing_router(state, limiter, Arc::new(allowlist))
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))))
}

fn get(uri: &str, host: Option<&str>) -> Request<Body> {
    let mut b = Request::builder().method(Method::GET).uri(uri);
    if let Some(h) = host {
        b = b.header("host", h);
    }
    b.body(Body::empty()).unwrap()
}

fn allowlist_8080() -> HostAllowlist {
    HostAllowlist::for_bound_addr("192.168.1.42:8080".parse().unwrap(), Some("my-mac.local"))
}

#[tokio::test]
async fn missing_host_returns_421() {
    let router = router_with_allowlist(allowlist_8080());
    let resp = router.oneshot(get("/health", None)).await.unwrap();
    assert_eq!(resp.status(), 421);
}

#[tokio::test]
async fn evil_host_returns_421() {
    let router = router_with_allowlist(allowlist_8080());
    let resp = router
        .oneshot(get("/health", Some("evil.com")))
        .await
        .unwrap();
    assert_eq!(resp.status(), 421);
}

#[tokio::test]
async fn bound_lan_ip_is_accepted() {
    let router = router_with_allowlist(allowlist_8080());
    let resp = router
        .oneshot(get("/health", Some("192.168.1.42:8080")))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn localhost_with_bound_port_is_accepted() {
    let router = router_with_allowlist(allowlist_8080());
    let resp = router
        .oneshot(get("/health", Some("localhost:8080")))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn ipv4_loopback_is_accepted() {
    let router = router_with_allowlist(allowlist_8080());
    let resp = router
        .oneshot(get("/health", Some("127.0.0.1:8080")))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn ipv6_loopback_is_accepted() {
    let router = router_with_allowlist(allowlist_8080());
    let resp = router
        .oneshot(get("/health", Some("[::1]:8080")))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn mdns_hostname_is_accepted() {
    let router = router_with_allowlist(allowlist_8080());
    let resp = router
        .oneshot(get("/health", Some("my-mac.local:8080")))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn evil_origin_returns_421_even_with_good_host() {
    let router = router_with_allowlist(allowlist_8080());
    let req = Request::builder()
        .method(Method::GET)
        .uri("/health")
        .header("host", "localhost:8080")
        .header("origin", "https://evil.com")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 421);
}

#[tokio::test]
async fn matching_origin_is_accepted() {
    let router = router_with_allowlist(allowlist_8080());
    let req = Request::builder()
        .method(Method::GET)
        .uri("/health")
        .header("host", "localhost:8080")
        .header("origin", "http://localhost:8080")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn evil_referer_returns_421() {
    let router = router_with_allowlist(allowlist_8080());
    let req = Request::builder()
        .method(Method::GET)
        .uri("/health")
        .header("host", "localhost:8080")
        .header("referer", "https://evil.com/landing-page")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 421);
}

#[tokio::test]
async fn pending_allowlist_rejects_everything() {
    // `pending()` is the fail-closed sentinel returned by constructors
    // that don't yet know the bound port. A production caller MUST
    // replace it; if they forget, every request 421s — which is the
    // correct degraded behavior.
    let router = router_with_allowlist(HostAllowlist::pending());
    let resp = router
        .oneshot(get("/health", Some("localhost:8080")))
        .await
        .unwrap();
    assert_eq!(resp.status(), 421);
}
