//! Tiered rate-limit behavior through the full router.
//!
//! Tight-quota tests that intentionally burst past the tier ceiling.
//! Uses a dedicated builder so the numbers are specific to these
//! tests — `build_test_daemon` (with its 100/min generous quotas)
//! would swallow any burst.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Method, Request};
use tower::ServiceExt;

use auths_core::pairing::types::{Base64UrlEncoded, CreateSessionRequest};
use auths_pairing_daemon::{
    DaemonState, HostAllowlist, TieredRateConfig, TieredRateLimiter, build_pairing_router,
};

fn tight_router() -> axum::Router {
    let session = CreateSessionRequest {
        session_id: "tier-test".to_string(),
        controller_did: "did:keri:x".to_string(),
        ephemeral_pubkey: Base64UrlEncoded::from_raw("AAAA".to_string()),
        short_code: "ABC123".to_string(),
        capabilities: vec![],
        expires_at: 9999999999,
    };
    let (tx, _rx) = tokio::sync::oneshot::channel();
    let state = Arc::new(DaemonState::new(session, b"tok".to_vec(), tx));
    let tiers = TieredRateConfig {
        // Narrow quotas so burst tests can actually hit them.
        session_create_per_min: 1,
        session_lookup_per_min: 2,
        sas_submissions_per_session: 1,
        other_per_min: 1000,
        // Tight backoff threshold so the "miss lockout" test is cheap.
        lookup_miss_threshold: 2,
        ..TieredRateConfig::default()
    };
    let limiter = Arc::new(TieredRateLimiter::new(tiers));
    let allowlist = Arc::new(HostAllowlist::allow_any_for_tests());
    build_pairing_router(state, limiter, allowlist)
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))))
}

fn get_health() -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri("/health")
        .body(Body::empty())
        .unwrap()
}

fn get_lookup(code: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(format!("/v1/pairing/sessions/by-code/{code}"))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn session_lookup_burst_honors_per_tier_quota() {
    // Quota = 2/min. Three rapid lookups: 1st ok, 2nd ok, 3rd → 429.
    let router = tight_router();
    let r1 = router.clone().oneshot(get_lookup("DOESNT")).await.unwrap();
    // First two lookups burn the quota; status irrelevant (404) — we
    // care that the rate limiter hasn't fired yet.
    assert!(r1.status() != 429, "1st should not be 429, got {}", r1.status());
    let r2 = router.clone().oneshot(get_lookup("MATTER")).await.unwrap();
    assert!(r2.status() != 429, "2nd should not be 429, got {}", r2.status());
    let r3 = router.clone().oneshot(get_lookup("NOMORE")).await.unwrap();
    assert_eq!(r3.status(), 429, "3rd lookup should be rate-limited");
}

#[tokio::test]
async fn other_tier_is_independent_from_session_lookup() {
    // `/health` is `Tier::Other` with 1000/min quota. Should never
    // trip the tiered limiter during this test.
    let router = tight_router();
    for i in 0..5 {
        let resp = router.clone().oneshot(get_health()).await.unwrap();
        assert_eq!(resp.status(), 200, "/health #{i} should be 200");
    }
}

#[tokio::test]
async fn rate_limited_response_carries_retry_after_header() {
    let router = tight_router();
    // Burn the SessionLookup quota.
    let _ = router.clone().oneshot(get_lookup("AAA")).await.unwrap();
    let _ = router.clone().oneshot(get_lookup("BBB")).await.unwrap();
    let limited = router.oneshot(get_lookup("CCC")).await.unwrap();

    assert_eq!(limited.status(), 429);
    let hdr = limited
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok());
    assert!(
        hdr.is_some(),
        "429 response must carry Retry-After; got none"
    );
    let secs: u64 = hdr.unwrap().parse().unwrap();
    // Retry-After is bounded by the window (60s) but must be ≥ 1.
    assert!(
        (1..=60).contains(&secs),
        "Retry-After {secs} outside [1, 60]"
    );
}
