mod builder;
mod cors_absent;
mod host_allowlist;
mod rate_limiter;
mod rate_tiers;
mod request_limits;
mod router;
mod token;

use std::net::SocketAddr;
use std::sync::Arc;

use auths_core::pairing::types::{Base64UrlEncoded, CreateSessionRequest};
use auths_pairing_daemon::{
    DaemonState, HostAllowlist, TieredRateConfig, TieredRateLimiter, build_pairing_router,
};
use axum::extract::connect_info::MockConnectInfo;

pub fn test_session() -> CreateSessionRequest {
    CreateSessionRequest {
        session_id: "test-session-001".to_string(),
        controller_did: "did:keri:test123".to_string(),
        ephemeral_pubkey: Base64UrlEncoded::from_raw("dGVzdC1wdWJrZXk".to_string()),
        short_code: "ABC123".to_string(),
        capabilities: vec!["sign_commit".to_string()],
        expires_at: 9999999999,
    }
}

pub fn build_test_daemon() -> (axum::Router, Arc<DaemonState>, String) {
    let session = test_session();
    let token_bytes = b"test-token-bytes-16".to_vec();
    let token_b64 = "dGVzdC10b2tlbi1ieXRlcy0xNg".to_string();
    let (tx, _rx) = tokio::sync::oneshot::channel();
    let state = Arc::new(DaemonState::new(session, token_bytes, tx));
    // Generous per-tier quotas so existing handler tests aren't
    // throttled by the rate limiter.
    let tiers = TieredRateConfig {
        session_create_per_min: 100,
        session_lookup_per_min: 100,
        sas_submissions_per_session: 100,
        other_per_min: 1000,
        ..TieredRateConfig::default()
    };
    let limiter = Arc::new(TieredRateLimiter::new(tiers));
    // Integration tests want to exercise handler behavior without
    // fighting the Host allowlist. The wildcard `allow_any_for_tests`
    // constructor exists for exactly this. The dedicated allowlist
    // tests live in `tests/cases/host_allowlist.rs`.
    let allowlist = Arc::new(HostAllowlist::allow_any_for_tests());
    let router = build_pairing_router(state.clone(), limiter, allowlist)
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));
    (router, state, token_b64)
}

