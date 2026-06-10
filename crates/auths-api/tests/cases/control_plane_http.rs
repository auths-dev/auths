//! Control-plane HTTP wiring (E1 B1): the public surface boots, the challenge route
//! mints, and a mutating route is gated behind a presentation (401 without one).
//!
//! The authenticated issue/list/revoke happy paths are covered by the SDK workflow +
//! `authenticate` tests they compose over; this asserts the router/auth wiring.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::disallowed_methods)]

use std::sync::Arc;

use auths_api::app::{build_router, AppState};
use auths_core::ports::clock::SystemClock;
use auths_core::storage::keychain::{KeyAlias, KeyStorage};
use auths_core::testing::IsolatedKeychainHandle;
use auths_id::attestation::export::AttestationSink;
use auths_id::storage::attestation::AttestationSource;
use auths_id::storage::identity::IdentityStorage;
use auths_rp::{Audience, InMemoryChallengeStore};
use auths_sdk::context::AuthsContext;
use auths_storage::git::{
    GitRegistryBackend, RegistryAttestationStorage, RegistryConfig, RegistryIdentityStorage,
};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

/// A minimal control-plane state over an empty git-backed registry (no identity).
/// Enough to exercise the public routes + the auth gate, which never touch the org.
fn test_state() -> (tempfile::TempDir, AppState) {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path();
    if git2::Repository::open(path).is_err() {
        git2::Repository::init(path).unwrap();
    }

    let registry: Arc<dyn auths_id::ports::registry::RegistryBackend + Send + Sync> = Arc::new(
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(path)),
    );
    let identity_storage: Arc<dyn IdentityStorage + Send + Sync> =
        Arc::new(RegistryIdentityStorage::new(path.to_path_buf()));
    let store = Arc::new(RegistryAttestationStorage::new(path));
    let attestation_sink: Arc<dyn AttestationSink + Send + Sync> =
        Arc::clone(&store) as Arc<dyn AttestationSink + Send + Sync>;
    let attestation_source: Arc<dyn AttestationSource + Send + Sync> =
        store as Arc<dyn AttestationSource + Send + Sync>;
    let key_storage: Arc<dyn KeyStorage + Send + Sync> = Arc::new(IsolatedKeychainHandle::new());

    let ctx = AuthsContext::builder()
        .registry(registry)
        .key_storage(key_storage)
        .clock(Arc::new(SystemClock))
        .identity_storage(identity_storage)
        .attestation_sink(attestation_sink)
        .attestation_source(attestation_source)
        .build();

    let state = AppState::new(
        Arc::new(ctx),
        KeyAlias::new_unchecked("org-key"),
        "Eorgprefix0000000000000000000000000000000000".to_string(),
        Arc::new(InMemoryChallengeStore::new(16)),
        Audience::parse("api.example.com").unwrap(),
    );
    (tmp, state)
}

#[tokio::test]
async fn health_is_public() {
    let (_tmp, state) = test_state();
    let app = build_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn challenge_route_mints_without_auth() {
    let (_tmp, state) = test_state();
    let app = build_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/auth/challenge")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn protected_route_requires_presentation() {
    let (_tmp, state) = test_state();
    let app = build_router(state);
    // No Authorization header → the rp_auth middleware denies before the handler runs.
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/org/Eorgprefix0000000000000000000000000000000000/agents")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"label":"a","capabilities":["sign_commit"]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
