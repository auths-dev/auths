use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use http_body_util::BodyExt;
use tower::ServiceExt;

use auths_core::pairing::types::{
    Base64UrlEncoded, SubmitConfirmationRequest, SubmitResponseRequest,
};
use auths_pairing_daemon::{DaemonState, RateLimiter, build_pairing_router};

use super::{build_test_daemon, test_session};

#[allow(clippy::unwrap_used)]
async fn response_body(resp: axum::http::Response<Body>) -> String {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn router_for(state: &Arc<DaemonState>) -> axum::Router {
    build_pairing_router(state.clone(), Arc::new(RateLimiter::new(100)))
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
async fn lookup_by_code_found() {
    let (router, _, _) = build_test_daemon();

    let req = axum::http::Request::builder()
        .uri("/v1/pairing/sessions/by-code/ABC123")
        .body(Body::empty())
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    let body = response_body(resp).await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["session_id"], "test-session-001");
    assert_eq!(json["status"], "pending");
}

#[tokio::test]
async fn lookup_by_code_not_found() {
    let (router, _, _) = build_test_daemon();

    let req = axum::http::Request::builder()
        .uri("/v1/pairing/sessions/by-code/ZZZZZ9")
        .body(Body::empty())
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn get_session_by_id() {
    let (router, _, _) = build_test_daemon();

    let req = axum::http::Request::builder()
        .uri("/v1/pairing/sessions/test-session-001")
        .body(Body::empty())
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn get_session_not_found() {
    let (router, _, _) = build_test_daemon();

    let req = axum::http::Request::builder()
        .uri("/v1/pairing/sessions/nonexistent")
        .body(Body::empty())
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn submit_response_requires_token() {
    let (router, _, _) = build_test_daemon();

    let submit = SubmitResponseRequest {
        device_x25519_pubkey: Base64UrlEncoded::from_raw("dGVzdA".to_string()),
        device_signing_pubkey: Base64UrlEncoded::from_raw("dGVzdA".to_string()),
        device_did: "did:key:z6Mktest".to_string(),
        signature: Base64UrlEncoded::from_raw("c2ln".to_string()),
        device_name: None,
    };

    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/pairing/sessions/test-session-001/response")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&submit).unwrap()))
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 401, "missing token should be unauthorized");
}

#[tokio::test]
async fn submit_response_with_valid_token() {
    let (router, _, token_b64) = build_test_daemon();

    let submit = SubmitResponseRequest {
        device_x25519_pubkey: Base64UrlEncoded::from_raw("dGVzdA".to_string()),
        device_signing_pubkey: Base64UrlEncoded::from_raw("dGVzdA".to_string()),
        device_did: "did:key:z6Mktest".to_string(),
        signature: Base64UrlEncoded::from_raw("c2ln".to_string()),
        device_name: Some("Test Device".to_string()),
    };

    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/pairing/sessions/test-session-001/response")
        .header("content-type", "application/json")
        .header("X-Pairing-Token", &token_b64)
        .body(Body::from(serde_json::to_string(&submit).unwrap()))
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn submit_confirmation_requires_token() {
    let (router, _, _) = build_test_daemon();

    let confirm = SubmitConfirmationRequest {
        encrypted_attestation: None,
        aborted: false,
    };

    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/pairing/sessions/test-session-001/confirm")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&confirm).unwrap()))
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn get_confirmation_requires_token() {
    let (router, _, _) = build_test_daemon();

    let req = axum::http::Request::builder()
        .uri("/v1/pairing/sessions/test-session-001/confirmation")
        .body(Body::empty())
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn get_confirmation_with_valid_token() {
    let (router, _, token_b64) = build_test_daemon();

    let req = axum::http::Request::builder()
        .uri("/v1/pairing/sessions/test-session-001/confirmation")
        .header("X-Pairing-Token", &token_b64)
        .body(Body::empty())
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    let body = response_body(resp).await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["aborted"], false);
}

#[tokio::test]
async fn full_pairing_flow() {
    let session = test_session();
    let token_bytes = b"test-token-bytes-16".to_vec();
    let token_b64 = "dGVzdC10b2tlbi1ieXRlcy0xNg";
    let (tx, _rx) = tokio::sync::oneshot::channel();
    let state = Arc::new(DaemonState::new(session, token_bytes, tx));

    // 1. Lookup by code
    let resp = router_for(&state)
        .oneshot(
            axum::http::Request::builder()
                .uri("/v1/pairing/sessions/by-code/ABC123")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = serde_json::from_str(&response_body(resp).await).unwrap();
    assert_eq!(body["status"], "pending");

    // 2. Submit response
    let submit = SubmitResponseRequest {
        device_x25519_pubkey: Base64UrlEncoded::from_raw("dGVzdA".to_string()),
        device_signing_pubkey: Base64UrlEncoded::from_raw("dGVzdA".to_string()),
        device_did: "did:key:z6Mktest".to_string(),
        signature: Base64UrlEncoded::from_raw("c2ln".to_string()),
        device_name: None,
    };
    let resp = router_for(&state)
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/v1/pairing/sessions/test-session-001/response")
                .header("content-type", "application/json")
                .header("X-Pairing-Token", token_b64)
                .body(Body::from(serde_json::to_string(&submit).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // 3. Verify status transitioned to responded
    let resp = router_for(&state)
        .oneshot(
            axum::http::Request::builder()
                .uri("/v1/pairing/sessions/test-session-001")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_str(&response_body(resp).await).unwrap();
    assert_eq!(body["status"], "responded");

    // 4. Submit confirmation
    let confirm = SubmitConfirmationRequest {
        encrypted_attestation: Some("encrypted-data".to_string()),
        aborted: false,
    };
    let resp = router_for(&state)
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/v1/pairing/sessions/test-session-001/confirm")
                .header("content-type", "application/json")
                .header("X-Pairing-Token", token_b64)
                .body(Body::from(serde_json::to_string(&confirm).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // 5. Verify confirmation is retrievable
    let resp = router_for(&state)
        .oneshot(
            axum::http::Request::builder()
                .uri("/v1/pairing/sessions/test-session-001/confirmation")
                .header("X-Pairing-Token", token_b64)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_str(&response_body(resp).await).unwrap();
    assert_eq!(body["aborted"], false);
    assert_eq!(body["encrypted_attestation"], "encrypted-data");
}
