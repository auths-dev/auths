use auths_oidc_bridge::BridgeConfig;
use auths_oidc_bridge::BridgeState;
use auths_verifier::core::Capability;

use super::helpers::{create_signed_attestation, create_test_keypair, ed25519_pubkey_to_did_key};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use tower::ServiceExt;

use super::helpers::TEST_RSA_PEM;

fn test_app_with_policy(policy_json: &str) -> axum::Router {
    let config = BridgeConfig::default()
        .with_issuer_url("https://oidc.example.com")
        .with_default_audience("sts.amazonaws.com")
        .with_max_ttl(3600)
        .with_default_ttl(900)
        .with_rate_limit_enabled(false)
        .with_signing_key_pem(TEST_RSA_PEM)
        .with_workload_policy_json(policy_json);
    let state = BridgeState::new(config.clone()).expect("failed to create bridge state");
    auths_oidc_bridge::routes::router(state, &config)
}

fn build_exchange_body(capabilities: Vec<Capability>) -> String {
    let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
    let root_did = ed25519_pubkey_to_did_key(&root_pk);
    let (device_kp, device_pk) = create_test_keypair(&[2u8; 32]);
    let device_did = ed25519_pubkey_to_did_key(&device_pk);

    let att = create_signed_attestation(
        &root_kp,
        &device_kp,
        &root_did,
        &device_did,
        false,
        Some(Utc::now() + Duration::days(365)),
        capabilities,
    );

    serde_json::to_string(&serde_json::json!({
        "attestation_chain": [att],
        "root_public_key": hex::encode(root_pk),
    }))
    .unwrap()
}

fn token_request(body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/token")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn exchange_with_allowing_policy_succeeds() {
    let policy = r#"{"op": "IsWorkload"}"#;
    let app = test_app_with_policy(policy);

    let body = build_exchange_body(vec![Capability::sign_commit()]);
    let response = app.oneshot(token_request(&body)).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(json["access_token"].is_string());
    assert_eq!(json["token_type"], "Bearer");
}

#[tokio::test]
async fn exchange_with_denying_policy_returns_403() {
    // Policy requires deploy:production, but chain only has sign:commit
    let policy = r#"{"op": "HasCapability", "args": "deploy:production"}"#;
    let app = test_app_with_policy(policy);

    let body = build_exchange_body(vec![Capability::sign_commit()]);
    let response = app.oneshot(token_request(&body)).await.unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["code"], "POLICY_DENIED");
}

#[tokio::test]
async fn exchange_with_capability_policy_matches() {
    // Policy requires sign_commit, chain has it → allow
    let policy = r#"{"op": "HasCapability", "args": "sign_commit"}"#;
    let app = test_app_with_policy(policy);

    let body = build_exchange_body(vec![Capability::sign_commit()]);
    let response = app.oneshot(token_request(&body)).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn exchange_with_workload_issuer_policy() {
    let (_root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
    let root_did = ed25519_pubkey_to_did_key(&root_pk);
    // The issuer DID is did:key:z6Mk... — extract_keri_prefix strips did:keri: but not did:key:
    // so keri_prefix = "did:key:z6Mk..." and keri_prefix_to_did keeps it since it starts with "did:"
    let policy = format!(r#"{{"op": "WorkloadIssuerIs", "args": "{}"}}"#, root_did);
    let app = test_app_with_policy(&policy);

    let body = build_exchange_body(vec![Capability::sign_commit()]);
    let response = app.oneshot(token_request(&body)).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}
