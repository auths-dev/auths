use auths_verifier::core::Capability;

use super::helpers::{create_signed_attestation, create_test_keypair, ed25519_pubkey_to_did_key};
use auths_oidc_bridge::BridgeConfig;
use auths_oidc_bridge::BridgeState;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use std::io::Write;
use tower::ServiceExt;

use super::helpers::TEST_RSA_PEM;

const GITHUB_ISSUER: &str = "https://token.actions.githubusercontent.com";

fn write_trust_registry_file(json: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(json.as_bytes()).unwrap();
    f.flush().unwrap();
    f
}

fn test_app_with_trust_registry(registry_json: &str) -> (axum::Router, tempfile::NamedTempFile) {
    let file = write_trust_registry_file(registry_json);
    let config = BridgeConfig::default()
        .with_issuer_url("https://oidc.example.com")
        .with_default_audience("sts.amazonaws.com")
        .with_max_ttl(7200)
        .with_default_ttl(900)
        .with_rate_limit_enabled(false)
        .with_signing_key_pem(TEST_RSA_PEM)
        .with_trust_registry_path(file.path().to_path_buf());
    let state = BridgeState::new(config.clone()).expect("failed to create bridge state");
    let app = auths_oidc_bridge::routes::router(state, &config);
    (app, file)
}

fn build_exchange_body(
    capabilities: Vec<Capability>,
    provider_issuer: Option<&str>,
    repository: Option<&str>,
    ttl_secs: Option<u64>,
) -> String {
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

    let mut body = serde_json::json!({
        "attestation_chain": [att],
        "root_public_key": hex::encode(root_pk),
    });

    if let Some(pi) = provider_issuer {
        body["provider_issuer"] = serde_json::json!(pi);
    }
    if let Some(repo) = repository {
        body["repository"] = serde_json::json!(repo);
    }
    if let Some(ttl) = ttl_secs {
        body["ttl_secs"] = serde_json::json!(ttl);
    }

    serde_json::to_string(&body).unwrap()
}

fn token_request(body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/token")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn github_registry_json() -> String {
    serde_json::json!({
        "entries": [{
            "provider_issuer": GITHUB_ISSUER,
            "allowed_repos": ["myorg/*"],
            "allowed_capabilities": ["sign:commit", "deploy:staging"],
            "max_token_ttl_seconds": 3600,
            "require_witness_quorum": null
        }]
    })
    .to_string()
}

#[tokio::test]
async fn trusted_provider_allowed_repo_matching_caps() {
    let (app, _file) = test_app_with_trust_registry(&github_registry_json());

    let body = build_exchange_body(
        vec![Capability::sign_commit()],
        Some(GITHUB_ISSUER),
        Some("myorg/myrepo"),
        None,
    );
    let response = app.oneshot(token_request(&body)).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(json["access_token"].is_string());
    assert_eq!(json["token_type"], "Bearer");
}

#[tokio::test]
async fn untrusted_provider_returns_403() {
    let (app, _file) = test_app_with_trust_registry(&github_registry_json());

    let body = build_exchange_body(
        vec![Capability::sign_commit()],
        Some("https://untrusted.example.com"),
        Some("myorg/myrepo"),
        None,
    );
    let response = app.oneshot(token_request(&body)).await.unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["code"], "PROVIDER_NOT_TRUSTED");
}

#[tokio::test]
async fn disallowed_repo_returns_403() {
    let (app, _file) = test_app_with_trust_registry(&github_registry_json());

    let body = build_exchange_body(
        vec![Capability::sign_commit()],
        Some(GITHUB_ISSUER),
        Some("otherorg/repo"),
        None,
    );
    let response = app.oneshot(token_request(&body)).await.unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["code"], "REPOSITORY_NOT_ALLOWED");
}

#[tokio::test]
async fn no_capability_overlap_returns_403() {
    let (app, _file) = test_app_with_trust_registry(&github_registry_json());

    // Chain has deploy:production, but registry only allows sign:commit and deploy:staging
    let body = build_exchange_body(
        vec![Capability::parse("deploy:production").unwrap()],
        Some(GITHUB_ISSUER),
        Some("myorg/myrepo"),
        None,
    );
    let response = app.oneshot(token_request(&body)).await.unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["code"], "CAPABILITY_NOT_ALLOWED");
}

#[tokio::test]
async fn ttl_capped_by_registry() {
    let (app, _file) = test_app_with_trust_registry(&github_registry_json());

    // Request TTL of 7200s, but registry max is 3600s
    let body = build_exchange_body(
        vec![Capability::sign_commit()],
        Some(GITHUB_ISSUER),
        Some("myorg/myrepo"),
        Some(7200),
    );
    let response = app.oneshot(token_request(&body)).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["expires_in"], 3600);
}

#[tokio::test]
async fn no_registry_allows_all() {
    let config = BridgeConfig::default()
        .with_issuer_url("https://oidc.example.com")
        .with_default_audience("sts.amazonaws.com")
        .with_max_ttl(3600)
        .with_default_ttl(900)
        .with_rate_limit_enabled(false)
        .with_signing_key_pem(TEST_RSA_PEM);
    let state = BridgeState::new(config.clone()).expect("failed to create bridge state");
    let app = auths_oidc_bridge::routes::router(state, &config);

    let body = build_exchange_body(vec![Capability::sign_commit()], None, None, None);
    let response = app.oneshot(token_request(&body)).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[cfg(feature = "oidc-policy")]
#[tokio::test]
async fn trust_check_runs_before_policy() {
    // Trust registry denies this provider, so we should get PROVIDER_NOT_TRUSTED
    // even though the policy would also deny (or allow)
    let registry_json = github_registry_json();
    let file = write_trust_registry_file(&registry_json);

    let config = BridgeConfig::default()
        .with_issuer_url("https://oidc.example.com")
        .with_default_audience("sts.amazonaws.com")
        .with_max_ttl(3600)
        .with_default_ttl(900)
        .with_rate_limit_enabled(false)
        .with_signing_key_pem(TEST_RSA_PEM)
        .with_trust_registry_path(file.path().to_path_buf())
        .with_workload_policy_json(r#"{"op": "IsWorkload"}"#);
    let state = BridgeState::new(config.clone()).expect("failed to create bridge state");
    let app = auths_oidc_bridge::routes::router(state, &config);

    // Use an untrusted provider — trust check should fail before policy runs
    let body = build_exchange_body(
        vec![Capability::sign_commit()],
        Some("https://untrusted.example.com"),
        Some("myorg/myrepo"),
        None,
    );
    let response = app.oneshot(token_request(&body)).await.unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    // Trust check error, NOT policy error — confirms ordering
    assert_eq!(json["code"], "PROVIDER_NOT_TRUSTED");
}
