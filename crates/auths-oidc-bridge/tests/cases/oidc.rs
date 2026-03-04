use auths_verifier::core::Capability;

use super::helpers::create_test_keypair;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use tower::ServiceExt;

use std::sync::Arc;

use super::helpers::{
    create_signed_attestation, ed25519_pubkey_to_did_key, test_app, test_app_with_admin_token,
    test_app_with_audience_validation, test_app_with_clock, test_app_with_rate_limit,
};

#[tokio::test]
async fn test_health_returns_ok() {
    let response = test_app()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
    assert!(json["version"].is_string());
}

#[tokio::test]
async fn test_openid_config_has_required_fields() {
    let response = test_app()
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["issuer"], "https://oidc.example.com");
    assert_eq!(
        json["jwks_uri"],
        "https://oidc.example.com/.well-known/jwks.json"
    );
    assert_eq!(json["token_endpoint"], "https://oidc.example.com/token");
    assert!(
        json["id_token_signing_alg_values_supported"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("RS256"))
    );
}

#[tokio::test]
async fn test_jwks_returns_rs256_key() {
    let response = test_app()
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let keys = json["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);

    let key = &keys[0];
    assert_eq!(key["kty"], "RSA");
    assert_eq!(key["alg"], "RS256");
    assert_eq!(key["use"], "sig");
    assert!(key["kid"].is_string());
    assert!(key["n"].is_string());
    assert!(key["e"].is_string());
}

#[tokio::test]
async fn test_token_exchange_with_valid_chain() {
    let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
    let root_did = ed25519_pubkey_to_did_key(&root_pk);
    let (device_kp, _device_pk) = create_test_keypair(&[2u8; 32]);
    let device_did = ed25519_pubkey_to_did_key(&_device_pk);

    let att = create_signed_attestation(
        &root_kp,
        &device_kp,
        &root_did,
        &device_did,
        false,
        Some(Utc::now() + Duration::days(365)),
        vec![Capability::sign_commit()],
    );

    let request_body = serde_json::json!({
        "attestation_chain": [att],
        "root_public_key": hex::encode(root_pk),
    });

    let response = test_app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json["access_token"].is_string());
    assert_eq!(json["token_type"], "Bearer");
    assert_eq!(json["expires_in"], 900);
    assert_eq!(json["subject"], root_did);

    // Decode the JWT header and verify kid and alg
    let token = json["access_token"].as_str().unwrap();
    let header_b64 = token.split('.').next().unwrap();
    let header_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        header_b64,
    )
    .unwrap();
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
    assert_eq!(header["alg"], "RS256");
    assert!(header["kid"].is_string());

    // Decode the JWT payload and verify claims
    let payload_b64 = token.split('.').nth(1).unwrap();
    let payload_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        payload_b64,
    )
    .unwrap();
    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
    assert_eq!(claims["iss"], "https://oidc.example.com");
    assert_eq!(claims["sub"], root_did);
    assert_eq!(claims["aud"], "sts.amazonaws.com");
    assert!(claims["exp"].is_number());
    assert!(claims["iat"].is_number());
    assert!(claims["jti"].is_string());
}

#[tokio::test]
async fn test_token_exchange_rejects_invalid_chain() {
    // Create an attestation with a bad signature (wrong root key)
    let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
    let (_, wrong_root_pk) = create_test_keypair(&[99u8; 32]);
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
        vec![],
    );

    // Use the wrong root key for verification
    let request_body = serde_json::json!({
        "attestation_chain": [att],
        "root_public_key": hex::encode(wrong_root_pk),
    });

    let response = test_app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_token_exchange_rejects_empty_chain() {
    let request_body = serde_json::json!({
        "attestation_chain": [],
        "root_public_key": hex::encode([0u8; 32]),
    });

    let response = test_app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["code"], "INVALID_CHAIN");
}

#[tokio::test]
async fn test_token_exchange_enforces_max_ttl() {
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
        vec![],
    );

    let request_body = serde_json::json!({
        "attestation_chain": [att],
        "root_public_key": hex::encode(root_pk),
        "ttl_secs": 7200,  // Exceeds max of 3600
    });

    let response = test_app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["code"], "TTL_EXCEEDS_MAX");
}

#[tokio::test]
async fn test_jwks_kid_matches_jwt_kid() {
    let app = test_app();

    // Get JWKS kid
    let jwks_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let jwks_body = jwks_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let jwks_json: serde_json::Value = serde_json::from_slice(&jwks_body).unwrap();
    let jwks_kid = jwks_json["keys"][0]["kid"].as_str().unwrap().to_string();

    // Exchange for a token
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
        vec![],
    );

    let request_body = serde_json::json!({
        "attestation_chain": [att],
        "root_public_key": hex::encode(root_pk),
    });

    let token_response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    let token_body = token_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let token_json: serde_json::Value = serde_json::from_slice(&token_body).unwrap();
    let token = token_json["access_token"].as_str().unwrap();

    // Decode JWT header
    let header_b64 = token.split('.').next().unwrap();
    let header_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        header_b64,
    )
    .unwrap();
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
    let jwt_kid = header["kid"].as_str().unwrap();

    assert_eq!(jwks_kid, jwt_kid);
}

#[tokio::test]
async fn test_token_exchange_deterministic_timestamps() {
    let fixed_time: u64 = 1_700_000_000;
    let clock = Arc::new(move || fixed_time);
    let app = test_app_with_clock(clock);

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
        vec![Capability::sign_commit()],
    );

    let request_body = serde_json::json!({
        "attestation_chain": [att],
        "root_public_key": hex::encode(root_pk),
        "ttl_secs": 600,
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["expires_in"], 600);

    // Decode JWT payload and assert exact timestamps
    let token = json["access_token"].as_str().unwrap();
    let payload_b64 = token.split('.').nth(1).unwrap();
    let payload_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        payload_b64,
    )
    .unwrap();
    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

    assert_eq!(claims["iat"], 1_700_000_000, "iat must match fixed clock");
    assert_eq!(
        claims["exp"], 1_700_000_600,
        "exp must be iat + ttl_secs (600)"
    );
}

#[tokio::test]
async fn test_rate_limit_burst_exhaustion() {
    let app = test_app_with_rate_limit(30, 5, true);

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
        vec![Capability::sign_commit()],
    );

    let body_str = serde_json::to_string(&serde_json::json!({
        "attestation_chain": [att],
        "root_public_key": hex::encode(root_pk),
    }))
    .unwrap();

    // First 5 requests should succeed (burst size = 5)
    for i in 0..5 {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token")
                    .header("content-type", "application/json")
                    .body(Body::from(body_str.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "request {i} should succeed within burst"
        );
    }

    // 6th request should be rate limited
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("content-type", "application/json")
                .body(Body::from(body_str.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

    // Verify Retry-After header is present
    assert!(response.headers().contains_key("retry-after"));

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["code"], "RATE_LIMITED");
}

#[tokio::test]
async fn test_rate_limit_per_prefix_isolation() {
    let app = test_app_with_rate_limit(30, 2, true);

    // Identity 1
    let (root_kp1, root_pk1) = create_test_keypair(&[1u8; 32]);
    let root_did1 = ed25519_pubkey_to_did_key(&root_pk1);
    let (device_kp1, device_pk1) = create_test_keypair(&[2u8; 32]);
    let device_did1 = ed25519_pubkey_to_did_key(&device_pk1);

    let att1 = create_signed_attestation(
        &root_kp1,
        &device_kp1,
        &root_did1,
        &device_did1,
        false,
        Some(Utc::now() + Duration::days(365)),
        vec![Capability::sign_commit()],
    );

    let body1 = serde_json::to_string(&serde_json::json!({
        "attestation_chain": [att1],
        "root_public_key": hex::encode(root_pk1),
    }))
    .unwrap();

    // Identity 2 (different keypair)
    let (root_kp2, root_pk2) = create_test_keypair(&[3u8; 32]);
    let root_did2 = ed25519_pubkey_to_did_key(&root_pk2);
    let (device_kp2, device_pk2) = create_test_keypair(&[4u8; 32]);
    let device_did2 = ed25519_pubkey_to_did_key(&device_pk2);

    let att2 = create_signed_attestation(
        &root_kp2,
        &device_kp2,
        &root_did2,
        &device_did2,
        false,
        Some(Utc::now() + Duration::days(365)),
        vec![Capability::sign_commit()],
    );

    let body2 = serde_json::to_string(&serde_json::json!({
        "attestation_chain": [att2],
        "root_public_key": hex::encode(root_pk2),
    }))
    .unwrap();

    // Exhaust burst for identity 1
    for _ in 0..2 {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token")
                    .header("content-type", "application/json")
                    .body(Body::from(body1.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    // Identity 1 should now be rate limited
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("content-type", "application/json")
                .body(Body::from(body1.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

    // Identity 2 should still work (independent bucket)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("content-type", "application/json")
                .body(Body::from(body2.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_rate_limit_disabled() {
    let app = test_app_with_rate_limit(30, 2, false);

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
        vec![Capability::sign_commit()],
    );

    let body_str = serde_json::to_string(&serde_json::json!({
        "attestation_chain": [att],
        "root_public_key": hex::encode(root_pk),
    }))
    .unwrap();

    // With rate limiting disabled, all requests should succeed even past burst
    for i in 0..10 {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token")
                    .header("content-type", "application/json")
                    .body(Body::from(body_str.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "request {i} should succeed with rate limiting disabled"
        );
    }
}

// --- Audience validation tests ---

#[test]
fn test_audience_kind_detection() {
    use auths_oidc_bridge::audience::{AudienceKind, detect_audience_kind};

    assert_eq!(detect_audience_kind("sts.amazonaws.com"), AudienceKind::Aws);
    assert_eq!(
        detect_audience_kind(
            "https://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/my-pool/providers/auths"
        ),
        AudienceKind::Gcp
    );
    assert_eq!(
        detect_audience_kind("api://some-azure-app-id"),
        AudienceKind::Azure
    );
    assert_eq!(
        detect_audience_kind("12345678-1234-1234-1234-123456789abc"),
        AudienceKind::Azure
    );
    assert_eq!(
        detect_audience_kind("custom-audience"),
        AudienceKind::Custom
    );
}

#[test]
fn test_audience_gcp_format_strict_rejects_bad_format() {
    use auths_oidc_bridge::audience::{AudienceValidation, validate_audience_format};

    // Valid GCP audience should succeed
    let result = validate_audience_format(
        "https://iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/my-pool/providers/auths",
        &AudienceValidation::Strict,
    );
    assert!(result.is_ok());

    // Invalid GCP audience (starts with GCP prefix but wrong format) should fail in strict mode
    let result = validate_audience_format(
        "https://iam.googleapis.com/projects/not-a-number/locations/global/workloadIdentityPools/my-pool/providers/auths",
        &AudienceValidation::Strict,
    );
    assert!(result.is_err());

    // Partial GCP URL should fail in strict mode
    let result = validate_audience_format(
        "https://iam.googleapis.com/something-else",
        &AudienceValidation::Strict,
    );
    assert!(result.is_err());
}

#[test]
fn test_audience_gcp_format_warn_allows_bad_format() {
    use auths_oidc_bridge::audience::{AudienceValidation, validate_audience_format};

    // Invalid GCP format in warn mode should still succeed
    let result = validate_audience_format(
        "https://iam.googleapis.com/projects/not-a-number/bad-format",
        &AudienceValidation::Warn,
    );
    assert!(result.is_ok());
}

#[test]
fn test_audience_validation_none_skips_all() {
    use auths_oidc_bridge::audience::{AudienceKind, AudienceValidation, validate_audience_format};

    let result =
        validate_audience_format("https://iam.googleapis.com/bad", &AudienceValidation::None);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), AudienceKind::Gcp);
}

#[tokio::test]
async fn test_audience_strict_rejects_bad_gcp_via_endpoint() {
    use auths_oidc_bridge::audience::AudienceValidation;

    let app = test_app_with_audience_validation(AudienceValidation::Strict);

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
        vec![Capability::sign_commit()],
    );

    // Send with a bad GCP audience
    let body_str = serde_json::to_string(&serde_json::json!({
        "attestation_chain": [att],
        "root_public_key": hex::encode(root_pk),
        "audience": "https://iam.googleapis.com/bad-format",
    }))
    .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("content-type", "application/json")
                .body(Body::from(body_str))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["code"], "INVALID_REQUEST");
}

#[tokio::test]
async fn test_token_includes_target_provider_for_aws() {
    let app = test_app();

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
        vec![Capability::sign_commit()],
    );

    let body_str = serde_json::to_string(&serde_json::json!({
        "attestation_chain": [att],
        "root_public_key": hex::encode(root_pk),
    }))
    .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("content-type", "application/json")
                .body(Body::from(body_str))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Decode JWT payload and check target_provider
    let token = json["access_token"].as_str().unwrap();
    let payload_b64 = token.split('.').nth(1).unwrap();
    let payload_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        payload_b64,
    )
    .unwrap();
    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

    // Default audience is sts.amazonaws.com → target_provider should be "aws"
    assert_eq!(claims["target_provider"], "aws");
}

// --- Capability scope-down tests ---

#[tokio::test]
async fn test_capability_scope_down_none_returns_all() {
    let app = test_app();

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
        vec![Capability::sign_commit()],
    );

    // No requested_capabilities → should get all chain capabilities
    let body_str = serde_json::to_string(&serde_json::json!({
        "attestation_chain": [att],
        "root_public_key": hex::encode(root_pk),
    }))
    .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("content-type", "application/json")
                .body(Body::from(body_str))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let token = json["access_token"].as_str().unwrap();
    let payload_b64 = token.split('.').nth(1).unwrap();
    let payload_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        payload_b64,
    )
    .unwrap();
    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

    let caps = claims["capabilities"].as_array().unwrap();
    assert!(caps.contains(&serde_json::json!("sign_commit")));
}

#[tokio::test]
async fn test_capability_scope_down_intersection() {
    let app = test_app();

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
        vec![Capability::sign_commit(), Capability::sign_release()],
    );

    // Request only sign:commit → should get only sign:commit
    let body_str = serde_json::to_string(&serde_json::json!({
        "attestation_chain": [att],
        "root_public_key": hex::encode(root_pk),
        "requested_capabilities": ["sign_commit"],
    }))
    .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("content-type", "application/json")
                .body(Body::from(body_str))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let token = json["access_token"].as_str().unwrap();
    let payload_b64 = token.split('.').nth(1).unwrap();
    let payload_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        payload_b64,
    )
    .unwrap();
    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

    let caps = claims["capabilities"].as_array().unwrap();
    assert_eq!(caps.len(), 1);
    assert_eq!(caps[0], "sign_commit");
}

#[tokio::test]
async fn test_capability_scope_down_insufficient() {
    let app = test_app();

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
        vec![Capability::sign_commit()],
    );

    // Request deploy:production which is not granted → 403
    let body_str = serde_json::to_string(&serde_json::json!({
        "attestation_chain": [att],
        "root_public_key": hex::encode(root_pk),
        "requested_capabilities": ["sign_release"],
    }))
    .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("content-type", "application/json")
                .body(Body::from(body_str))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["code"], "INSUFFICIENT_CAPABILITIES");
}

#[tokio::test]
async fn test_capability_scope_down_empty_array_is_error() {
    let app = test_app();

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
        vec![Capability::sign_commit()],
    );

    // Empty array → error (requesting nothing is not a wildcard)
    let body_str = serde_json::to_string(&serde_json::json!({
        "attestation_chain": [att],
        "root_public_key": hex::encode(root_pk),
        "requested_capabilities": [],
    }))
    .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("content-type", "application/json")
                .body(Body::from(body_str))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["code"], "INSUFFICIENT_CAPABILITIES");
}

// --- Key rotation tests ---

#[tokio::test]
async fn test_jwks_has_one_key_initially() {
    let app = test_app_with_admin_token("test-secret");

    let response = app
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["keys"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn test_rotation_produces_dual_jwks() {
    let app = test_app_with_admin_token("test-secret");

    let new_km = super::helpers::test_key_manager();
    let new_pem = new_km.private_key_pem().to_vec();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/rotate-key")
                .header("authorization", "Bearer test-secret")
                .body(Body::from(new_pem))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let jwks: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let keys = jwks["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 2, "rotation should produce 2 keys in JWKS");

    let kid0 = keys[0]["kid"].as_str().unwrap();
    let kid1 = keys[1]["kid"].as_str().unwrap();
    assert_ne!(kid0, kid1, "keys should have different kid values");

    // JWKS endpoint should also return 2 keys
    let response = app
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let jwks: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(jwks["keys"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn test_rotation_new_tokens_use_new_kid() {
    let app = test_app_with_admin_token("test-secret");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let jwks: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let initial_kid = jwks["keys"][0]["kid"].as_str().unwrap().to_string();

    let new_km = super::helpers::test_key_manager();
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/rotate-key")
                .header("authorization", "Bearer test-secret")
                .body(Body::from(new_km.private_key_pem().to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();

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
        vec![Capability::sign_commit()],
    );

    let token_response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/token")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&serde_json::json!({
                        "attestation_chain": [att],
                        "root_public_key": hex::encode(root_pk),
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(token_response.status(), StatusCode::OK);

    let body = token_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let token = json["access_token"].as_str().unwrap();

    let header_b64 = token.split('.').next().unwrap();
    let header_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        header_b64,
    )
    .unwrap();
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
    let new_kid = header["kid"].as_str().unwrap();

    assert_ne!(
        new_kid, initial_kid,
        "post-rotation tokens should use new kid"
    );
}

#[tokio::test]
async fn test_drop_previous_key() {
    let app = test_app_with_admin_token("test-secret");

    let new_km = super::helpers::test_key_manager();
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/rotate-key")
                .header("authorization", "Bearer test-secret")
                .body(Body::from(new_km.private_key_pem().to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/drop-previous-key")
                .header("authorization", "Bearer test-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let jwks: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        jwks["keys"].as_array().unwrap().len(),
        1,
        "after drop, JWKS should have 1 key"
    );
}

#[tokio::test]
async fn test_rotation_rejects_wrong_admin_token() {
    let app = test_app_with_admin_token("test-secret");
    let new_km = super::helpers::test_key_manager();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/rotate-key")
                .header("authorization", "Bearer wrong-token")
                .body(Body::from(new_km.private_key_pem().to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_rotation_endpoint_hidden_when_no_admin_token() {
    let app = test_app();
    let new_km = super::helpers::test_key_manager();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/rotate-key")
                .header("authorization", "Bearer something")
                .body(Body::from(new_km.private_key_pem().to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
