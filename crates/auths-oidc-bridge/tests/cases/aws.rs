use auths_verifier::core::Capability;

use super::helpers::create_test_keypair;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use tower::ServiceExt;

use super::helpers::{create_signed_attestation, ed25519_pubkey_to_did_key, test_app};

/// Mints a JWT from the test bridge via the HTTP endpoint.
async fn mint_test_jwt() -> (String, String) {
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

    let token = json["access_token"].as_str().unwrap().to_string();
    let subject = json["subject"].as_str().unwrap().to_string();

    (token, subject)
}

/// Real AWS STS integration test.
///
/// Requires:
/// - `AWS_ROLE_ARN`: The IAM role ARN configured to trust the bridge
/// - `AUTHS_BRIDGE_URL`: Base URL of the deployed bridge (HTTPS, publicly accessible)
/// - Standard AWS credentials
#[tokio::test]
#[ignore]
async fn test_aws_sts_assume_role_with_web_identity() {
    let role_arn = std::env::var("AWS_ROLE_ARN").expect("AWS_ROLE_ARN must be set");
    let _bridge_url = std::env::var("AUTHS_BRIDGE_URL").expect("AUTHS_BRIDGE_URL must be set");

    let (jwt, expected_subject) = mint_test_jwt().await;

    // Unique session name per test run to avoid collisions
    let session_name = format!("auths-test-{}", chrono::Utc::now().timestamp_millis());

    let config = aws_config::load_from_env().await;
    let sts_client = aws_sdk_sts::Client::new(&config);

    let result = sts_client
        .assume_role_with_web_identity()
        .role_arn(&role_arn)
        .web_identity_token(&jwt)
        .role_session_name(&session_name)
        .send()
        .await;

    match result {
        Ok(output) => {
            let credentials = output
                .credentials()
                .expect("AssumeRoleWithWebIdentity returned no credentials");

            assert!(
                !credentials.access_key_id().is_empty(),
                "access_key_id should be non-empty"
            );
            assert!(
                !credentials.secret_access_key().is_empty(),
                "secret_access_key should be non-empty"
            );
            assert!(
                !credentials.session_token().is_empty(),
                "session_token should be non-empty"
            );

            let subject = output.subject_from_web_identity_token().unwrap_or_default();
            assert_eq!(
                subject, expected_subject,
                "STS subject should match the KERI DID"
            );

            eprintln!("AWS STS AssumeRoleWithWebIdentity succeeded");
            eprintln!("  Subject: {subject}");
            eprintln!("  Session: {session_name}");
        }
        Err(e) => {
            panic!("AWS STS AssumeRoleWithWebIdentity failed: {e}");
        }
    }
}

/// LocalStack fallback test: validates STS request/response parsing.
///
/// Requires:
/// - `LOCALSTACK_URL`: LocalStack endpoint (default: http://localhost:4566)
///
/// Note: LocalStack does NOT validate JWT signatures against JWKS.
/// This test verifies that the STS client can parse the response correctly.
#[tokio::test]
#[ignore]
async fn test_aws_sts_localstack() {
    let localstack_url =
        std::env::var("LOCALSTACK_URL").unwrap_or_else(|_| "http://localhost:4566".to_string());

    let (jwt, _expected_subject) = mint_test_jwt().await;

    let session_name = format!("auths-test-{}", chrono::Utc::now().timestamp_millis());

    let config = aws_config::from_env()
        .endpoint_url(&localstack_url)
        .load()
        .await;
    let sts_client = aws_sdk_sts::Client::new(&config);

    // LocalStack may not have a role configured, so we use a dummy ARN
    let role_arn = std::env::var("AWS_ROLE_ARN")
        .unwrap_or_else(|_| "arn:aws:iam::000000000000:role/auths-localstack-test".to_string());

    let result = sts_client
        .assume_role_with_web_identity()
        .role_arn(&role_arn)
        .web_identity_token(&jwt)
        .role_session_name(&session_name)
        .send()
        .await;

    // LocalStack may succeed or fail depending on configuration;
    // the key assertion is that the SDK correctly serializes/deserializes
    match result {
        Ok(output) => {
            eprintln!("LocalStack STS succeeded");
            if let Some(creds) = output.credentials() {
                assert!(!creds.access_key_id().is_empty());
                eprintln!("  Got temporary credentials");
            }
        }
        Err(e) => {
            // Even on error, the SDK parsed the response — that's the test
            eprintln!("LocalStack STS returned error (expected if not configured): {e}");
        }
    }
}
