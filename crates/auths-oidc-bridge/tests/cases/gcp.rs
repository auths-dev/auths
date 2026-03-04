use auths_verifier::core::Capability;

use super::helpers::mint_jwt_from_bridge;

/// Real GCP Workload Identity Federation test.
///
/// Exchanges a bridge-minted JWT for a GCP access token via the STS endpoint.
///
/// Requires:
/// - `GCP_PROJECT_NUMBER`: The GCP project number (numeric)
/// - `GCP_POOL_ID`: Workload Identity Pool ID
/// - `GCP_PROVIDER_ID`: Workload Identity Pool Provider ID
/// - `AUTHS_BRIDGE_URL`: Base URL of the deployed bridge (HTTPS, publicly accessible)
///
/// The Workload Identity Pool Provider must be configured to trust the bridge's
/// issuer URL and JWKS endpoint.
#[tokio::test]
#[ignore]
async fn test_gcp_workload_identity_federation() {
    let project_number =
        std::env::var("GCP_PROJECT_NUMBER").expect("GCP_PROJECT_NUMBER must be set");
    let pool_id = std::env::var("GCP_POOL_ID").expect("GCP_POOL_ID must be set");
    let provider_id = std::env::var("GCP_PROVIDER_ID").expect("GCP_PROVIDER_ID must be set");

    let audience = format!(
        "https://iam.googleapis.com/projects/{project_number}/locations/global/workloadIdentityPools/{pool_id}/providers/{provider_id}"
    );

    let (jwt, _subject) = mint_jwt_from_bridge(&[Capability::sign_commit()]).await;

    let client = reqwest::Client::new();

    // Exchange the bridge JWT for a GCP STS token
    let sts_response = client
        .post("https://sts.googleapis.com/v1/token")
        .form(&[
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            ("audience", &audience),
            ("scope", "https://www.googleapis.com/auth/cloud-platform"),
            (
                "requested_token_type",
                "urn:ietf:params:oauth:token-type:access_token",
            ),
            ("subject_token_type", "urn:ietf:params:oauth:token-type:jwt"),
            ("subject_token", &jwt),
        ])
        .send()
        .await
        .expect("failed to reach GCP STS");

    let status = sts_response.status();
    let body: serde_json::Value = sts_response
        .json()
        .await
        .expect("invalid JSON from GCP STS");

    assert_eq!(
        status.as_u16(),
        200,
        "GCP STS returned non-200: {status} — {body}"
    );
    assert!(
        body["access_token"].is_string(),
        "response should contain access_token"
    );
    assert_eq!(
        body["token_type"]
            .as_str()
            .unwrap_or_default()
            .to_lowercase(),
        "bearer",
        "token_type should be Bearer"
    );

    eprintln!("GCP Workload Identity Federation succeeded");
    eprintln!("  Audience: {audience}");
}
