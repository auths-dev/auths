use auths_verifier::core::Capability;

use super::helpers::mint_jwt_from_bridge;

/// Real Azure AD Workload Identity token exchange test.
///
/// Exchanges a bridge-minted JWT for an Azure AD access token via the
/// client credentials flow with federated credential.
///
/// Requires:
/// - `AZURE_TENANT_ID`: Azure AD tenant ID
/// - `AZURE_CLIENT_ID`: App registration client ID (with federated credential configured)
/// - `AUTHS_BRIDGE_URL`: Base URL of the deployed bridge (HTTPS, publicly accessible)
///
/// The Azure AD app registration must have a federated credential configured
/// to trust the bridge's issuer URL with subject matching the KERI DID.
#[tokio::test]
#[ignore]
async fn test_azure_workload_identity_token_exchange() {
    let tenant_id = std::env::var("AZURE_TENANT_ID").expect("AZURE_TENANT_ID must be set");
    let client_id = std::env::var("AZURE_CLIENT_ID").expect("AZURE_CLIENT_ID must be set");

    let (jwt, _subject) = mint_jwt_from_bridge(&[Capability::sign_commit()]).await;

    let token_url = format!("https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token");

    let client = reqwest::Client::new();

    // Exchange the bridge JWT for an Azure AD access token using
    // client_credentials grant with client_assertion (federated credential)
    let response = client
        .post(&token_url)
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", &client_id),
            (
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ),
            ("client_assertion", &jwt),
            ("scope", &format!("{client_id}/.default")),
        ])
        .send()
        .await
        .expect("failed to reach Azure AD token endpoint");

    let status = response.status();
    let body: serde_json::Value = response.json().await.expect("invalid JSON from Azure AD");

    assert_eq!(
        status.as_u16(),
        200,
        "Azure AD returned non-200: {status} — {body}"
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

    eprintln!("Azure AD Workload Identity token exchange succeeded");
    eprintln!("  Tenant: {tenant_id}");
    eprintln!("  Client: {client_id}");
}
