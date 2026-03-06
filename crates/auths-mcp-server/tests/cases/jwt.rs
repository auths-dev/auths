use auths_mcp_server::AuthsToolAuth;

use super::helpers::*;

#[tokio::test]
async fn valid_token_authorizes_tool_call() {
    let (base_url, _handle) = start_mock_jwks_server().await;

    let auth = AuthsToolAuth::new(
        format!("{base_url}/.well-known/jwks.json"),
        &base_url,
        "auths-mcp-server",
        test_tool_capabilities(),
    );

    let claims = valid_mcp_claims(&base_url, "auths-mcp-server", &["fs:read"]);
    let token = sign_test_jwt(&claims);

    let agent = auth.authorize_tool_call(&token, "read_file").await.unwrap();
    assert_eq!(agent.did, "did:keri:ETestAgent123");
    assert!(agent.capabilities.contains(&"fs:read".to_string()));
}

#[tokio::test]
async fn wrong_capability_returns_insufficient() {
    let (base_url, _handle) = start_mock_jwks_server().await;

    let auth = AuthsToolAuth::new(
        format!("{base_url}/.well-known/jwks.json"),
        &base_url,
        "auths-mcp-server",
        test_tool_capabilities(),
    );

    let claims = valid_mcp_claims(&base_url, "auths-mcp-server", &["fs:read"]);
    let token = sign_test_jwt(&claims);

    let err = auth
        .authorize_tool_call(&token, "deploy")
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("insufficient capabilities"), "got: {msg}");
}

#[tokio::test]
async fn unknown_tool_returns_error() {
    let (base_url, _handle) = start_mock_jwks_server().await;

    let auth = AuthsToolAuth::new(
        format!("{base_url}/.well-known/jwks.json"),
        &base_url,
        "auths-mcp-server",
        test_tool_capabilities(),
    );

    let claims = valid_mcp_claims(&base_url, "auths-mcp-server", &["fs:read"]);
    let token = sign_test_jwt(&claims);

    let err = auth
        .authorize_tool_call(&token, "nonexistent")
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("unknown tool"), "got: {msg}");
}

#[tokio::test]
async fn expired_token_returns_error() {
    let (base_url, _handle) = start_mock_jwks_server().await;

    let auth = AuthsToolAuth::new(
        format!("{base_url}/.well-known/jwks.json"),
        &base_url,
        "auths-mcp-server",
        test_tool_capabilities(),
    );

    let claims = expired_mcp_claims(&base_url, "auths-mcp-server");
    let token = sign_test_jwt(&claims);

    let err = auth
        .authorize_tool_call(&token, "read_file")
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("token invalid"), "got: {msg}");
}

#[tokio::test]
async fn wrong_audience_returns_error() {
    let (base_url, _handle) = start_mock_jwks_server().await;

    let auth = AuthsToolAuth::new(
        format!("{base_url}/.well-known/jwks.json"),
        &base_url,
        "auths-mcp-server",
        test_tool_capabilities(),
    );

    let claims = valid_mcp_claims(&base_url, "wrong-audience", &["fs:read"]);
    let token = sign_test_jwt(&claims);

    let err = auth
        .authorize_tool_call(&token, "read_file")
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("token invalid"), "got: {msg}");
}

#[tokio::test]
async fn garbage_token_returns_error() {
    let (base_url, _handle) = start_mock_jwks_server().await;

    let auth = AuthsToolAuth::new(
        format!("{base_url}/.well-known/jwks.json"),
        &base_url,
        "auths-mcp-server",
        test_tool_capabilities(),
    );

    let err = auth
        .authorize_tool_call("not-a-valid-jwt", "read_file")
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("invalid") || msg.contains("token"),
        "got: {msg}"
    );
}

#[tokio::test]
async fn validate_jwt_returns_full_claims() {
    let (base_url, _handle) = start_mock_jwks_server().await;

    let auth = AuthsToolAuth::new(
        format!("{base_url}/.well-known/jwks.json"),
        &base_url,
        "auths-mcp-server",
        test_tool_capabilities(),
    );

    let claims = valid_mcp_claims(&base_url, "auths-mcp-server", &["fs:read", "fs:write"]);
    let token = sign_test_jwt(&claims);

    let oidc = auth.validate_jwt(&token).await.unwrap();
    assert_eq!(oidc.sub, "did:keri:ETestAgent123");
    assert_eq!(oidc.keri_prefix, "ETestAgent123");
    assert!(oidc.capabilities.contains(&"fs:read".to_string()));
    assert!(oidc.capabilities.contains(&"fs:write".to_string()));
}

#[tokio::test]
async fn multiple_capabilities_all_authorized() {
    let (base_url, _handle) = start_mock_jwks_server().await;

    let auth = AuthsToolAuth::new(
        format!("{base_url}/.well-known/jwks.json"),
        &base_url,
        "auths-mcp-server",
        test_tool_capabilities(),
    );

    let claims = valid_mcp_claims(
        &base_url,
        "auths-mcp-server",
        &["fs:read", "fs:write", "deploy:staging"],
    );
    let token = sign_test_jwt(&claims);

    auth.authorize_tool_call(&token, "read_file").await.unwrap();
    auth.authorize_tool_call(&token, "write_file")
        .await
        .unwrap();
    auth.authorize_tool_call(&token, "deploy").await.unwrap();
}
