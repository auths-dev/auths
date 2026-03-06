use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use super::helpers::*;

#[tokio::test]
async fn health_returns_200() {
    let (base_url, _handle) = start_mock_jwks_server().await;
    let app = test_router(&base_url);

    let resp = app
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
}

#[tokio::test]
async fn protected_resource_metadata() {
    let (base_url, _handle) = start_mock_jwks_server().await;
    let app = test_router(&base_url);

    let resp = app
        .oneshot(
            Request::get("/.well-known/oauth-protected-resource")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["authorization_servers"].is_array());
    let scopes = json["scopes_supported"].as_array().unwrap();
    assert!(!scopes.is_empty());
}

#[tokio::test]
async fn list_tools_returns_all_registered() {
    let (base_url, _handle) = start_mock_jwks_server().await;
    let app = test_router(&base_url);

    let resp = app
        .oneshot(Request::get("/mcp/tools").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let tools: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    assert!(names.contains(&"read_file"));
    assert!(names.contains(&"write_file"));
    assert!(names.contains(&"deploy"));
}

#[tokio::test]
async fn no_token_returns_401() {
    let (base_url, _handle) = start_mock_jwks_server().await;
    let app = test_router(&base_url);

    let resp = app
        .oneshot(
            Request::post("/mcp/tools/read_file")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"path":"/tmp/test.txt"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn invalid_token_returns_401() {
    let (base_url, _handle) = start_mock_jwks_server().await;
    let app = test_router(&base_url);

    let resp = app
        .oneshot(
            Request::post("/mcp/tools/read_file")
                .header("content-type", "application/json")
                .header("authorization", "Bearer garbage-token")
                .body(Body::from(r#"{"path":"/tmp/test.txt"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn insufficient_capabilities_returns_403() {
    let (base_url, _handle) = start_mock_jwks_server().await;
    let app = test_router(&base_url);

    let claims = valid_mcp_claims(&base_url, "auths-mcp-server", &["fs:read"]);
    let token = sign_test_jwt(&claims);

    let resp = app
        .oneshot(
            Request::post("/mcp/tools/deploy")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(r#"{"env":"staging"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn expired_token_returns_401() {
    let (base_url, _handle) = start_mock_jwks_server().await;
    let app = test_router(&base_url);

    let claims = expired_mcp_claims(&base_url, "auths-mcp-server");
    let token = sign_test_jwt(&claims);

    let resp = app
        .oneshot(
            Request::post("/mcp/tools/read_file")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(r#"{"path":"/tmp/test.txt"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn authorized_deploy_succeeds() {
    let (base_url, _handle) = start_mock_jwks_server().await;
    let app = test_router(&base_url);

    let claims = valid_mcp_claims(&base_url, "auths-mcp-server", &["deploy:staging"]);
    let token = sign_test_jwt(&claims);

    let resp = app
        .oneshot(
            Request::post("/mcp/tools/deploy")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(r#"{"env":"staging"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["success"], true);
    assert_eq!(json["result"]["status"], "deployed");
}

#[tokio::test]
async fn authorized_read_file_returns_content() {
    let (base_url, _handle) = start_mock_jwks_server().await;
    let app = test_router(&base_url);

    let test_path = "/tmp/auths_mcp_test_read.txt";
    let test_content = "hello from mcp-server test";
    std::fs::write(test_path, test_content).unwrap();

    let claims = valid_mcp_claims(&base_url, "auths-mcp-server", &["fs:read"]);
    let token = sign_test_jwt(&claims);

    let resp = app
        .oneshot(
            Request::post("/mcp/tools/read_file")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(
                    serde_json::json!({"path": test_path}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["success"], true);
    assert_eq!(json["result"]["content"], test_content);

    std::fs::remove_file(test_path).ok();
}

#[tokio::test]
async fn authorized_write_file_creates_file() {
    let (base_url, _handle) = start_mock_jwks_server().await;
    let app = test_router(&base_url);

    let test_path = "/tmp/auths_mcp_test_write.txt";
    std::fs::remove_file(test_path).ok();

    let claims = valid_mcp_claims(&base_url, "auths-mcp-server", &["fs:write"]);
    let token = sign_test_jwt(&claims);

    let resp = app
        .oneshot(
            Request::post("/mcp/tools/write_file")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(
                    serde_json::json!({"path": test_path, "content": "written by test"})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        std::fs::read_to_string(test_path).unwrap(),
        "written by test"
    );
    std::fs::remove_file(test_path).ok();
}

#[tokio::test]
async fn unknown_tool_returns_404() {
    let (base_url, _handle) = start_mock_jwks_server().await;
    let app = test_router(&base_url);

    let claims = valid_mcp_claims(&base_url, "auths-mcp-server", &["fs:read"]);
    let token = sign_test_jwt(&claims);

    let resp = app
        .oneshot(
            Request::post("/mcp/tools/nonexistent")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
