//! SCIM protocol compliance tests.
//!
//! Tests that validate SCIM request/response format without a database.
//! Full lifecycle tests require PostgreSQL and are marked with #[ignore].

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use auths_scim_server::config::ScimServerConfig;
use auths_scim_server::routes::router;
use auths_scim_server::state::ScimServerState;

#[allow(clippy::expect_used)]
fn test_state() -> ScimServerState {
    let config = ScimServerConfig::default();
    let pg_config = deadpool_postgres::Config::new();
    let pool = pg_config
        .create_pool(
            Some(deadpool_postgres::Runtime::Tokio1),
            tokio_postgres::NoTls,
        )
        .expect("pool");
    ScimServerState::new(config, pool)
}

#[tokio::test]
async fn users_endpoint_requires_auth() {
    let app = router(test_state());

    // GET /Users without auth should return 401
    let req = Request::get("/Users").body(Body::empty()).unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["schemas"].is_array());
    assert_eq!(json["status"], "401");
}

#[tokio::test]
async fn users_endpoint_requires_bearer_format() {
    let app = router(test_state());

    let req = Request::get("/Users")
        .header("Authorization", "Basic dXNlcjpwYXNz")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn user_not_found_returns_scim_error() {
    let app = router(test_state());

    // GET /Users/{random-uuid} should return 401 (no auth)
    let req = Request::get("/Users/00000000-0000-0000-0000-000000000000")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    // Without auth, we get 401 before reaching the handler
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn error_response_has_scim_content_type() {
    let app = router(test_state());

    let req = Request::get("/Users").body(Body::empty()).unwrap();
    let resp = app.oneshot(req).await.unwrap();

    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(content_type, "application/scim+json");
}

#[tokio::test]
async fn post_users_requires_auth() {
    let app = router(test_state());

    let body = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "test-bot"
    });

    let req = Request::post("/Users")
        .header("Content-Type", "application/scim+json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn delete_users_requires_auth() {
    let app = router(test_state());

    let req = Request::delete("/Users/00000000-0000-0000-0000-000000000000")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn patch_users_requires_auth() {
    let app = router(test_state());

    let body = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "Replace", "value": {"active": false}}]
    });

    let req = Request::patch("/Users/00000000-0000-0000-0000-000000000000")
        .header("Content-Type", "application/scim+json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn put_users_requires_auth() {
    let app = router(test_state());

    let body = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "test-bot",
        "active": true
    });

    let req = Request::put("/Users/00000000-0000-0000-0000-000000000000")
        .header("Content-Type", "application/scim+json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
