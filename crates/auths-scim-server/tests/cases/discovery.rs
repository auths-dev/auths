//! Discovery endpoint tests (no auth required).

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
async fn api_root_returns_json_index() {
    let app = router(test_state());
    let req = Request::get("/").body(Body::empty()).unwrap();
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["name"], "Auths SCIM 2.0 Provisioning API");
    assert!(json["endpoints"]["users"].is_string());
}

#[tokio::test]
async fn service_provider_config_returns_config() {
    let app = router(test_state());
    let req = Request::get("/ServiceProviderConfig")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["schemas"].is_array());
}

#[tokio::test]
async fn resource_types_returns_user_type() {
    let app = router(test_state());
    let req = Request::get("/ResourceTypes").body(Body::empty()).unwrap();
    let resp = app.oneshot(req).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let arr = json.as_array().unwrap();
    assert!(!arr.is_empty());
    assert_eq!(arr[0]["id"], "User");
    assert_eq!(arr[0]["endpoint"], "/Users");
}

#[tokio::test]
async fn discovery_endpoints_require_no_auth() {
    let app = router(test_state());

    // All discovery endpoints should work without auth
    for path in ["/", "/ServiceProviderConfig", "/ResourceTypes"] {
        let req = Request::get(path).body(Body::empty()).unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "Expected 200 for {} without auth",
            path
        );
    }
}
