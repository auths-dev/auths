//! Regression: the pairing daemon MUST NOT attach any
//! `Access-Control-Allow-*` headers on any response.
//!
//! We previously shipped `CorsLayer::permissive()`, which made DNS
//! rebinding trivially profitable: a rebound browser could read the
//! response because `Access-Control-Allow-Origin: *` + credentials-
//! allowed is a documented unsafe combination. Removing the layer
//! entirely is locked in by these tests so a future "let's add
//! browser support" reflex can't regress it silently.

use axum::body::Body;
use axum::http::{Method, Request};
use tower::ServiceExt;

use super::build_test_daemon;

/// `OPTIONS` on any route must fall through to Axum's default 405.
/// Specifically: no `Access-Control-Allow-Origin`, and no
/// `Access-Control-Allow-Methods` / `Headers` / `Credentials` /
/// `Private-Network` headers.
#[tokio::test]
async fn options_health_returns_405_with_no_cors_headers() {
    let (router, _, _) = build_test_daemon();

    let req = Request::builder()
        .method(Method::OPTIONS)
        .uri("/health")
        .header("Origin", "https://evil.example.com")
        .header("Access-Control-Request-Method", "GET")
        .header("Access-Control-Request-Headers", "content-type")
        .header("Access-Control-Request-Private-Network", "true")
        .body(Body::empty())
        .expect("request builder");

    let resp = router.oneshot(req).await.expect("oneshot");
    assert_eq!(
        resp.status(),
        405,
        "OPTIONS without a CorsLayer must 405 (method-not-allowed)"
    );
    assert_no_cors_headers(&resp);
}

/// A real GET with an `Origin` header (which a browser fetch would
/// include) gets processed normally, but the response MUST NOT carry
/// any CORS allowance headers. The Origin-allowlist defense for this
/// scenario lives in the Host-allowlist middleware — not in CORS.
#[tokio::test]
async fn get_health_with_evil_origin_returns_200_with_no_cors_headers() {
    let (router, _, _) = build_test_daemon();

    let req = Request::builder()
        .method(Method::GET)
        .uri("/health")
        .header("Origin", "https://evil.example.com")
        .body(Body::empty())
        .expect("request builder");

    let resp = router.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), 200);
    assert_no_cors_headers(&resp);
}

/// A 404 path (e.g. a probing request) must also not leak CORS.
#[tokio::test]
async fn unknown_path_404_has_no_cors_headers() {
    let (router, _, _) = build_test_daemon();

    let req = Request::builder()
        .method(Method::GET)
        .uri("/does-not-exist")
        .header("Origin", "https://evil.example.com")
        .body(Body::empty())
        .expect("request builder");

    let resp = router.oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), 404);
    assert_no_cors_headers(&resp);
}

fn assert_no_cors_headers(resp: &axum::http::Response<Body>) {
    for forbidden in [
        "access-control-allow-origin",
        "access-control-allow-methods",
        "access-control-allow-headers",
        "access-control-allow-credentials",
        "access-control-allow-private-network",
        "access-control-max-age",
        "access-control-expose-headers",
    ] {
        assert!(
            resp.headers().get(forbidden).is_none(),
            "response unexpectedly carries `{forbidden}` — CORS layer must not be re-added"
        );
    }
}
