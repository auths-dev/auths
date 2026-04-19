//! Request-limits enforcement — end-to-end through the full Axum
//! middleware stack.
//!
//! Unit tests for the pure functions (`check_json_depth`,
//! `check_string_lengths`) live in `src/request_limits.rs`. These
//! integration tests exercise `LimitedJson<T>` + the body-size layer
//! through an actual handler and assert the wire-level
//! status/body shape.

use axum::body::Body;
use axum::http::{Method, Request};
use http_body_util::BodyExt;
use tower::ServiceExt;

use super::build_test_daemon;

async fn body_string(resp: axum::http::Response<Body>) -> String {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn post_submit_response(token_b64: &str, json_body: String) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/v1/pairing/sessions/test-session-001/response")
        .header("content-type", "application/json")
        .header("x-pairing-token", token_b64)
        .body(Body::from(json_body))
        .unwrap()
}

#[tokio::test]
async fn seventy_kib_body_returns_413() {
    let (router, _, token) = build_test_daemon();

    // 70 KiB body (above the 64 KiB cap) shaped as a huge JSON string
    // field — the body-size layer rejects before any JSON parse runs.
    let mut huge = String::from("{\"filler\":\"");
    huge.push_str(&"a".repeat(70 * 1024));
    huge.push_str("\"}");
    let req = post_submit_response(&token, huge);

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 413);
}

#[tokio::test]
async fn depth_17_json_returns_400_with_json_depth_exceeded_error_code() {
    let (router, _, token) = build_test_daemon();

    let deep = format!("{}{}", "[".repeat(17), "]".repeat(17));
    let req = post_submit_response(&token, deep);

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 400);
    let body = body_string(resp).await;
    assert!(
        body.contains("\"error\":\"json-depth-exceeded\""),
        "body should carry the machine-readable code; got: {body}"
    );
}

#[tokio::test]
async fn five_kib_string_in_non_ephemeral_field_returns_413() {
    let (router, _, token) = build_test_daemon();

    let long = "x".repeat(5 * 1024);
    let body = format!(
        "{{\"short_code\":\"ABC123\",\"device_ephemeral_pubkey\":\"AAAA\",\"device_signing_pubkey\":\"BBBB\",\"device_did\":\"did:key:{long}\",\"signature\":\"\"}}"
    );
    let req = post_submit_response(&token, body);

    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 413);
}

#[tokio::test]
async fn valid_small_body_is_accepted_by_middleware() {
    let (router, _, token) = build_test_daemon();

    // Well-formed request that passes every T4 cap. Because the test
    // `build_test_daemon` seeds a minimal state, the handler may still
    // return an application-level error — we don't assert 200 here,
    // only that the middleware caps (413 / 400) did NOT fire. The
    // handler's own validation is covered by router.rs tests.
    let body = r#"{"short_code":"ABC123","device_ephemeral_pubkey":"AAAA","device_signing_pubkey":"BBBB","device_did":"did:key:test","signature":""}"#.to_string();
    let req = post_submit_response(&token, body);

    let resp = router.oneshot(req).await.unwrap();
    let status = resp.status().as_u16();
    assert!(
        status != 400 && status != 413,
        "middleware caps fired unexpectedly: {status}"
    );
}

#[tokio::test]
async fn wrong_content_type_returns_400() {
    let (router, _, token) = build_test_daemon();

    let req = Request::builder()
        .method(Method::POST)
        .uri("/v1/pairing/sessions/test-session-001/response")
        .header("content-type", "text/plain")
        .header("x-pairing-token", token)
        .body(Body::from("not json"))
        .unwrap();

    let resp = router.oneshot(req).await.unwrap();
    // `LimitedJson` rejects non-JSON content-type as malformed (400).
    assert_eq!(resp.status(), 400);
}
