//! HMAC authentication — `GET /v1/pairing/sessions/lookup`.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Method, Request};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::hmac;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use auths_pairing_daemon::domain_separation::DAEMON_HMAC_INFO;

use super::build_test_daemon;

const SHORT_CODE: &str = "ABC123";

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn derive_kid(short_code: &str) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(short_code.as_bytes());
    let full = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

fn derive_key(short_code: &str) -> [u8; 32] {
    let hk = hkdf::Hkdf::<Sha256>::new(None, short_code.as_bytes());
    let mut key = [0u8; 32];
    let _ = hk.expand(DAEMON_HMAC_INFO, &mut key);
    key
}

fn build_hmac_header(short_code: &str, ts_override: Option<i64>, nonce: &[u8]) -> String {
    let kid = derive_kid(short_code);
    let key = derive_key(short_code);
    let ts = ts_override.unwrap_or_else(now);

    let mut hasher = Sha256::new();
    hasher.update(b"");
    let body_hash = hasher.finalize();
    let body_hash_hex = hex::encode(body_hash);
    let nonce_b64 = URL_SAFE_NO_PAD.encode(nonce);

    let mut canonical = Vec::new();
    canonical.extend_from_slice(DAEMON_HMAC_INFO);
    canonical.push(b'\n');
    canonical.extend_from_slice(b"GET");
    canonical.push(b'\n');
    canonical.extend_from_slice(b"/v1/pairing/sessions/lookup");
    canonical.push(b'\n');
    canonical.extend_from_slice(body_hash_hex.as_bytes());
    canonical.push(b'\n');
    canonical.extend_from_slice(ts.to_string().as_bytes());
    canonical.push(b'\n');
    canonical.extend_from_slice(nonce_b64.as_bytes());

    let ring_key = hmac::Key::new(hmac::HMAC_SHA256, &key);
    let sig = hmac::sign(&ring_key, &canonical);

    format!(
        "Auths-HMAC kid={},ts={},nonce={},sig={}",
        URL_SAFE_NO_PAD.encode(kid),
        ts,
        nonce_b64,
        URL_SAFE_NO_PAD.encode(sig.as_ref()),
    )
}

fn lookup_request(auth: Option<String>) -> Request<Body> {
    let mut b = Request::builder()
        .method(Method::GET)
        .uri("/v1/pairing/sessions/lookup");
    if let Some(h) = auth {
        b = b.header("authorization", h);
    }
    b.body(Body::empty()).unwrap()
}

#[tokio::test]
async fn valid_hmac_returns_200_with_session_id() {
    let (router, _, _) = build_test_daemon();
    let auth = build_hmac_header(SHORT_CODE, None, &[0u8; 16]);
    let resp = router.oneshot(lookup_request(Some(auth))).await.unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn missing_authorization_returns_401() {
    let (router, _, _) = build_test_daemon();
    let resp = router.oneshot(lookup_request(None)).await.unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn wrong_short_code_returns_401() {
    let (router, _, _) = build_test_daemon();
    // Sign with a short code the server doesn't know.
    let auth = build_hmac_header("WRONG1", None, &[1u8; 16]);
    let resp = router.oneshot(lookup_request(Some(auth))).await.unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn expired_ts_returns_401() {
    let (router, _, _) = build_test_daemon();
    // 5 minutes ago — well outside the 30-second window.
    let stale = now() - 300;
    let auth = build_hmac_header(SHORT_CODE, Some(stale), &[2u8; 16]);
    let resp = router.oneshot(lookup_request(Some(auth))).await.unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn replayed_nonce_returns_409() {
    let (router, _, _) = build_test_daemon();
    let nonce = [3u8; 16];
    let auth = build_hmac_header(SHORT_CODE, None, &nonce);
    let resp1 = router
        .clone()
        .oneshot(lookup_request(Some(auth.clone())))
        .await
        .unwrap();
    assert_eq!(resp1.status(), 200);
    let resp2 = router.oneshot(lookup_request(Some(auth))).await.unwrap();
    assert_eq!(resp2.status(), 409);
}

#[tokio::test]
async fn tampered_signature_returns_401() {
    let (router, _, _) = build_test_daemon();
    let good = build_hmac_header(SHORT_CODE, None, &[4u8; 16]);
    // Replace the last sig byte with something else.
    let bad = good.strip_suffix("=").unwrap_or(&good).to_string() + "X";
    let resp = router.oneshot(lookup_request(Some(bad))).await.unwrap();
    // Either 400 (malformed) or 401 (bad sig) — both represent rejection.
    assert!(resp.status() == 401 || resp.status() == 400);
}
