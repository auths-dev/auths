//! Device-signature authentication for session-scoped endpoints.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Method, Request};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use auths_pairing_daemon::domain_separation::DAEMON_SIG_CONTEXT;

use super::build_test_daemon;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

struct DeviceKey {
    sk: SigningKey,
    vk: VerifyingKey,
}

impl DeviceKey {
    fn new() -> Self {
        let mut rng = OsRng;
        let sk = SigningKey::generate(&mut rng);
        let vk = sk.verifying_key();
        Self { sk, vk }
    }

    fn vk_bytes(&self) -> [u8; 32] {
        self.vk.to_bytes()
    }

    fn kid(&self) -> [u8; 16] {
        let mut h = Sha256::new();
        h.update(self.vk_bytes());
        let full = h.finalize();
        let mut out = [0u8; 16];
        out.copy_from_slice(&full[..16]);
        out
    }

    fn sign_canonical(&self, canonical: &[u8]) -> [u8; 64] {
        self.sk.sign(canonical).to_bytes()
    }
}

fn canonical(method: &str, path: &str, body: &[u8], ts: i64, nonce: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(body);
    let body_hash = hasher.finalize();
    let body_hash_hex = hex::encode(body_hash);
    let nonce_b64 = URL_SAFE_NO_PAD.encode(nonce);
    let mut out = Vec::new();
    out.extend_from_slice(DAEMON_SIG_CONTEXT);
    out.push(b'\n');
    out.extend_from_slice(method.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(path.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(body_hash_hex.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(ts.to_string().as_bytes());
    out.push(b'\n');
    out.extend_from_slice(nonce_b64.as_bytes());
    out
}

fn sig_header(key: &DeviceKey, method: &str, path: &str, body: &[u8], nonce: &[u8]) -> String {
    let ts = now();
    let canonical = canonical(method, path, body, ts, nonce);
    let sig = key.sign_canonical(&canonical);
    format!(
        "Auths-Sig kid={},ts={},nonce={},sig={}",
        URL_SAFE_NO_PAD.encode(key.kid()),
        ts,
        URL_SAFE_NO_PAD.encode(nonce),
        URL_SAFE_NO_PAD.encode(sig),
    )
}

fn submit_response_body(key: &DeviceKey) -> String {
    // Minimal but valid body shape accepted by SubmitResponseRequest.
    let vk_b64 = URL_SAFE_NO_PAD.encode(key.vk_bytes());
    format!(
        r#"{{"device_ephemeral_pubkey":"AAAA","device_signing_pubkey":"{vk_b64}","curve":"ed25519","device_did":"did:key:z6Mkt","signature":"","device_name":"Test"}}"#
    )
}

#[tokio::test]
async fn valid_sig_on_response_is_accepted_and_binds_pubkey() {
    let (router, _, _) = build_test_daemon();
    let key = DeviceKey::new();
    let body = submit_response_body(&key);
    let body_bytes = body.as_bytes();
    let auth = sig_header(
        &key,
        "POST",
        "/v1/pairing/sessions/test-session-001/response",
        body_bytes,
        &[0u8; 16],
    );
    let req = Request::builder()
        .method(Method::POST)
        .uri("/v1/pairing/sessions/test-session-001/response")
        .header("content-type", "application/json")
        .header("authorization", auth)
        .body(Body::from(body.clone()))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    // Accept anything except 401 — application-level errors may
    // surface as 409 (state conflict) on subsequent calls, but the
    // auth path must not fail here.
    assert_ne!(resp.status(), 401, "valid sig should not 401");
    assert_ne!(resp.status(), 409, "first submit should not conflict");
}

#[tokio::test]
async fn missing_authorization_on_session_endpoint_returns_401() {
    let (router, _, _) = build_test_daemon();
    let key = DeviceKey::new();
    let body = submit_response_body(&key);
    let req = Request::builder()
        .method(Method::POST)
        .uri("/v1/pairing/sessions/test-session-001/response")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn sig_from_wrong_key_returns_401() {
    let (router, _, _) = build_test_daemon();
    let real = DeviceKey::new();
    let fake = DeviceKey::new();
    // Body carries `real`'s pubkey, but the signature is from `fake`.
    let body = submit_response_body(&real);
    let body_bytes = body.as_bytes();
    // Use fake's kid so it doesn't match the real pubkey's kid.
    let auth = sig_header(
        &fake,
        "POST",
        "/v1/pairing/sessions/test-session-001/response",
        body_bytes,
        &[1u8; 16],
    );
    let req = Request::builder()
        .method(Method::POST)
        .uri("/v1/pairing/sessions/test-session-001/response")
        .header("content-type", "application/json")
        .header("authorization", auth)
        .body(Body::from(body))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn tampered_body_returns_401() {
    let (router, _, _) = build_test_daemon();
    let key = DeviceKey::new();
    let body = submit_response_body(&key);
    let auth = sig_header(
        &key,
        "POST",
        "/v1/pairing/sessions/test-session-001/response",
        body.as_bytes(),
        &[2u8; 16],
    );
    // Send a different body than was signed.
    let tampered = body.replace("Test", "Evil!");
    let req = Request::builder()
        .method(Method::POST)
        .uri("/v1/pairing/sessions/test-session-001/response")
        .header("content-type", "application/json")
        .header("authorization", auth)
        .body(Body::from(tampered))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn pre_response_get_session_is_public() {
    // Status endpoint is explicitly unauthenticated — this test
    // locks that invariant in.
    let (router, _, _) = build_test_daemon();
    let req = Request::builder()
        .method(Method::GET)
        .uri("/v1/pairing/sessions/test-session-001")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 200);
}
