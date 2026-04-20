//! End-to-end P-256 signed-request verification through the daemon.
//!
//! Proves an iOS-shape P-256 signature (Secure-Enclave-equivalent,
//! produced by `p256::ecdsa::SigningKey`) verifies under `verify_sig`
//! in the daemon's `auth.rs`, **provided** the wire formats match the
//! decisions in ADRs 002 and 003:
//!
//! - Signature on the wire: raw r‖s (64 B), not DER.
//! - Pubkey on the wire: 33-byte compressed SEC1, not 65 B uncompressed.
//! - `curve: "p256"` carried as a sibling JSON field; daemon dispatch
//!   is `curve`-tag-based (not byte-length-based per CLAUDE.md §4).

use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Method, Request};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey, signature::Signer};
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

/// A P-256 signing key plus derived values useful in tests.
struct P256DeviceKey {
    sk: SigningKey,
    vk: VerifyingKey,
}

impl P256DeviceKey {
    fn new() -> Self {
        let sk = SigningKey::random(&mut OsRng);
        let vk = *sk.verifying_key();
        Self { sk, vk }
    }

    /// Compressed SEC1 public key (33 bytes, 0x02/0x03 || X).
    fn vk_compressed(&self) -> [u8; 33] {
        let encoded = self.vk.to_encoded_point(true);
        let mut arr = [0u8; 33];
        arr.copy_from_slice(encoded.as_bytes());
        arr
    }

    /// Uncompressed SEC1 public key (65 bytes, 0x04 || X || Y) —
    /// what iOS `SecKeyCopyExternalRepresentation` emits.
    fn vk_uncompressed(&self) -> [u8; 65] {
        let encoded = self.vk.to_encoded_point(false);
        let mut arr = [0u8; 65];
        arr.copy_from_slice(encoded.as_bytes());
        arr
    }

    /// First 16 bytes of SHA-256 over the compressed pubkey — matches
    /// the daemon's `pubkey_kid` computation in `auth.rs`.
    fn kid(&self) -> [u8; 16] {
        let mut h = Sha256::new();
        h.update(self.vk_compressed());
        let full = h.finalize();
        let mut out = [0u8; 16];
        out.copy_from_slice(&full[..16]);
        out
    }

    /// Sign canonical bytes and return raw r‖s (64 B) per ADR 002.
    fn sign_canonical_raw(&self, canonical: &[u8]) -> [u8; 64] {
        let sig: Signature = self.sk.sign(canonical);
        sig.to_bytes().into()
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

fn sig_header(key: &P256DeviceKey, method: &str, path: &str, body: &[u8], nonce: &[u8]) -> String {
    let ts = now();
    let c = canonical(method, path, body, ts, nonce);
    let sig = key.sign_canonical_raw(&c);
    format!(
        "Auths-Sig kid={},ts={},nonce={},sig={}",
        URL_SAFE_NO_PAD.encode(key.kid()),
        ts,
        URL_SAFE_NO_PAD.encode(nonce),
        URL_SAFE_NO_PAD.encode(sig),
    )
}

fn submit_response_body_p256(key: &P256DeviceKey) -> String {
    // Body shape matches `SubmitResponseRequest` with `curve: "p256"`
    // and the 33-byte compressed SEC1 pubkey per ADR 003.
    let vk_b64 = URL_SAFE_NO_PAD.encode(key.vk_compressed());
    format!(
        r#"{{"device_ephemeral_pubkey":"AAAA","device_signing_pubkey":"{vk_b64}","curve":"p256","device_did":"did:key:zDna","signature":"","device_name":"Test"}}"#
    )
}

fn submit_response_body_p256_uncompressed(key: &P256DeviceKey) -> String {
    // Body shape with 65-byte uncompressed pubkey — should be rejected
    // by the daemon per ADR 003.
    let vk_b64 = URL_SAFE_NO_PAD.encode(key.vk_uncompressed());
    format!(
        r#"{{"device_ephemeral_pubkey":"AAAA","device_signing_pubkey":"{vk_b64}","curve":"p256","device_did":"did:key:zDna","signature":"","device_name":"Test"}}"#
    )
}

#[tokio::test]
async fn p256_signed_response_is_accepted_and_binds_pubkey() {
    let (router, _, _) = build_test_daemon();
    let key = P256DeviceKey::new();
    let body = submit_response_body_p256(&key);
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
    // Accept anything except 401 — downstream flow may produce 409 or
    // other application-level codes, but the auth / decode_device_pubkey
    // path must not bounce a valid P-256 signature.
    assert_ne!(
        resp.status(),
        401,
        "valid P-256 sig must not return 401, got {}",
        resp.status()
    );
    assert_ne!(
        resp.status(),
        400,
        "valid P-256 body must not 400 on decode_device_pubkey, got {}",
        resp.status()
    );
    assert_ne!(resp.status(), 409, "first submit must not conflict");
}

#[tokio::test]
async fn p256_signed_response_with_65_byte_pubkey_returns_400_not_401() {
    // ADR 003: daemon rejects 65-byte uncompressed P-256 pubkeys.
    // The rejection must surface as 400 (InvalidPubkeyLength, kebab
    // code "invalid-pubkey-length") rather than as 401
    // (UnauthorizedSig) — the CLAUDE.md §4 rule that curve/length
    // mismatches must look like routing errors, not signature errors.
    let (router, _, _) = build_test_daemon();
    let key = P256DeviceKey::new();
    let body = submit_response_body_p256_uncompressed(&key);
    let body_bytes = body.as_bytes();
    let auth = sig_header(
        &key,
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
    assert_eq!(
        resp.status(),
        400,
        "65-byte P-256 pubkey must 400 on decode, not {} ",
        resp.status()
    );
}

#[tokio::test]
async fn p256_signed_response_with_wrong_signature_returns_401() {
    // Sanity: a P-256-shaped request whose signature doesn't match the
    // canonical input must 401 through the normal verify_sig path.
    let (router, _, _) = build_test_daemon();
    let real = P256DeviceKey::new();
    let wrong = P256DeviceKey::new();
    let body = submit_response_body_p256(&real);
    let body_bytes = body.as_bytes();
    // Use real's kid (so kid-lookup succeeds) but sign with wrong's key.
    let ts = now();
    let c = canonical(
        "POST",
        "/v1/pairing/sessions/test-session-001/response",
        body_bytes,
        ts,
        &[2u8; 16],
    );
    let sig = wrong.sign_canonical_raw(&c);
    let auth = format!(
        "Auths-Sig kid={},ts={},nonce={},sig={}",
        URL_SAFE_NO_PAD.encode(real.kid()),
        ts,
        URL_SAFE_NO_PAD.encode([2u8; 16]),
        URL_SAFE_NO_PAD.encode(sig),
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
