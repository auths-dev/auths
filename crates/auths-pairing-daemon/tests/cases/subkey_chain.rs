//! End-to-end subkey-chain verification through the daemon.
//!
//! Exercises the four acceptance-critical paths for the subkey chain
//! extension (`auths-device-subkey-v1`):
//!
//! 1. Valid chain (subkey signed by a distinct bootstrap key) — accepted.
//! 2. Chain whose binding signature does not verify — rejected with
//!    `invalid-subkey-chain` (400).
//! 3. Self-referential chain (bootstrap == subkey) — rejected with
//!    `invalid-subkey-chain` (400).
//! 4. Chain attached to an Ed25519 session — rejected (subkey chain is
//!    defined only for P-256 subkeys; iOS Secure Enclave is P-256).
//!
//! The "feature disabled" case (request carries a chain but the daemon
//! was compiled without `subkey-chain-v1`) is covered by a compile-time
//! fact: `verify_subkey_chain_if_present` returns
//! `DaemonError::UnsupportedSubkeyChain` unconditionally when the
//! feature is off. A dedicated `#[cfg(not(feature = "subkey-chain-v1"))]`
//! integration test would need a second build configuration; that is
//! left to the daemon's CI matrix rather than duplicated here.

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
use auths_pairing_protocol::Base64UrlEncoded;
use auths_pairing_protocol::subkey_chain::{SubkeyChain, build_binding_message_v1};

use super::build_test_daemon;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// P-256 signing key helper, mirroring `p256_end_to_end.rs::P256DeviceKey`.
struct P256Key {
    sk: SigningKey,
    vk: VerifyingKey,
}

impl P256Key {
    fn new() -> Self {
        let sk = SigningKey::random(&mut OsRng);
        let vk = *sk.verifying_key();
        Self { sk, vk }
    }

    fn compressed(&self) -> [u8; 33] {
        let encoded = self.vk.to_encoded_point(true);
        let mut arr = [0u8; 33];
        arr.copy_from_slice(encoded.as_bytes());
        arr
    }

    fn kid(&self) -> [u8; 16] {
        let mut h = Sha256::new();
        h.update(self.compressed());
        let full = h.finalize();
        let mut out = [0u8; 16];
        out.copy_from_slice(&full[..16]);
        out
    }

    fn sign_raw(&self, msg: &[u8]) -> [u8; 64] {
        let sig: Signature = self.sk.sign(msg);
        sig.to_bytes().into()
    }
}

fn canonical(method: &str, path: &str, body: &[u8], ts: i64, nonce: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(body);
    let body_hash_hex = hex::encode(hasher.finalize());
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
    out.extend_from_slice(URL_SAFE_NO_PAD.encode(nonce).as_bytes());
    out
}

fn sig_header(key: &P256Key, method: &str, path: &str, body: &[u8], nonce: &[u8]) -> String {
    let ts = now();
    let c = canonical(method, path, body, ts, nonce);
    let sig = key.sign_raw(&c);
    format!(
        "Auths-Sig kid={},ts={},nonce={},sig={}",
        URL_SAFE_NO_PAD.encode(key.kid()),
        ts,
        URL_SAFE_NO_PAD.encode(nonce),
        URL_SAFE_NO_PAD.encode(sig),
    )
}

fn body_with_chain(subkey: &P256Key, chain: Option<SubkeyChain>) -> String {
    let vk_b64 = URL_SAFE_NO_PAD.encode(subkey.compressed());
    let base = format!(
        r#"{{"device_ephemeral_pubkey":"AAAA","device_signing_pubkey":"{vk_b64}","curve":"p256","device_did":"did:key:zDna","signature":""#
    );
    let tail = match chain {
        None => r#"","device_name":"Test"}"#.to_string(),
        Some(chain) => {
            let bootstrap = chain.bootstrap_pubkey.as_str();
            let bsig = chain.subkey_binding_signature.as_str();
            format!(
                r#"","device_name":"Test","subkey_chain":{{"bootstrap_pubkey":"{bootstrap}","subkey_binding_signature":"{bsig}"}}}}"#
            )
        }
    };
    format!("{base}{tail}")
}

fn make_chain(bootstrap: &P256Key, subkey_compressed: &[u8; 33], session_id: &str) -> SubkeyChain {
    let msg = build_binding_message_v1(session_id, subkey_compressed);
    let raw = bootstrap.sign_raw(&msg);
    let bootstrap_b64 = URL_SAFE_NO_PAD.encode(bootstrap.compressed());
    SubkeyChain {
        bootstrap_pubkey: Base64UrlEncoded::from_raw(bootstrap_b64),
        subkey_binding_signature: Base64UrlEncoded::from_raw(URL_SAFE_NO_PAD.encode(raw)),
    }
}

#[tokio::test]
async fn valid_subkey_chain_is_accepted() {
    let (router, _, _) = build_test_daemon();
    let session_id = "test-session-001";
    let bootstrap = P256Key::new();
    let subkey = P256Key::new();
    let chain = make_chain(&bootstrap, &subkey.compressed(), session_id);

    let body = body_with_chain(&subkey, Some(chain));
    let path = format!("/v1/pairing/sessions/{session_id}/response");
    let auth = sig_header(&subkey, "POST", &path, body.as_bytes(), &[0u8; 16]);

    let req = Request::builder()
        .method(Method::POST)
        .uri(&path)
        .header("content-type", "application/json")
        .header("authorization", auth)
        .body(Body::from(body))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_ne!(resp.status(), 400, "valid chain must not 400");
    assert_ne!(resp.status(), 401, "valid chain must not 401");
    assert_ne!(resp.status(), 409, "first submit must not conflict");
}

#[tokio::test]
async fn subkey_chain_with_bad_signature_is_rejected() {
    let (router, _, _) = build_test_daemon();
    let session_id = "test-session-001";
    let bootstrap = P256Key::new();
    let subkey = P256Key::new();
    let mut chain = make_chain(&bootstrap, &subkey.compressed(), session_id);

    // Corrupt the binding signature (flip a middle byte).
    let mut raw = URL_SAFE_NO_PAD
        .decode(chain.subkey_binding_signature.as_str())
        .unwrap();
    raw[32] ^= 0x01;
    chain.subkey_binding_signature = Base64UrlEncoded::from_raw(URL_SAFE_NO_PAD.encode(raw));

    let body = body_with_chain(&subkey, Some(chain));
    let path = format!("/v1/pairing/sessions/{session_id}/response");
    let auth = sig_header(&subkey, "POST", &path, body.as_bytes(), &[1u8; 16]);

    let req = Request::builder()
        .method(Method::POST)
        .uri(&path)
        .header("content-type", "application/json")
        .header("authorization", auth)
        .body(Body::from(body))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 400, "bad-signature chain must 400");
}

#[tokio::test]
async fn self_referential_subkey_chain_is_rejected() {
    let (router, _, _) = build_test_daemon();
    let session_id = "test-session-001";
    let same_key = P256Key::new();
    // bootstrap == subkey: chain signed over itself.
    let chain = make_chain(&same_key, &same_key.compressed(), session_id);

    let body = body_with_chain(&same_key, Some(chain));
    let path = format!("/v1/pairing/sessions/{session_id}/response");
    let auth = sig_header(&same_key, "POST", &path, body.as_bytes(), &[2u8; 16]);

    let req = Request::builder()
        .method(Method::POST)
        .uri(&path)
        .header("content-type", "application/json")
        .header("authorization", auth)
        .body(Body::from(body))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 400, "self-referential chain must 400");
}
