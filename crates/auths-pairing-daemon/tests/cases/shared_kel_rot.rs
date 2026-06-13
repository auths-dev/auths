//! End-to-end test of the shared-KEL rotation receive endpoint.
//!
//! A paired device (P-256, Secure-Enclave-shape) binds its pubkey via
//! `POST /response`, then submits a co-authored rotation envelope to
//! `POST /shared-kel-rot`. The daemon must:
//! - accept only under the session-bound `Auths-Sig` key,
//! - decode the envelope and verify its CESR indexed signatures against
//!   the rotation's own key list before storing anything,
//! - hold exactly one rotation for the embedding host (`take_shared_kel_rot`),
//! - reject a tampered envelope with the typed 400 (`invalid-shared-kel-rot`).

use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Method, Request};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey, signature::Signer};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use auths_keri::{
    CesrKey, Event, IndexedSignature, KeriPublicKey, KeriSequence, Prefix, RotEvent, RotEventInit,
    Said, Threshold, VersionString, encode_signed_rot, finalize_rot_event, serialize_attachment,
    serialize_for_signing,
};
use auths_pairing_daemon::domain_separation::DAEMON_SIG_CONTEXT;

use super::build_test_daemon;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

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

    fn vk_compressed(&self) -> [u8; 33] {
        let encoded = self.vk.to_encoded_point(true);
        let mut arr = [0u8; 33];
        arr.copy_from_slice(encoded.as_bytes());
        arr
    }

    fn kid(&self) -> [u8; 16] {
        let mut h = Sha256::new();
        h.update(self.vk_compressed());
        let full = h.finalize();
        let mut out = [0u8; 16];
        out.copy_from_slice(&full[..16]);
        out
    }

    fn sign_canonical_raw(&self, canonical: &[u8]) -> [u8; 64] {
        let sig: Signature = self.sk.sign(canonical);
        sig.to_bytes().into()
    }
}

fn canonical(method: &str, path: &str, body: &[u8], ts: i64, nonce: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(body);
    let body_hash_hex = hex::encode(hasher.finalize());
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

/// Bind `key` to the session via `POST /response` (first signed request).
async fn bind_pubkey(router: axum::Router, key: &P256DeviceKey) {
    let vk_b64 = URL_SAFE_NO_PAD.encode(key.vk_compressed());
    let body = format!(
        r#"{{"device_ephemeral_pubkey":"AAAA","device_signing_pubkey":"{vk_b64}","curve":"p256","device_did":"did:key:zDna","signature":"","device_name":"Test"}}"#
    );
    let path = "/v1/pairing/sessions/test-session-001/response";
    let auth = sig_header(key, "POST", path, body.as_bytes(), &[7u8; 16]);
    let req = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header("content-type", "application/json")
        .header("authorization", auth)
        .body(Body::from(body))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert!(
        resp.status().is_success(),
        "pubkey bind (submit response) failed: {}",
        resp.status()
    );
}

/// Build a valid signed-rot wire envelope: a single-controller rotation
/// whose indexed signature verifies against its own `k[0]`.
fn valid_rot_envelope(controller: &SigningKey) -> String {
    let compressed: [u8; 33] = controller
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap();
    let pk = KeriPublicKey::P256 {
        key: compressed,
        transferable: true,
    };
    // A structurally-valid prior SAID (any Blake3 digest will do — the
    // daemon's gate does not replay chain linkage; the host does).
    let prior_said = auths_keri::compute_next_commitment(&pk);
    let rot = finalize_rot_event(RotEvent::new(RotEventInit {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: Prefix::new_unchecked("EOZZSHAREDKELPREFIXxxxxxxxxxxxxxxxxxxxxxxxxx".into()),
        s: KeriSequence::new(1),
        p: prior_said,
        kt: Threshold::Simple(1),
        k: vec![CesrKey::new_unchecked(pk.to_qb64().unwrap())],
        nt: Threshold::Simple(1),
        n: vec![],
        bt: Threshold::Simple(0),
        br: vec![],
        ba: vec![],
        c: vec![],
        a: vec![],
    }))
    .unwrap();
    let canonical = serialize_for_signing(&Event::Rot(rot.clone())).unwrap();
    let sig: Signature = controller.sign(&canonical);
    let raw: [u8; 64] = sig.to_bytes().into();
    let attachment = serialize_attachment(&[IndexedSignature {
        index: 0,
        prior_index: None,
        sig: raw.to_vec(),
    }])
    .unwrap();
    encode_signed_rot(&rot, &attachment).unwrap()
}

#[tokio::test]
async fn signed_rot_envelope_is_received_and_held_for_the_host() {
    let (router, state, _) = build_test_daemon();
    let key = P256DeviceKey::new();
    bind_pubkey(router.clone(), &key).await;

    let controller = SigningKey::random(&mut OsRng);
    let envelope = valid_rot_envelope(&controller);
    let body = format!(r#"{{"rot_envelope":"{envelope}"}}"#);
    let path = "/v1/pairing/sessions/test-session-001/shared-kel-rot";
    let auth = sig_header(&key, "POST", path, body.as_bytes(), &[8u8; 16]);
    let req = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header("content-type", "application/json")
        .header("authorization", auth)
        .body(Body::from(body))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert!(
        resp.status().is_success(),
        "valid rot envelope must be accepted, got {}",
        resp.status()
    );

    let held = state
        .take_shared_kel_rot()
        .await
        .expect("host must find the received rotation");
    assert_eq!(held.rot_envelope, envelope);
    assert!(
        state.take_shared_kel_rot().await.is_none(),
        "take is single-shot"
    );
}

#[tokio::test]
async fn tampered_rot_envelope_is_rejected_with_typed_400() {
    let (router, state, _) = build_test_daemon();
    let key = P256DeviceKey::new();
    bind_pubkey(router.clone(), &key).await;

    let controller = SigningKey::random(&mut OsRng);
    let envelope = valid_rot_envelope(&controller);
    // Re-sign the same event with a DIFFERENT key: the envelope decodes
    // fine but the indexed signature no longer verifies against k[0].
    let (rot, _attachment) = auths_keri::decode_signed_rot(&envelope).unwrap();
    let attacker = SigningKey::random(&mut OsRng);
    let canonical = serialize_for_signing(&Event::Rot(rot.clone())).unwrap();
    let bad_sig: Signature = attacker.sign(&canonical);
    let raw: [u8; 64] = bad_sig.to_bytes().into();
    let bad_attachment = serialize_attachment(&[IndexedSignature {
        index: 0,
        prior_index: None,
        sig: raw.to_vec(),
    }])
    .unwrap();
    let forged = encode_signed_rot(&rot, &bad_attachment).unwrap();

    let body = format!(r#"{{"rot_envelope":"{forged}"}}"#);
    let path = "/v1/pairing/sessions/test-session-001/shared-kel-rot";
    let auth = sig_header(&key, "POST", path, body.as_bytes(), &[9u8; 16]);
    let req = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header("content-type", "application/json")
        .header("authorization", auth)
        .body(Body::from(body))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        400,
        "forged indexed signature must be rejected at the boundary"
    );
    assert!(
        state.take_shared_kel_rot().await.is_none(),
        "a rejected envelope must never be stored"
    );
}

#[tokio::test]
async fn unbound_key_cannot_submit_a_rot() {
    // No prior /response — no bound pubkey — the endpoint must 401
    // before doing any envelope work.
    let (router, state, _) = build_test_daemon();
    let key = P256DeviceKey::new();
    let controller = SigningKey::random(&mut OsRng);
    let envelope = valid_rot_envelope(&controller);
    let body = format!(r#"{{"rot_envelope":"{envelope}"}}"#);
    let path = "/v1/pairing/sessions/test-session-001/shared-kel-rot";
    let auth = sig_header(&key, "POST", path, body.as_bytes(), &[10u8; 16]);
    let req = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header("content-type", "application/json")
        .header("authorization", auth)
        .body(Body::from(body))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), 401);
    assert!(state.take_shared_kel_rot().await.is_none());
}
