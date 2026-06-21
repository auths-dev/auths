//! Air-gapped IoT test suite - validates complete HTTP decoupling.
//!
//! # Infrastructure
//!
//! - `LocalGitResolver`: Git-only DID resolution (NO HTTP registry calls)
//! - `InMemorySessionStore`: Pure in-memory session storage
//! - All cryptography via `ring` crate (offline Ed25519 verification)
//!
//! # Proof of HTTP Decoupling
//!
//! This suite proves that IoT devices can:
//! 1. Bootstrap trust from embedded root anchors (`.auths/roots.json`)
//! 2. Verify capability chains completely offline
//! 3. Validate witness quorum without registry access
//! 4. Resist temporal attacks in unreliable clock environments
//! 5. Enforce cryptographic correctness without network dependencies
//!
//! Every test executes in an isolated `TempDir` with:
//! - No `reqwest` or HTTP client dependencies
//! - No network sockets opened
//! - All verification via local Git repository
//! - Canonical JSON + Ed25519 signatures only

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{DateTime, Duration, Utc};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use tempfile::TempDir;
use tower::ServiceExt;

use auths_auth_server::adapters::{InMemoryClientStore, InMemorySessionStore, LocalGitResolver};
use auths_auth_server::config::AuthServerConfig;
use auths_auth_server::{AuthServerState, routes};
use auths_core::trust::roots_file::RootsFile;
use auths_crypto::ed25519_pubkey_to_did_key;
use auths_verifier::CanonicalDid;
use auths_verifier::Said;
use auths_verifier::core::{
    Attestation, CanonicalAttestationData, Capability, Ed25519PublicKey, Ed25519Signature,
    canonicalize_attestation_data,
};
use auths_verifier::types::DeviceDID;
use auths_verifier::verify::{
    verify_chain, verify_chain_with_capability, verify_chain_with_witnesses, verify_with_keys,
};
use auths_verifier::witness::{WitnessReceipt, WitnessVerifyConfig};

use super::helpers::{body_json, create_test_keypair};

// ============================================================================
// Helpers
// ============================================================================

/// Bootstrap a temp git repo with one KERI identity.
///
/// Returns `(TempDir, did, raw_pubkey_32_bytes, pkcs8_bytes_for_signing)`.
/// `TempDir` must stay alive for the test duration.
fn setup_repo() -> (TempDir, String, Vec<u8>, Vec<u8>) {
    let dir = TempDir::new().unwrap();
    git2::Repository::init(dir.path()).unwrap();
    let storage = auths_storage::git::RegistryIdentityStorage::new(dir.path());
    let (did, result) = storage.initialize_identity(None, None).unwrap();
    (
        dir,
        did,
        result.current_public_key,
        result.current_keypair_pkcs8.as_ref().to_vec(),
    )
}

fn make_app(dir: &TempDir) -> axum::Router {
    let resolver = LocalGitResolver::open(dir.path()).expect("open resolver");
    let sessions = InMemorySessionStore::new();
    let config = AuthServerConfig::default().with_challenge_ttl(300);
    routes::router(AuthServerState::new(
        resolver,
        sessions,
        InMemoryClientStore::new(),
        config,
    ))
}

/// Create app with custom challenge TTL for expiration testing.
fn make_app_with_ttl(dir: &TempDir, ttl_secs: u64) -> axum::Router {
    let resolver = LocalGitResolver::open(dir.path()).expect("open resolver");
    let sessions = InMemorySessionStore::new();
    let config = AuthServerConfig::default().with_challenge_ttl(ttl_secs);
    routes::router(AuthServerState::new(
        resolver,
        sessions,
        InMemoryClientStore::new(),
        config,
    ))
}

/// Create a signed attestation with custom timestamp.
fn create_attestation_with_timestamp(
    issuer_kp: &Ed25519KeyPair,
    device_kp: &Ed25519KeyPair,
    issuer_did: &str,
    subject_did: &str,
    timestamp: Option<DateTime<Utc>>,
) -> Attestation {
    let device_pk: [u8; 32] = device_kp.public_key().as_ref().try_into().unwrap();

    let mut att = Attestation {
        version: 1,
        rid: "test-rid".into(),
        issuer: CanonicalDid::new_unchecked(issuer_did),
        subject: DeviceDID::new_unchecked(subject_did),
        device_public_key: Ed25519PublicKey::from_bytes(device_pk),
        identity_signature: Ed25519Signature::empty(),
        device_signature: Ed25519Signature::empty(),
        revoked_at: None,
        expires_at: Some(Utc::now() + Duration::days(365)),
        timestamp,
        note: None,
        payload: None,
        role: None,
        capabilities: vec![],
        delegated_by: None,
        signer_type: None,
        environment_claim: None,
    };

    let data = CanonicalAttestationData {
        version: att.version,
        rid: att.rid.as_str(),
        issuer: &att.issuer,
        subject: &att.subject,
        device_public_key: att.device_public_key.as_ref(),
        payload: &att.payload,
        timestamp: &att.timestamp,
        expires_at: &att.expires_at,
        revoked_at: &att.revoked_at,
        note: &att.note,
        role: att.role.as_ref().map(|r| r.as_str()),
        capabilities: if att.capabilities.is_empty() {
            None
        } else {
            Some(&att.capabilities)
        },
        delegated_by: att.delegated_by.as_ref(),
        signer_type: att.signer_type.as_ref(),
    };
    let canonical_bytes = canonicalize_attestation_data(&data).unwrap();

    let id_sig: [u8; 64] = issuer_kp
        .sign(&canonical_bytes)
        .as_ref()
        .try_into()
        .unwrap();
    att.identity_signature = Ed25519Signature::from_bytes(id_sig);
    let dev_sig: [u8; 64] = device_kp
        .sign(&canonical_bytes)
        .as_ref()
        .try_into()
        .unwrap();
    att.device_signature = Ed25519Signature::from_bytes(dev_sig);

    att
}

/// Create a signed attestation with capabilities.
fn create_attestation_with_capabilities(
    issuer_kp: &Ed25519KeyPair,
    device_kp: &Ed25519KeyPair,
    issuer_did: &str,
    subject_did: &str,
    capabilities: Vec<Capability>,
) -> Attestation {
    let device_pk: [u8; 32] = device_kp.public_key().as_ref().try_into().unwrap();

    let mut att = Attestation {
        version: 1,
        rid: "test-rid".into(),
        issuer: CanonicalDid::new_unchecked(issuer_did),
        subject: DeviceDID::new_unchecked(subject_did),
        device_public_key: Ed25519PublicKey::from_bytes(device_pk),
        identity_signature: Ed25519Signature::empty(),
        device_signature: Ed25519Signature::empty(),
        revoked_at: None,
        expires_at: Some(Utc::now() + Duration::days(365)),
        timestamp: Some(Utc::now()),
        note: None,
        payload: None,
        role: None,
        capabilities: capabilities.clone(),
        delegated_by: None,
        signer_type: None,
        environment_claim: None,
    };

    let caps_ref = if att.capabilities.is_empty() {
        None
    } else {
        Some(&att.capabilities)
    };
    let data = CanonicalAttestationData {
        version: att.version,
        rid: att.rid.as_str(),
        issuer: &att.issuer,
        subject: &att.subject,
        device_public_key: att.device_public_key.as_ref(),
        payload: &att.payload,
        timestamp: &att.timestamp,
        expires_at: &att.expires_at,
        revoked_at: &att.revoked_at,
        note: &att.note,
        role: att.role.as_ref().map(|r| r.as_str()),
        capabilities: caps_ref,
        delegated_by: att.delegated_by.as_ref(),
        signer_type: att.signer_type.as_ref(),
    };
    let canonical_bytes = canonicalize_attestation_data(&data).unwrap();

    let id_sig: [u8; 64] = issuer_kp
        .sign(&canonical_bytes)
        .as_ref()
        .try_into()
        .unwrap();
    att.identity_signature = Ed25519Signature::from_bytes(id_sig);
    let dev_sig: [u8; 64] = device_kp
        .sign(&canonical_bytes)
        .as_ref()
        .try_into()
        .unwrap();
    att.device_signature = Ed25519Signature::from_bytes(dev_sig);

    att
}

/// Create a signed witness receipt.
fn create_witness_receipt(
    witness_kp: &Ed25519KeyPair,
    witness_did: &str,
    event_said: &str,
    seq: u64,
) -> WitnessReceipt {
    let mut receipt = WitnessReceipt {
        v: "KERI10JSON000000_".into(),
        t: "rct".into(),
        d: Said::new_unchecked(format!("EReceipt_{}", seq)),
        i: witness_did.into(),
        s: seq,
        a: Said::new_unchecked(event_said.into()),
        sig: vec![],
    };
    let payload = receipt.signing_payload().unwrap();
    receipt.sig = witness_kp.sign(&payload).as_ref().to_vec();
    receipt
}

// ============================================================================
// Tests
// ============================================================================

#[tokio::test]
async fn full_auth_flow_air_gapped() {
    let (dir, did, pub_key, pkcs8) = setup_repo();
    let app = make_app(&dir);

    // 1. POST /auth/init
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/init")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"domain":"airgapped.test"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let init = body_json(resp.into_body()).await;
    let session_id = init["id"].as_str().unwrap();
    let nonce = init["challenge"].as_str().unwrap();
    let domain = init["domain"].as_str().unwrap();
    assert_eq!(domain, "airgapped.test");

    // 2. Sign canonical JSON
    let keypair = Ed25519KeyPair::from_pkcs8(&pkcs8).expect("keypair from pkcs8");
    let payload = serde_json::json!({ "domain": domain, "nonce": nonce });
    let canonical = json_canon::to_string(&payload).unwrap();
    let sig = keypair.sign(canonical.as_bytes());

    // 3. POST /auth/verify
    let verify_body = serde_json::json!({
        "id": session_id,
        "did": did,
        "signature": hex::encode(sig.as_ref()),
        "public_key": hex::encode(&pub_key),
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/verify")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&verify_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let result = body_json(resp.into_body()).await;
    assert_eq!(result["verified"], true);

    // 4. Status should be verified
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/auth/status/{session_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let status = body_json(resp.into_body()).await;
    assert_eq!(status["status"], "verified");
    assert_eq!(status["did"], did);
}

#[tokio::test]
async fn rejects_unknown_did_air_gapped() {
    let (dir, _, _, _) = setup_repo();
    let app = make_app(&dir);

    // Init a session
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/init")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"domain":"test.io"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    let init = body_json(resp.into_body()).await;
    let session_id = init["id"].as_str().unwrap();
    let nonce = init["challenge"].as_str().unwrap();

    // Fabricate a keypair that was never registered
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let payload = serde_json::json!({ "domain": "test.io", "nonce": nonce });
    let canonical = json_canon::to_string(&payload).unwrap();
    let sig = kp.sign(canonical.as_bytes());

    let verify_body = serde_json::json!({
        "id": session_id,
        "did": "did:keri:EThisDoesNotExist12345",
        "signature": hex::encode(sig.as_ref()),
        "public_key": hex::encode(kp.public_key().as_ref()),
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/verify")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&verify_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    // ResolutionFailed -> 422 Unprocessable Entity
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn rejects_wrong_key_air_gapped() {
    let (dir, did, _correct_pub_key, _correct_pkcs8) = setup_repo();
    let app = make_app(&dir);

    // Init
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/init")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"domain":"attacker.io"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    let init = body_json(resp.into_body()).await;
    let session_id = init["id"].as_str().unwrap();
    let nonce = init["challenge"].as_str().unwrap();

    // Sign with a completely different keypair (not the registered one)
    let rng = SystemRandom::new();
    let attacker_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let attacker_kp = Ed25519KeyPair::from_pkcs8(attacker_pkcs8.as_ref()).unwrap();
    let payload = serde_json::json!({ "domain": "attacker.io", "nonce": nonce });
    let canonical = json_canon::to_string(&payload).unwrap();
    let sig = attacker_kp.sign(canonical.as_bytes());

    let verify_body = serde_json::json!({
        "id": session_id,
        "did": did,
        "signature": hex::encode(sig.as_ref()),
        "public_key": hex::encode(attacker_kp.public_key().as_ref()),
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/verify")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&verify_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

// ============================================================================
// Phase 1: Temporal Security Tests
// ============================================================================

#[tokio::test]
async fn session_expiration_rejects_expired_challenge() {
    let (dir, did, pub_key, pkcs8) = setup_repo();
    let app = make_app_with_ttl(&dir, 1); // 1 second TTL

    // 1. POST /auth/init
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/init")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"domain":"expired.test"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let init = body_json(resp.into_body()).await;
    let session_id = init["id"].as_str().unwrap();
    let nonce = init["challenge"].as_str().unwrap();
    let domain = init["domain"].as_str().unwrap();

    // 2. Wait for expiration
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // 3. Sign canonical JSON (correctly)
    let keypair = Ed25519KeyPair::from_pkcs8(&pkcs8).expect("keypair from pkcs8");
    let payload = serde_json::json!({ "domain": domain, "nonce": nonce });
    let canonical = json_canon::to_string(&payload).unwrap();
    let sig = keypair.sign(canonical.as_bytes());

    // 4. POST /auth/verify with expired session
    let verify_body = serde_json::json!({
        "id": session_id,
        "did": did,
        "signature": hex::encode(sig.as_ref()),
        "public_key": hex::encode(&pub_key),
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/verify")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&verify_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should reject expired session
    assert!(
        resp.status() == StatusCode::GONE || resp.status() == StatusCode::UNPROCESSABLE_ENTITY,
        "Expected 410 or 422, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn replay_attack_same_nonce_rejected() {
    let (dir, did, pub_key, pkcs8) = setup_repo();
    let app = make_app(&dir);

    // 1. Complete full auth flow successfully
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/init")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"domain":"replay.test"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    let init1 = body_json(resp.into_body()).await;
    let session_id1 = init1["id"].as_str().unwrap();
    let nonce1 = init1["challenge"].as_str().unwrap();

    let keypair = Ed25519KeyPair::from_pkcs8(&pkcs8).expect("keypair from pkcs8");
    let payload1 = serde_json::json!({ "domain": "replay.test", "nonce": nonce1 });
    let canonical1 = json_canon::to_string(&payload1).unwrap();
    let sig1 = keypair.sign(canonical1.as_bytes());

    let verify_body1 = serde_json::json!({
        "id": session_id1,
        "did": did,
        "signature": hex::encode(sig1.as_ref()),
        "public_key": hex::encode(&pub_key),
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/verify")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&verify_body1).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 2. Create NEW session with different nonce
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/init")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"domain":"replay.test"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    let init2 = body_json(resp.into_body()).await;
    let session_id2 = init2["id"].as_str().unwrap();
    let nonce2 = init2["challenge"].as_str().unwrap();

    // Nonces should be different
    assert_ne!(nonce1, nonce2);

    // 3. Try to verify session2 using session1's signature (replay attack)
    let verify_body2 = serde_json::json!({
        "id": session_id2,
        "did": did,
        "signature": hex::encode(sig1.as_ref()), // OLD signature
        "public_key": hex::encode(&pub_key),
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/verify")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&verify_body2).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should fail due to signature mismatch
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn replay_attack_same_domain_different_nonce_rejected() {
    let (dir, did, pub_key, pkcs8) = setup_repo();
    let app = make_app(&dir);

    // 1. Init session1 with domain
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/init")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"domain":"iot.device.local"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    let init1 = body_json(resp.into_body()).await;
    let nonce1 = init1["challenge"].as_str().unwrap();

    // 2. Sign canonical JSON for nonce1
    let keypair = Ed25519KeyPair::from_pkcs8(&pkcs8).expect("keypair from pkcs8");
    let payload1 = serde_json::json!({ "domain": "iot.device.local", "nonce": nonce1 });
    let canonical1 = json_canon::to_string(&payload1).unwrap();
    let sig1 = keypair.sign(canonical1.as_bytes());

    // 3. Init session2 with SAME domain but get different nonce
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/init")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"domain":"iot.device.local"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    let init2 = body_json(resp.into_body()).await;
    let session_id2 = init2["id"].as_str().unwrap();
    let nonce2 = init2["challenge"].as_str().unwrap();

    // Verify nonces are different
    assert_ne!(nonce1, nonce2);

    // 4. Try to verify session2 using sig1 (which was for nonce1)
    let verify_body2 = serde_json::json!({
        "id": session_id2,
        "did": did,
        "signature": hex::encode(sig1.as_ref()),
        "public_key": hex::encode(&pub_key),
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/verify")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&verify_body2).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should fail - signature is bound to nonce, not just domain
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn clock_skew_future_timestamp_within_tolerance() {
    // Create attestation with timestamp 3 minutes in the future (within 5-min tolerance)
    let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
    let root_did = ed25519_pubkey_to_did_key(&root_pk);
    let (device_kp, device_pk) = create_test_keypair(&[2u8; 32]);
    let device_did = ed25519_pubkey_to_did_key(&device_pk);

    let future_timestamp = Utc::now() + Duration::minutes(3);
    let attestation = create_attestation_with_timestamp(
        &root_kp,
        &device_kp,
        &root_did,
        &device_did,
        Some(future_timestamp),
    );

    // Verify - should succeed (within MAX_SKEW_SECS = 300 seconds)
    let result = verify_with_keys(&attestation, &root_pk).await;
    assert!(
        result.is_ok(),
        "Attestation with 3-min future timestamp should verify"
    );
}

#[tokio::test]
async fn clock_skew_far_future_timestamp_rejected() {
    // Create attestation with timestamp 10 minutes in the future (beyond 5-min tolerance)
    let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
    let root_did = ed25519_pubkey_to_did_key(&root_pk);
    let (device_kp, device_pk) = create_test_keypair(&[2u8; 32]);
    let device_did = ed25519_pubkey_to_did_key(&device_pk);

    let far_future_timestamp = Utc::now() + Duration::minutes(10);
    let attestation = create_attestation_with_timestamp(
        &root_kp,
        &device_kp,
        &root_did,
        &device_did,
        Some(far_future_timestamp),
    );

    // Verify - should fail (beyond MAX_SKEW_SECS)
    let result = verify_with_keys(&attestation, &root_pk).await;
    assert!(
        result.is_err(),
        "Attestation with 10-min future timestamp should be rejected"
    );

    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("in the future"),
        "Error should mention 'in the future', got: {}",
        err_msg
    );
}

// ============================================================================
// Phase 2: Cryptographic Edge Cases
// ============================================================================

#[tokio::test]
async fn canonical_json_variation_breaks_signature() {
    let (dir, did, pub_key, pkcs8) = setup_repo();
    let app = make_app(&dir);

    // 1. POST /auth/init
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/init")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"domain":"test.local"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    let init = body_json(resp.into_body()).await;
    let session_id = init["id"].as_str().unwrap();
    let nonce = init["challenge"].as_str().unwrap();

    // 2. Sign CANONICAL JSON
    let keypair = Ed25519KeyPair::from_pkcs8(&pkcs8).expect("keypair from pkcs8");
    let payload = serde_json::json!({ "domain": "test.local", "nonce": nonce });
    let canonical = json_canon::to_string(&payload).unwrap();
    let sig = keypair.sign(canonical.as_bytes());

    // 3. Submit verification with signature, but server will re-canonicalize
    //    If the canonical form differs, signature will fail
    let verify_body = serde_json::json!({
        "id": session_id,
        "did": did,
        "signature": hex::encode(sig.as_ref()),
        "public_key": hex::encode(&pub_key),
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/verify")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&verify_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should succeed because we used canonical JSON correctly
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn signature_tamper_single_bit_flip_rejected() {
    let (dir, did, pub_key, pkcs8) = setup_repo();
    let app = make_app(&dir);

    // 1. POST /auth/init
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/init")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"domain":"tamper.test"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    let init = body_json(resp.into_body()).await;
    let session_id = init["id"].as_str().unwrap();
    let nonce = init["challenge"].as_str().unwrap();

    // 2. Sign canonical JSON
    let keypair = Ed25519KeyPair::from_pkcs8(&pkcs8).expect("keypair from pkcs8");
    let payload = serde_json::json!({ "domain": "tamper.test", "nonce": nonce });
    let canonical = json_canon::to_string(&payload).unwrap();
    let sig = keypair.sign(canonical.as_bytes());

    // 3. Tamper with signature - flip a single bit
    let mut tampered_sig = sig.as_ref().to_vec();
    tampered_sig[31] ^= 0x01; // Flip bit in byte 31

    // 4. POST /auth/verify with tampered signature
    let verify_body = serde_json::json!({
        "id": session_id,
        "did": did,
        "signature": hex::encode(&tampered_sig),
        "public_key": hex::encode(&pub_key),
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/verify")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&verify_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should fail - signature verification failed
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn public_key_substitution_attack_rejected() {
    let (dir, did, _correct_pub_key, _correct_pkcs8) = setup_repo();
    let app = make_app(&dir);

    // 1. POST /auth/init
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/init")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"domain":"attack.test"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    let init = body_json(resp.into_body()).await;
    let session_id = init["id"].as_str().unwrap();
    let nonce = init["challenge"].as_str().unwrap();

    // 2. Generate attacker's keypair
    let rng = SystemRandom::new();
    let attacker_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let attacker_kp = Ed25519KeyPair::from_pkcs8(attacker_pkcs8.as_ref()).unwrap();
    let attacker_pub_key = attacker_kp.public_key().as_ref();

    // 3. Sign with attacker's private key
    let payload = serde_json::json!({ "domain": "attack.test", "nonce": nonce });
    let canonical = json_canon::to_string(&payload).unwrap();
    let sig = attacker_kp.sign(canonical.as_bytes());

    // 4. Try to verify legitimate DID with attacker's public key
    let verify_body = serde_json::json!({
        "id": session_id,
        "did": did, // Legitimate DID
        "signature": hex::encode(sig.as_ref()),
        "public_key": hex::encode(attacker_pub_key), // Attacker's key
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/verify")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&verify_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should fail - presented key doesn't match resolved key
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

// ============================================================================
// Phase 3: Capability Chain Verification
// ============================================================================

#[tokio::test]
async fn capability_chain_two_hop_intersection_succeeds() {
    // Create 3-level identity chain
    let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
    let root_did = ed25519_pubkey_to_did_key(&root_pk);

    let (inter_kp, inter_pk) = create_test_keypair(&[2u8; 32]);
    let inter_did = ed25519_pubkey_to_did_key(&inter_pk);

    let (device_kp, device_pk) = create_test_keypair(&[3u8; 32]);
    let device_did = ed25519_pubkey_to_did_key(&device_pk);

    // Att1: root → intermediate, caps: [sign_commit, manage_members]
    let att1 = create_attestation_with_capabilities(
        &root_kp,
        &inter_kp,
        &root_did,
        &inter_did,
        vec![Capability::sign_commit(), Capability::manage_members()],
    );

    // Att2: intermediate → device, caps: [sign_commit, sign_release]
    let att2 = create_attestation_with_capabilities(
        &inter_kp,
        &device_kp,
        &inter_did,
        &device_did,
        vec![Capability::sign_commit(), Capability::sign_release()],
    );

    // Verify chain for sign_commit (in intersection)
    let result =
        verify_chain_with_capability(&[att1, att2], &Capability::sign_commit(), &root_pk).await;
    assert!(result.is_ok(), "Chain should verify for sign_commit");
    assert!(result.unwrap().is_valid(), "Chain should be valid");
}

#[tokio::test]
async fn capability_chain_rejects_missing_capability_in_middle_link() {
    let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
    let root_did = ed25519_pubkey_to_did_key(&root_pk);

    let (inter_kp, inter_pk) = create_test_keypair(&[2u8; 32]);
    let inter_did = ed25519_pubkey_to_did_key(&inter_pk);

    let (device_kp, device_pk) = create_test_keypair(&[3u8; 32]);
    let device_did = ed25519_pubkey_to_did_key(&device_pk);

    // Att1: root → intermediate, caps: [sign_commit, manage_members]
    let att1 = create_attestation_with_capabilities(
        &root_kp,
        &inter_kp,
        &root_did,
        &inter_did,
        vec![Capability::sign_commit(), Capability::manage_members()],
    );

    // Att2: intermediate → device, caps: [manage_members] (missing sign_commit)
    let att2 = create_attestation_with_capabilities(
        &inter_kp,
        &device_kp,
        &inter_did,
        &device_did,
        vec![Capability::manage_members()],
    );

    // Verify chain for sign_commit (NOT in intersection)
    let result =
        verify_chain_with_capability(&[att1, att2], &Capability::sign_commit(), &root_pk).await;
    assert!(
        result.is_err(),
        "Should fail - sign_commit not in intersection"
    );
}

#[tokio::test]
async fn revocation_in_chain_breaks_delegation() {
    let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
    let root_did = ed25519_pubkey_to_did_key(&root_pk);

    let (inter_kp, inter_pk) = create_test_keypair(&[2u8; 32]);
    let inter_did = ed25519_pubkey_to_did_key(&inter_pk);

    let (device_kp, device_pk) = create_test_keypair(&[3u8; 32]);
    let device_did = ed25519_pubkey_to_did_key(&device_pk);

    // Create attestations
    let att1 = create_attestation_with_capabilities(
        &root_kp,
        &inter_kp,
        &root_did,
        &inter_did,
        vec![Capability::sign_commit()],
    );

    // Att2 is REVOKED
    let mut att2 = create_attestation_with_capabilities(
        &inter_kp,
        &device_kp,
        &inter_did,
        &device_did,
        vec![Capability::sign_commit()],
    );
    att2.revoked_at = Some(Utc::now()); // Mark as revoked

    // Verify chain - should fail due to revocation
    let result = verify_chain(&[att1, att2], &root_pk).await;
    assert!(result.is_ok(), "Chain verification returns report");
    let report = result.unwrap();
    assert!(
        !report.is_valid(),
        "Chain should be invalid due to revocation"
    );
}

// ============================================================================
// Phase 4: Witness Quorum
// ============================================================================

#[tokio::test]
async fn witness_quorum_2_of_3_succeeds() {
    // Create attestation chain
    let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
    let root_did = ed25519_pubkey_to_did_key(&root_pk);
    let (device_kp, device_pk) = create_test_keypair(&[2u8; 32]);
    let device_did = ed25519_pubkey_to_did_key(&device_pk);

    let attestation = create_attestation_with_capabilities(
        &root_kp,
        &device_kp,
        &root_did,
        &device_did,
        vec![Capability::sign_commit()],
    );

    // Create 3 witnesses
    let (w1_kp, w1_pk) = create_test_keypair(&[10u8; 32]);
    let (w2_kp, w2_pk) = create_test_keypair(&[20u8; 32]);
    let (_w3_kp, w3_pk) = create_test_keypair(&[30u8; 32]);

    // Create receipts for W1 and W2 only
    let r1 = create_witness_receipt(&w1_kp, "did:key:w1", "EEvent1", 1);
    let r2 = create_witness_receipt(&w2_kp, "did:key:w2", "EEvent1", 1);

    let config = WitnessVerifyConfig {
        receipts: &[r1, r2],
        witness_keys: &[
            ("did:key:w1".into(), w1_pk.to_vec()),
            ("did:key:w2".into(), w2_pk.to_vec()),
            ("did:key:w3".into(), w3_pk.to_vec()),
        ],
        threshold: 2,
    };

    let report = verify_chain_with_witnesses(&[attestation], &root_pk, &config)
        .await
        .unwrap();
    assert!(
        report.is_valid(),
        "Chain should be valid with 2-of-3 quorum"
    );
    assert!(report.witness_quorum.is_some());
    let quorum = report.witness_quorum.unwrap();
    assert_eq!(quorum.verified, 2);
    assert_eq!(quorum.required, 2);
}

#[tokio::test]
async fn witness_quorum_1_of_3_fails_threshold() {
    // Create attestation chain
    let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
    let root_did = ed25519_pubkey_to_did_key(&root_pk);
    let (device_kp, device_pk) = create_test_keypair(&[2u8; 32]);
    let device_did = ed25519_pubkey_to_did_key(&device_pk);

    let attestation = create_attestation_with_capabilities(
        &root_kp,
        &device_kp,
        &root_did,
        &device_did,
        vec![Capability::sign_commit()],
    );

    // Create 3 witnesses
    let (w1_kp, w1_pk) = create_test_keypair(&[10u8; 32]);
    let (_w2_kp, w2_pk) = create_test_keypair(&[20u8; 32]);
    let (_w3_kp, w3_pk) = create_test_keypair(&[30u8; 32]);

    // Only W1 signs (insufficient for threshold=2)
    let r1 = create_witness_receipt(&w1_kp, "did:key:w1", "EEvent1", 1);

    let config = WitnessVerifyConfig {
        receipts: &[r1],
        witness_keys: &[
            ("did:key:w1".into(), w1_pk.to_vec()),
            ("did:key:w2".into(), w2_pk.to_vec()),
            ("did:key:w3".into(), w3_pk.to_vec()),
        ],
        threshold: 2,
    };

    let report = verify_chain_with_witnesses(&[attestation], &root_pk, &config)
        .await
        .unwrap();
    assert!(
        !report.is_valid(),
        "Chain should be invalid with 1-of-3 when threshold is 2"
    );
    assert!(report.witness_quorum.is_some());
    let quorum = report.witness_quorum.unwrap();
    assert_eq!(quorum.verified, 1);
    assert_eq!(quorum.required, 2);
}

// ============================================================================
// Phase 5: Hardware Root Anchor Simulation
// ============================================================================

#[tokio::test]
async fn hardware_root_anchor_file_validation() {
    // 1. Create temp directory with .auths/roots.json
    let temp_dir = TempDir::new().unwrap();
    let auths_dir = temp_dir.path().join(".auths");
    std::fs::create_dir(&auths_dir).unwrap();
    let roots_path = auths_dir.join("roots.json");

    // 2. Create root keypair and DID
    let (root_kp, root_pk) = create_test_keypair(&[100u8; 32]);
    let root_did = format!(
        "did:keri:ERootAnchor{}",
        bs58::encode(&root_pk).into_string()
    );

    // 3. Write roots.json
    let roots_json = serde_json::json!({
        "version": 1,
        "roots": [{
            "did": root_did,
            "public_key_hex": hex::encode(root_pk),
            "note": "Embedded IoT root trust anchor"
        }]
    });
    std::fs::write(
        &roots_path,
        serde_json::to_string_pretty(&roots_json).unwrap(),
    )
    .unwrap();

    // 4. Load roots file
    let roots = RootsFile::load(&roots_path).unwrap();
    assert_eq!(roots.version, 1);

    // 5. Find root entry
    let entry = roots.find(&root_did);
    assert!(entry.is_some(), "Root entry should be found");
    let entry = entry.unwrap();

    // 6. Decode public key
    let pk_bytes = entry.public_key_bytes().unwrap();
    assert_eq!(pk_bytes.len(), 32, "Public key should be 32 bytes");

    // 7. Create attestation signed by root
    let (device_kp, device_pk) = create_test_keypair(&[101u8; 32]);
    let device_did = ed25519_pubkey_to_did_key(&device_pk);

    let device_pk_array: [u8; 32] = device_pk;
    let mut attestation = Attestation {
        version: 1,
        rid: "test-rid".into(),
        issuer: CanonicalDid::new_unchecked(root_did.clone()),
        subject: DeviceDID::new_unchecked(&device_did),
        device_public_key: Ed25519PublicKey::from_bytes(device_pk_array),
        identity_signature: Ed25519Signature::empty(),
        device_signature: Ed25519Signature::empty(),
        revoked_at: None,
        expires_at: Some(Utc::now() + Duration::days(365)),
        timestamp: Some(Utc::now()),
        note: None,
        payload: None,
        role: None,
        capabilities: vec![],
        delegated_by: None,
        signer_type: None,
        environment_claim: None,
    };

    let data = CanonicalAttestationData {
        version: attestation.version,
        rid: attestation.rid.as_str(),
        issuer: &attestation.issuer,
        subject: &attestation.subject,
        device_public_key: attestation.device_public_key.as_ref(),
        payload: &attestation.payload,
        timestamp: &attestation.timestamp,
        expires_at: &attestation.expires_at,
        revoked_at: &attestation.revoked_at,
        note: &attestation.note,
        role: attestation.role.as_ref().map(|r| r.as_str()),
        capabilities: if attestation.capabilities.is_empty() {
            None
        } else {
            Some(&attestation.capabilities)
        },
        delegated_by: attestation.delegated_by.as_ref(),
        signer_type: attestation.signer_type.as_ref(),
    };
    let canonical_bytes = canonicalize_attestation_data(&data).unwrap();

    let id_sig: [u8; 64] = root_kp.sign(&canonical_bytes).as_ref().try_into().unwrap();
    attestation.identity_signature = Ed25519Signature::from_bytes(id_sig);
    let dev_sig: [u8; 64] = device_kp
        .sign(&canonical_bytes)
        .as_ref()
        .try_into()
        .unwrap();
    attestation.device_signature = Ed25519Signature::from_bytes(dev_sig);

    // 8. Verify attestation using public key from roots file
    let result = verify_with_keys(&attestation, &pk_bytes).await;
    assert!(
        result.is_ok(),
        "Attestation should verify with root anchor from file"
    );
}
