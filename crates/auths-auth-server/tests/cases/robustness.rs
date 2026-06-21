//! Robustness integration tests: race conditions and concurrency.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Instant;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use ring::signature::{Ed25519KeyPair, KeyPair};
use tower::ServiceExt;

use auths_auth_server::adapters::{InMemoryClientStore, InMemorySessionStore};
use auths_auth_server::config::AuthServerConfig;
use auths_auth_server::domain::SessionStatus;
use auths_auth_server::ports::{IdentityResolver, ResolveError};
use auths_auth_server::{AuthServerState, routes};
use auths_verifier::CanonicalDid;
use auths_verifier::core::{Capability, Ed25519PublicKey, Ed25519Signature};

use super::helpers::body_json;

// ============================================================================
// Mock resolver
// ============================================================================

struct MockIdentityResolver {
    keys: RwLock<HashMap<String, Vec<u8>>>,
}

impl MockIdentityResolver {
    fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
        }
    }

    fn insert(&self, did: impl Into<String>, key: Vec<u8>) {
        self.keys.write().unwrap().insert(did.into(), key);
    }
}

#[async_trait]
impl IdentityResolver for MockIdentityResolver {
    async fn resolve_current_key(&self, did: &str) -> Result<Vec<u8>, ResolveError> {
        self.keys
            .read()
            .unwrap()
            .get(did)
            .cloned()
            .ok_or_else(|| ResolveError::NotFound(did.to_string()))
    }
}

use auths_crypto::ed25519_pubkey_to_did_key;

fn create_signed_attestation(
    issuer_kp: &Ed25519KeyPair,
    device_kp: &Ed25519KeyPair,
    issuer_did: &str,
    subject_did: &str,
    capabilities: Vec<Capability>,
) -> auths_verifier::core::Attestation {
    use auths_verifier::core::{
        Attestation, CanonicalAttestationData, canonicalize_attestation_data,
    };
    use auths_verifier::types::DeviceDID;
    use chrono::{Duration, Utc};

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
        capabilities,
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

// ============================================================================
// Tests
// ============================================================================

/// When a background thread expires a Pending session via CAS, a concurrent
/// verify attempt must get 410 Gone (Expired), not 409 Conflict.
#[tokio::test]
async fn cas_race_condition_to_expiration() {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let public_key = keypair.public_key().as_ref().to_vec();

    let did = "did:keri:Erace";

    let resolver = MockIdentityResolver::new();
    resolver.insert(did, public_key.clone());

    let config = AuthServerConfig::default().with_challenge_ttl(300);
    let sessions = InMemorySessionStore::new();
    let clients = InMemoryClientStore::new();
    let state = AuthServerState::new(resolver, sessions, clients, config);
    let app = routes::router(state.clone());

    // 1. Init a session
    let init_req = Request::builder()
        .method("POST")
        .uri("/auth/init")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"domain":"race.test"}"#))
        .unwrap();

    let resp = app.clone().oneshot(init_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let init_data = body_json(resp.into_body()).await;
    let session_id: uuid::Uuid = init_data["id"].as_str().unwrap().parse().unwrap();
    let nonce = init_data["challenge"].as_str().unwrap().to_string();

    // 2. Simulate the background GC expiring the session before verify runs
    let expired = state
        .app_service()
        .sessions()
        .update_status(&session_id, SessionStatus::Pending, SessionStatus::Expired)
        .await
        .unwrap();
    assert!(expired, "CAS to Expired should succeed");

    // 3. Attempt to verify — session was expired by the GC
    let payload = serde_json::json!({ "domain": "race.test", "nonce": nonce });
    let canonical = json_canon::to_string(&payload).unwrap();
    let sig = keypair.sign(canonical.as_bytes());

    let verify_body = serde_json::json!({
        "id": session_id.to_string(),
        "did": did,
        "signature": hex::encode(sig.as_ref()),
        "public_key": hex::encode(keypair.public_key().as_ref()),
    });

    let verify_req = Request::builder()
        .method("POST")
        .uri("/auth/verify")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&verify_body).unwrap()))
        .unwrap();

    let resp = app.oneshot(verify_req).await.unwrap();
    // Must be 410 Gone (Expired), not 409 Conflict
    assert_eq!(
        resp.status(),
        StatusCode::GONE,
        "session expired by GC must return 410, not 409"
    );
}

/// Concurrent /connect/register requests (heavy Argon2) must not starve
/// lightweight endpoints like GET /config.
#[tokio::test]
async fn registration_starvation_prevention() {
    let config = AuthServerConfig::default()
        .with_challenge_ttl(300)
        .with_allow_http_redirects(true);
    let resolver = MockIdentityResolver::new();
    let sessions = InMemorySessionStore::new();
    let clients = InMemoryClientStore::new();
    let state = AuthServerState::new(resolver, sessions, clients, config);

    // Build valid registration payloads
    let (root_kp, root_pk) = super::helpers::create_test_keypair(&[90u8; 32]);
    let root_did = ed25519_pubkey_to_did_key(&root_pk);
    let (device_kp, device_pk) = super::helpers::create_test_keypair(&[91u8; 32]);
    let device_did = ed25519_pubkey_to_did_key(&device_pk);

    let att = create_signed_attestation(
        &root_kp,
        &device_kp,
        &root_did,
        &device_did,
        vec![Capability::parse("oidc:client:register").unwrap()],
    );

    let reg_body = serde_json::json!({
        "client_name": "Load Test",
        "redirect_uris": ["http://localhost:8080/callback"],
        "keri_capability_receipt": {
            "attestation_chain": [att],
            "root_public_key": hex::encode(root_pk)
        }
    });

    // Fire 8 concurrent registration requests (each runs Argon2 hashing)
    let mut registration_handles = Vec::new();
    for _ in 0..8 {
        let body = reg_body.clone();
        let s = state.clone();
        registration_handles.push(tokio::spawn(async move {
            let app = routes::router(s);
            let req = Request::builder()
                .method("POST")
                .uri("/connect/register")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();
            app.oneshot(req).await.unwrap()
        }));
    }

    // While those are in flight, measure how fast a lightweight GET /config responds
    let config_start = Instant::now();
    let config_app = routes::router(state.clone());
    let config_req = Request::builder()
        .uri("/config")
        .body(Body::empty())
        .unwrap();
    let config_resp = config_app.oneshot(config_req).await.unwrap();
    let config_latency = config_start.elapsed();

    assert_eq!(config_resp.status(), StatusCode::OK);
    // If Argon2 were blocking the reactor, /config would stall for hundreds of ms.
    // With spawn_blocking it should respond in under 50ms.
    assert!(
        config_latency.as_millis() < 50,
        "GET /config took {}ms — Argon2 may be blocking the reactor",
        config_latency.as_millis()
    );

    // Wait for registrations to complete and verify they all succeeded
    for handle in registration_handles {
        let resp = handle.await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }
}
