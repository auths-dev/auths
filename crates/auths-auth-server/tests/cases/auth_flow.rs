use std::collections::HashMap;
use std::sync::RwLock;

use async_trait::async_trait;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ring::signature::{Ed25519KeyPair, KeyPair};
use tower::ServiceExt;

use auths_auth_server::adapters::{InMemoryClientStore, InMemorySessionStore};
use auths_auth_server::config::AuthServerConfig;
use auths_auth_server::ports::{IdentityResolver, ResolveError};
use auths_auth_server::{AuthServerState, routes};

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

// ============================================================================
// Helpers
// ============================================================================

fn make_state(resolver: MockIdentityResolver, ttl: u64) -> AuthServerState {
    let config = AuthServerConfig::default().with_challenge_ttl(ttl);
    let sessions = InMemorySessionStore::new();
    AuthServerState::new(resolver, sessions, InMemoryClientStore::new(), config)
}

// ============================================================================
// Tests
// ============================================================================

#[tokio::test]
async fn test_full_auth_flow() {
    // Generate a keypair
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let public_key = keypair.public_key().as_ref().to_vec();

    let did = "did:keri:Etest123";

    // Set up mock resolver with the key
    let resolver = MockIdentityResolver::new();
    resolver.insert(did, public_key.clone());

    let state = make_state(resolver, 300);
    let app = routes::router(state);

    // 1. POST /auth/init
    let init_req = Request::builder()
        .method("POST")
        .uri("/auth/init")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"domain":"bank.example.com"}"#))
        .unwrap();

    let resp = app.clone().oneshot(init_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let init_data = body_json(resp.into_body()).await;
    let session_id = init_data["id"].as_str().unwrap();
    let nonce = init_data["challenge"].as_str().unwrap();
    let domain = init_data["domain"].as_str().unwrap();
    assert_eq!(domain, "bank.example.com");

    // 2. Check status is pending
    let status_req = Request::builder()
        .uri(format!("/auth/status/{session_id}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(status_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let status_data = body_json(resp.into_body()).await;
    assert_eq!(status_data["status"], "pending");

    // 3. Sign the challenge
    let payload = serde_json::json!({
        "domain": domain,
        "nonce": nonce,
    });
    let canonical = json_canon::to_string(&payload).unwrap();
    let sig = keypair.sign(canonical.as_bytes());

    // 4. POST /auth/verify
    let verify_body = serde_json::json!({
        "id": session_id,
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

    let resp = app.clone().oneshot(verify_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let verify_data = body_json(resp.into_body()).await;
    assert_eq!(verify_data["verified"], true);

    // 5. Check status is verified
    let status_req = Request::builder()
        .uri(format!("/auth/status/{session_id}"))
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(status_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let status_data = body_json(resp.into_body()).await;
    assert_eq!(status_data["status"], "verified");
    assert_eq!(status_data["did"], did);
}

#[tokio::test]
async fn test_reject_wrong_key() {
    let rng = ring::rand::SystemRandom::new();

    // Key A: what the resolver returns
    let pkcs8_a = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let keypair_a = Ed25519KeyPair::from_pkcs8(pkcs8_a.as_ref()).unwrap();

    // Key B: what the attacker uses
    let pkcs8_b = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let keypair_b = Ed25519KeyPair::from_pkcs8(pkcs8_b.as_ref()).unwrap();

    let did = "did:keri:Eattacker";

    let resolver = MockIdentityResolver::new();
    resolver.insert(did, keypair_a.public_key().as_ref().to_vec());

    let state = make_state(resolver, 300);
    let app = routes::router(state);

    // Init session
    let init_req = Request::builder()
        .method("POST")
        .uri("/auth/init")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"domain":"evil.com"}"#))
        .unwrap();

    let resp = app.clone().oneshot(init_req).await.unwrap();
    let init_data = body_json(resp.into_body()).await;
    let session_id = init_data["id"].as_str().unwrap();
    let nonce = init_data["challenge"].as_str().unwrap();

    // Sign with key B (wrong key)
    let payload = serde_json::json!({
        "domain": "evil.com",
        "nonce": nonce,
    });
    let canonical = json_canon::to_string(&payload).unwrap();
    let sig = keypair_b.sign(canonical.as_bytes());

    let verify_body = serde_json::json!({
        "id": session_id,
        "did": did,
        "signature": hex::encode(sig.as_ref()),
        "public_key": hex::encode(keypair_b.public_key().as_ref()),
    });

    let verify_req = Request::builder()
        .method("POST")
        .uri("/auth/verify")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&verify_body).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(verify_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn test_expired_session() {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

    let did = "did:keri:Eexpired";

    let resolver = MockIdentityResolver::new();
    resolver.insert(did, keypair.public_key().as_ref().to_vec());

    // TTL = 0 means immediately expired
    let state = make_state(resolver, 0);
    let app = routes::router(state);

    // Init session (it's already expired due to TTL=0)
    let init_req = Request::builder()
        .method("POST")
        .uri("/auth/init")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"domain":"bank.test"}"#))
        .unwrap();

    let resp = app.clone().oneshot(init_req).await.unwrap();
    let init_data = body_json(resp.into_body()).await;
    let session_id = init_data["id"].as_str().unwrap();
    let nonce = init_data["challenge"].as_str().unwrap();

    // Try to verify
    let payload = serde_json::json!({
        "domain": "bank.test",
        "nonce": nonce,
    });
    let canonical = json_canon::to_string(&payload).unwrap();
    let sig = keypair.sign(canonical.as_bytes());

    let verify_body = serde_json::json!({
        "id": session_id,
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

    let resp = app.clone().oneshot(verify_req).await.unwrap();
    // Should be 410 Gone (expired)
    assert_eq!(resp.status(), StatusCode::GONE);
}

#[tokio::test]
async fn test_session_not_found() {
    let resolver = MockIdentityResolver::new();
    let state = make_state(resolver, 300);
    let app = routes::router(state);

    let status_req = Request::builder()
        .uri("/auth/status/00000000-0000-0000-0000-000000000000")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(status_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_double_verify_rejected() {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

    let did = "did:keri:Edouble";

    let resolver = MockIdentityResolver::new();
    resolver.insert(did, keypair.public_key().as_ref().to_vec());

    let state = make_state(resolver, 300);
    let app = routes::router(state);

    // Init
    let init_req = Request::builder()
        .method("POST")
        .uri("/auth/init")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"domain":"test.com"}"#))
        .unwrap();

    let resp = app.clone().oneshot(init_req).await.unwrap();
    let init_data = body_json(resp.into_body()).await;
    let session_id = init_data["id"].as_str().unwrap();
    let nonce = init_data["challenge"].as_str().unwrap();

    // Sign and verify
    let payload = serde_json::json!({ "domain": "test.com", "nonce": nonce });
    let canonical = json_canon::to_string(&payload).unwrap();
    let sig = keypair.sign(canonical.as_bytes());

    let verify_body = serde_json::json!({
        "id": session_id,
        "did": did,
        "signature": hex::encode(sig.as_ref()),
        "public_key": hex::encode(keypair.public_key().as_ref()),
    });

    // First verify — should succeed
    let verify_req = Request::builder()
        .method("POST")
        .uri("/auth/verify")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&verify_body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(verify_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Second verify — should be 409 Conflict
    let verify_req = Request::builder()
        .method("POST")
        .uri("/auth/verify")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&verify_body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(verify_req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}
