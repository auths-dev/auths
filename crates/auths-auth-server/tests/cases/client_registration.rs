//! Integration tests for POST /connect/register (RFC 7591 dynamic registration).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{Duration, Utc};
use ring::signature::{Ed25519KeyPair, KeyPair};
use tower::ServiceExt;

use auths_auth_server::adapters::{InMemoryClientStore, InMemorySessionStore};
use auths_auth_server::config::AuthServerConfig;
use auths_auth_server::ports::{IdentityResolver, ResolveError};
use auths_auth_server::{AuthServerState, routes};
use auths_verifier::CanonicalDid;
use auths_verifier::core::{
    Attestation, CanonicalAttestationData, Capability, Ed25519PublicKey, Ed25519Signature,
    canonicalize_attestation_data,
};
use auths_verifier::types::DeviceDID;

use super::helpers::body_json;

use std::collections::HashMap;
use std::sync::RwLock;

use async_trait::async_trait;

// ============================================================================
// Mock resolver (copied from auth_flow tests)
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

fn make_state() -> AuthServerState {
    let config = AuthServerConfig::default()
        .with_challenge_ttl(300)
        .with_allow_http_redirects(true); // Allow HTTP for tests
    let resolver = MockIdentityResolver::new();
    let sessions = InMemorySessionStore::new();
    let clients = InMemoryClientStore::new();
    AuthServerState::new(resolver, sessions, clients, config)
}

use auths_crypto::ed25519_pubkey_to_did_key;

fn create_signed_attestation_with_caps(
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

fn make_valid_registration_body(
    attestation: &Attestation,
    root_pk: &[u8; 32],
) -> serde_json::Value {
    serde_json::json!({
        "client_name": "Test Service",
        "redirect_uris": ["http://localhost:8080/callback"],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_basic",
        "keri_capability_receipt": {
            "attestation_chain": [attestation],
            "root_public_key": hex::encode(root_pk)
        }
    })
}

async fn post_register(
    app: axum::Router,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let request = Request::builder()
        .method("POST")
        .uri("/connect/register")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let json = body_json(response.into_body()).await;
    (status, json)
}

// ============================================================================
// Tests
// ============================================================================

#[tokio::test]
async fn register_happy_path_client_secret_basic() {
    let (root_kp, root_pk) = super::helpers::create_test_keypair(&[1u8; 32]);
    let root_did = ed25519_pubkey_to_did_key(&root_pk);
    let (device_kp, device_pk) = super::helpers::create_test_keypair(&[2u8; 32]);
    let device_did = ed25519_pubkey_to_did_key(&device_pk);

    let att = create_signed_attestation_with_caps(
        &root_kp,
        &device_kp,
        &root_did,
        &device_did,
        vec![Capability::parse("oidc:client:register").unwrap()],
    );

    let body = make_valid_registration_body(&att, &root_pk);
    let app = routes::router(make_state());

    let (status, json) = post_register(app, body).await;

    assert_eq!(status, StatusCode::CREATED);
    assert!(json["client_id"].is_string());
    assert!(json["client_secret"].is_string());
    assert!(json["registration_access_token"].is_string());
    assert_eq!(json["client_name"], "Test Service");
    assert_eq!(json["token_endpoint_auth_method"], "client_secret_basic");
    assert!(json["client_id_issued_at"].is_number());
}

#[tokio::test]
async fn register_private_key_jwt_no_secret() {
    let (root_kp, root_pk) = super::helpers::create_test_keypair(&[10u8; 32]);
    let root_did = ed25519_pubkey_to_did_key(&root_pk);
    let (device_kp, device_pk) = super::helpers::create_test_keypair(&[11u8; 32]);
    let device_did = ed25519_pubkey_to_did_key(&device_pk);

    let att = create_signed_attestation_with_caps(
        &root_kp,
        &device_kp,
        &root_did,
        &device_did,
        vec![Capability::parse("oidc:client:register").unwrap()],
    );

    let body = serde_json::json!({
        "client_name": "JWT Service",
        "redirect_uris": ["http://localhost:8080/callback"],
        "token_endpoint_auth_method": "private_key_jwt",
        "jwks": { "keys": [{"kty": "OKP", "crv": "Ed25519"}] },
        "keri_capability_receipt": {
            "attestation_chain": [att],
            "root_public_key": hex::encode(root_pk)
        }
    });

    let app = routes::router(make_state());
    let (status, json) = post_register(app, body).await;

    assert_eq!(status, StatusCode::CREATED);
    assert!(json.get("client_secret").is_none() || json["client_secret"].is_null());
    assert_eq!(json["token_endpoint_auth_method"], "private_key_jwt");
}

#[tokio::test]
async fn register_empty_redirect_uris_returns_400() {
    let (root_kp, root_pk) = super::helpers::create_test_keypair(&[20u8; 32]);
    let root_did = ed25519_pubkey_to_did_key(&root_pk);
    let (device_kp, device_pk) = super::helpers::create_test_keypair(&[21u8; 32]);
    let device_did = ed25519_pubkey_to_did_key(&device_pk);

    let att = create_signed_attestation_with_caps(
        &root_kp,
        &device_kp,
        &root_did,
        &device_did,
        vec![Capability::parse("oidc:client:register").unwrap()],
    );

    let body = serde_json::json!({
        "redirect_uris": [],
        "keri_capability_receipt": {
            "attestation_chain": [att],
            "root_public_key": hex::encode(root_pk)
        }
    });

    let app = routes::router(make_state());
    let (status, _json) = post_register(app, body).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn register_missing_capability_returns_error() {
    let (root_kp, root_pk) = super::helpers::create_test_keypair(&[30u8; 32]);
    let root_did = ed25519_pubkey_to_did_key(&root_pk);
    let (device_kp, device_pk) = super::helpers::create_test_keypair(&[31u8; 32]);
    let device_did = ed25519_pubkey_to_did_key(&device_pk);

    // No capabilities — should fail the capability check
    let att = create_signed_attestation_with_caps(
        &root_kp,
        &device_kp,
        &root_did,
        &device_did,
        vec![], // No capabilities!
    );

    let body = make_valid_registration_body(&att, &root_pk);
    let app = routes::router(make_state());

    let (status, _json) = post_register(app, body).await;

    // Should fail with verification error (missing capability)
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn register_private_key_jwt_without_jwks_returns_400() {
    let (root_kp, root_pk) = super::helpers::create_test_keypair(&[40u8; 32]);
    let root_did = ed25519_pubkey_to_did_key(&root_pk);
    let (device_kp, device_pk) = super::helpers::create_test_keypair(&[41u8; 32]);
    let device_did = ed25519_pubkey_to_did_key(&device_pk);

    let att = create_signed_attestation_with_caps(
        &root_kp,
        &device_kp,
        &root_did,
        &device_did,
        vec![Capability::parse("oidc:client:register").unwrap()],
    );

    let body = serde_json::json!({
        "redirect_uris": ["http://localhost:8080/callback"],
        "token_endpoint_auth_method": "private_key_jwt",
        // No jwks field!
        "keri_capability_receipt": {
            "attestation_chain": [att],
            "root_public_key": hex::encode(root_pk)
        }
    });

    let app = routes::router(make_state());
    let (status, _json) = post_register(app, body).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn register_same_aid_twice_gets_different_client_ids() {
    let (root_kp, root_pk) = super::helpers::create_test_keypair(&[50u8; 32]);
    let root_did = ed25519_pubkey_to_did_key(&root_pk);
    let (device_kp, device_pk) = super::helpers::create_test_keypair(&[51u8; 32]);
    let device_did = ed25519_pubkey_to_did_key(&device_pk);

    let att = create_signed_attestation_with_caps(
        &root_kp,
        &device_kp,
        &root_did,
        &device_did,
        vec![Capability::parse("oidc:client:register").unwrap()],
    );

    let body = make_valid_registration_body(&att, &root_pk);
    let state = make_state();

    // First registration
    let app1 = routes::router(state.clone());
    let (status1, json1) = post_register(app1, body.clone()).await;
    assert_eq!(status1, StatusCode::CREATED);

    // Second registration with same AID
    let app2 = routes::router(state);
    let (status2, json2) = post_register(app2, body).await;
    assert_eq!(status2, StatusCode::CREATED);

    // Different client IDs
    assert_ne!(json1["client_id"], json2["client_id"]);
}
