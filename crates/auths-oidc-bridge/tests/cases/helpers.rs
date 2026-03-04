use std::sync::{Arc, LazyLock};

use auths_oidc_bridge::jwks::KeyManager;
use auths_oidc_bridge::{BridgeConfig, BridgeState};
use auths_verifier::IdentityDID;
use auths_verifier::core::{
    Attestation, CanonicalAttestationData, Capability, Ed25519PublicKey, Ed25519Signature,
    canonicalize_attestation_data,
};
use auths_verifier::types::DeviceDID;
use chrono::Utc;
use ring::signature::{Ed25519KeyPair, KeyPair};

/// Creates a deterministic Ed25519 keypair from a 32-byte seed.
pub(super) fn create_test_keypair(seed: &[u8; 32]) -> (Ed25519KeyPair, [u8; 32]) {
    let keypair = Ed25519KeyPair::from_seed_unchecked(seed).unwrap();
    let public_key: [u8; 32] = keypair.public_key().as_ref().try_into().unwrap();
    (keypair, public_key)
}

/// Pre-generated RSA-2048 key (PKCS#1 PEM) — avoids slow key generation in tests.
pub(super) const TEST_RSA_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----\n\
MIIEpAIBAAKCAQEAyXBnW3NbVqqbkPd7es3OrZzjlz2ryfFr52WL0EPxV8XrMa0B\n\
g5bxfieOB/6sgPRxkqZqZ90L7/iO1l+0z4PtUAKBFsdEjSvpc9QsrUEC2FExAi05\n\
iboipJ2S357ws1ow//QA+ejdwrWwbwIJ5TpdAmHQxi6lB0AALrXHHT0PZHjCVJUH\n\
w6eS4bdu4ML0+I/v/kYFPDK6f5bjZhbXX5k8L1lIV4ODnEOINI1lhvvPFfUmxzM0\n\
89RNCrxUWMHwUXjqwu0tO8BgsuNhorraR5xMBQcmyw2hHTkI1xlj6Wb+0sfkc/Q6\n\
7v5/BbiAgBI1oSg+IlrXz2IRbb+z8TdvqHanaQIDAQABAoIBAAPEsIpLbCgA5Qwf\n\
NRYlB3rD9pX7t1z9wTEA+06YFsm3kCDLxb16c2YSw1tu7jczW3SM3Gy4++IvWiy0\n\
eaNwKl5WzadpbuTdL27VR0iucKkvS6VoxyzGaKN/tyGrzYDtbQE8xU/nhU6BK53I\n\
Afthzh+fSNKMSNYL4nT9PY5UeBc/CpNmPen7I6BOzkBKOkGyAAlyvaqndbYdiT4D\n\
CwviZuo/t9KdLMR0l2r4bAh/rdPdzPPnCfgUmbwNSpQCRUKyleZYmJGUTHBb8jbJ\n\
WV2wI6eh3jWDaidWo3Hzj+HNiYtjihsDsyrxNBopAj3cs3kFpfNq1vTGxDniQH7J\n\
ua5CpAECgYEA6psyPE9RAQFYfsPtcQiq5RDmrz/BQp+qIInr5Ndsxjc4opafILFS\n\
HC80ulq8lpZCiIslShZkeAMTI0kaAlxxSGXDet4S1RX38EvugsupMO7yN88S6tgX\n\
tZqQSkrT4NXXEhfPfD9CB1MYuFLUni92k5SyTfhKrndaAymOxsX99EECgYEA287u\n\
bDDht/7ETW4rbjyuzufH7N9kch3jtSxKdyQPem1Yl+cazlKlcR+wk5gNdLsTwIqR\n\
fnfWL+85jlYOZgdv6f/uNDVnzJ/DO1A1Ic/+hMqXrmH071OU13+P0RYifxmHr//j\n\
+dqsYUd7XYCRQQ4RGP/rsm3o0lSt2/69Bm8kSSkCgYEA39eIDOcYwL7J8tl5+Xlt\n\
pPWFRPytpqW0qystOcEZdd5GWUshNQ46681Wn9/nRD7F6IXq5E+NOLymS+p5uHr/\n\
UzZVVywAB/PYBxxLy9wJ6Dh0Py+COzRHGu0IcvoGQuWFOSwiuceZdmeglG3jk7Jx\n\
jso3fhFDIEecSJwkMB/E+IECgYAcSmbvb98tYlH7sUlPt+m74aMevqXb9jLfl6LB\n\
8Nc5J6e2bV1K3uJCTBTa+kAJHSbuqicNwvjDVKPwyOyzfxONZ45OE+2XLZzgHnOo\n\
NXAJwVWCcUMoJnbKwbVN8O5hs3R+V44NE3MKVjvvjeOkHt5efFnmrjTAFXwHC6Ni\n\
l51w+QKBgQCBM2dvk1CMxy8IDs1CR8fQ7hNkF3T8nCGW+VtQG3x1Nu4cb8uhCm27\n\
6uaJf7xz8x/TV+xoqjksQQSgBiqVPRG5MHlXrkK1R3FJYJ9Cd1AJnOe3PlkjnAWG\n\
JF9H4tMdB75Kpb6IlV9tmJDHjWuoBCpsZo8lzgb8yI7JbWeDrZLksA==\n\
-----END RSA PRIVATE KEY-----\n";

/// Second pre-generated RSA-2048 key for rotation tests.
pub(super) const TEST_RSA_PEM_2: &str = "-----BEGIN RSA PRIVATE KEY-----\n\
MIIEogIBAAKCAQEA8l4ZDRF8+bJX0m8rjVVHzChZoY/ofx1lQ0GoGNn2wjACZRCH\n\
ArB1BMdOsjxX32QdwyadgLyf0jhnoxI0i0oY2acHKaSinFjbAB6Wut+HjrpX4VCZ\n\
UX5kdpdQV92RHwtsN3W4xWBWAE5/9re0aYh3HDwNRHaIOBlMtDX8yl/W/avW7xcd\n\
xFuFFVJPPCxJXDCqMh4nwZnrxElA0MfY79HFP4qhuO7PlHeuOafF58AOFwufRGOQ\n\
GVWwD0j05fo81BhENtcm1WNlCQvfe95fzr8PYm6Lww3XqFEMtLNdiErqpK4Ip0ZC\n\
zTgzmbVibRDHMlZ5k/P6/JlApww57xZ/alRMeQIDAQABAoIBACtM1WPozm+bxaXi\n\
V6ER7dhTEyRSngJrwYYhCkOaWUP7KMpeiAhadyWJ6AzezAIslEajtPrleBYqHpXb\n\
MEj8TXFBLn3pnGWbWFDuphYvzjuZHg8yg5m0H4WyZde0zXMC6uwDm6WjnunCHIl6\n\
63/5MfJ45hPnq1F+b544kPek5Ld/7U7E2M49K+yWa1ZDut/ZUB/yKW0l0AcxD0pU\n\
v4XWokf0j9YTy2CTJ7vYgbID8zRW7OBnbboQ+ulwCLLegmf59vCpb+r/Qpym6r1Q\n\
+sxX0lWcUNKZmmfvTbrPjf9lS2QgRxoY4rC5oU5zjuv9C3Tosn3N9G6UHBmL+nXj\n\
NiVGCEMCgYEA+eaQqdpJvHz5gSRXee3IkGsRoVuJHbTDJ6vZDcqGXUWR3UjZRGDY\n\
ENOwKHIWpvob2JGRpeCuu734Mv4lkZxq/D+HjNx/NkyxDMDwr2dNJrl0pW4NL50p\n\
/N1URuolvbua+DVpswA7UVM77MpNXuoCxlO618NzKxIR9x+s62pbIiMCgYEA+Eh2\n\
5QRtdSpk2qDauLkrBd1Bx1cdtkhvYaYx0n2A1xyNxzYpj8j9ZUtJj+oCoHfV1Ep/\n\
e6ntab4U1b0f+ZR7v79qycT1mGA01gbQsb3fXo4Aydr9VThdG3Ll5dmkmGBBAeWO\n\
wDH+nxWDD4+AX0OzAnGjVsoyWKtrc/9KtGzaurMCgYARKLe+MfLmMl6fc3NeN+mR\n\
oQhw3+wmUgckbjRVMhbPyLsfSqVAgLXVUfPCkzLi/EF1OWmazjaxRXYJalICEY93\n\
CpWwImPJwrJVgdoE8T7m7c0Inung3xXG+xuSUvmMcZlOebxsQhPQnbp7o9h0L/VI\n\
0O7/abg6uN7q7Q3ejEr9qQKBgFlmTllcZMVhhHssnFUTZ6hu6PaMKcivAFwa6amv\n\
QysxvuNSX1jEuGk22MAXNObu/3G3eXvfzfrbVMk5lj/Z9U0v8ZXBc+VwDtZaEd9O\n\
TRXQ7/u+/KUo7G2ry5gd7CRp1D6ImAQgfFxv9Icv1rt2twhUPspLeCFxZ/mWnSGm\n\
aIP9AoGAQL7ivzQGTLujS+YRYwrG92KmoQGrXdYihNJ8cgvsW+BWrb/CMLZvR9ON\n\
854/jOvUNczQitFNExGrNds4kWRwSXNbuTbrLZlWID0YUkUIBYuLhiIv50qAPwx7\n\
6JDY+d7ZX8br+r/sXwabXFUk7ySv4697cnQ6wIEg0Ls6xt8YhRQ=\n\
-----END RSA PRIVATE KEY-----\n";

/// Returns a `KeyManager` loaded from a pre-generated dummy PEM (for rotation tests).
pub(super) fn test_key_manager() -> KeyManager {
    KeyManager::from_pem(TEST_RSA_PEM_2.as_bytes()).expect("static test PEM must parse")
}

/// Shared test state: uses a pre-generated RSA key — no runtime key generation.
pub(super) static TEST_STATE: LazyLock<(BridgeState, BridgeConfig)> = LazyLock::new(|| {
    let config = BridgeConfig::default()
        .with_issuer_url("https://oidc.example.com")
        .with_default_audience("sts.amazonaws.com")
        .with_max_ttl(3600)
        .with_default_ttl(900)
        .with_signing_key_pem(TEST_RSA_PEM);
    let state = BridgeState::new(config.clone()).expect("failed to create bridge state");
    (state, config)
});

pub(super) fn test_app() -> axum::Router {
    let (state, config) = &*TEST_STATE;
    auths_oidc_bridge::routes::router(state.clone(), config)
}

/// Create a test app with an injectable clock function for deterministic timestamps.
pub(super) fn test_app_with_clock(clock: Arc<dyn Fn() -> u64 + Send + Sync>) -> axum::Router {
    let config = BridgeConfig::default()
        .with_issuer_url("https://oidc.example.com")
        .with_default_audience("sts.amazonaws.com")
        .with_max_ttl(3600)
        .with_default_ttl(900)
        .with_signing_key_pem(TEST_RSA_PEM);
    let state =
        BridgeState::new_with_clock(config.clone(), clock).expect("failed to create bridge state");
    auths_oidc_bridge::routes::router(state, &config)
}

/// Create a test app with custom rate limit settings.
pub(super) fn test_app_with_rate_limit(rpm: u32, burst: u32, enabled: bool) -> axum::Router {
    let config = BridgeConfig::default()
        .with_issuer_url("https://oidc.example.com")
        .with_default_audience("sts.amazonaws.com")
        .with_max_ttl(3600)
        .with_default_ttl(900)
        .with_rate_limit_rpm(rpm)
        .with_rate_limit_burst(burst)
        .with_rate_limit_enabled(enabled)
        .with_signing_key_pem(TEST_RSA_PEM);
    let state = BridgeState::new(config.clone()).expect("failed to create bridge state");
    auths_oidc_bridge::routes::router(state, &config)
}

/// Create a test app with a specific audience validation mode.
pub(super) fn test_app_with_audience_validation(
    mode: auths_oidc_bridge::audience::AudienceValidation,
) -> axum::Router {
    let config = BridgeConfig::default()
        .with_issuer_url("https://oidc.example.com")
        .with_max_ttl(3600)
        .with_default_ttl(900)
        .with_audience_validation(mode)
        .with_rate_limit_enabled(false)
        .with_signing_key_pem(TEST_RSA_PEM);
    let state = BridgeState::new(config.clone()).expect("failed to create bridge state");
    auths_oidc_bridge::routes::router(state, &config)
}

/// Create a test app with admin token enabled.
pub(super) fn test_app_with_admin_token(token: &str) -> axum::Router {
    let config = BridgeConfig::default()
        .with_issuer_url("https://oidc.example.com")
        .with_default_audience("sts.amazonaws.com")
        .with_max_ttl(3600)
        .with_default_ttl(900)
        .with_admin_token(token)
        .with_rate_limit_enabled(false)
        .with_signing_key_pem(TEST_RSA_PEM);
    let state = BridgeState::new(config.clone()).expect("failed to create bridge state");
    auths_oidc_bridge::routes::router(state, &config)
}

pub(super) use auths_crypto::ed25519_pubkey_to_did_key;

/// Mint a JWT from the bridge, either via a deployed bridge URL or the in-process test app.
///
/// When `AUTHS_BRIDGE_URL` is set, sends a real HTTP request to the deployed bridge.
/// Otherwise, uses the in-process `test_app()` to mint the token locally.
///
/// Returns `(access_token, subject)`.
pub(super) async fn mint_jwt_from_bridge(capabilities: &[Capability]) -> (String, String) {
    use chrono::Duration;

    let (root_kp, root_pk) = create_test_keypair(&[1u8; 32]);
    let root_did = ed25519_pubkey_to_did_key(&root_pk);
    let (device_kp, device_pk) = create_test_keypair(&[2u8; 32]);
    let device_did = ed25519_pubkey_to_did_key(&device_pk);

    let att = create_signed_attestation(
        &root_kp,
        &device_kp,
        &root_did,
        &device_did,
        false,
        Some(Utc::now() + Duration::days(365)),
        capabilities.to_vec(),
    );

    let request_body = serde_json::json!({
        "attestation_chain": [att],
        "root_public_key": hex::encode(root_pk),
    });

    if let Ok(bridge_url) = std::env::var("AUTHS_BRIDGE_URL") {
        // Deployed bridge: real HTTP request
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{bridge_url}/token"))
            .json(&request_body)
            .send()
            .await
            .expect("failed to reach deployed bridge");

        assert_eq!(
            resp.status().as_u16(),
            200,
            "bridge /token returned non-200: {}",
            resp.status()
        );

        let json: serde_json::Value = resp.json().await.expect("invalid JSON from bridge");
        let token = json["access_token"].as_str().unwrap().to_string();
        let subject = json["subject"].as_str().unwrap().to_string();
        (token, subject)
    } else {
        // In-process bridge
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use http_body_util::BodyExt;
        use tower::ServiceExt;

        let response = test_app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let token = json["access_token"].as_str().unwrap().to_string();
        let subject = json["subject"].as_str().unwrap().to_string();
        (token, subject)
    }
}

/// Create a signed attestation for testing.
pub(super) fn create_signed_attestation(
    issuer_kp: &Ed25519KeyPair,
    device_kp: &Ed25519KeyPair,
    issuer_did: &str,
    subject_did: &str,
    revoked: bool,
    expires_at: Option<chrono::DateTime<Utc>>,
    capabilities: Vec<Capability>,
) -> Attestation {
    let device_pk: [u8; 32] = device_kp.public_key().as_ref().try_into().unwrap();

    let revoked_at = if revoked { Some(Utc::now()) } else { None };

    let mut att = Attestation {
        version: 1,
        rid: "test-rid".into(),
        issuer: IdentityDID::new(issuer_did),
        subject: DeviceDID::new(subject_did),
        device_public_key: Ed25519PublicKey::from_bytes(device_pk),
        identity_signature: Ed25519Signature::empty(),
        device_signature: Ed25519Signature::empty(),
        revoked_at,
        expires_at,
        timestamp: Some(Utc::now()),
        note: None,
        payload: None,
        role: None,
        capabilities,
        delegated_by: None,
        signer_type: None,
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
