use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use axum::{Json, Router, routing::get};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1::EncodeRsaPrivateKey;
use serde_json::json;

use auths_idp::IdpError;
use auths_idp::jwks::test_jwks_client;

// Pre-generated 2048-bit RSA key — avoids ~2-3s key generation in debug mode.
const TEST_RSA_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAqQEkBlNgzl73KvtCjLdafiGQk+xEq1w0ZiPA6IpLn88FwRaL
f50EPefAKxs90zXK66mfnJ7k1fAQ30ynWCSfEKT3u56HQHw2q5wOA2rhVpIA7zHC
8ifsEe3MWnokMeXJyHY/y/7lYTnImvJSk4yxJGIrFFyNJ8blXt07clrIoMWlBAXl
LCiInp/YcDaFydZee9Oe6X3Wme0BkendMqmH6LuFZrA3D9kWU6zPVVyLOR4Miv8+
PgG1KHyd6+aH9KA1kQdGAkMygzsmUy8UfQ3kqPgB02GAQWGMkyrbe/WLpVot9oNc
oxPEsZlh8osnV5Er7DIpPsO5RVUVOIf1my6bKwIDAQABAoIBAAVRzrSk7uD1YUSe
Pa/Yh5snwE6/pZZajnWr6MMJCKys41VQDy+tnWK7cYjfJc4znRcCMvlxkOoLpo74
xohXjWrZ3nMD4Dr540NPOVZciLTlCe19fKbgSyXHUo2DLFzRCvhp1xk7L995u6Q7
k2N8jrOCpDDTDEhfvNGEbNNtIxqDAPp82T2mKOpaYF5tcmg8j5r/Nh/oFAmGjplz
TVvGqaWaEYpE7Whtlje6boY1S3z1R465oTMVOCvNvZ9lMMkZHnYg9bd9u5qgsYTF
FIcAU2ZfI8Y+Cpu8wvFPpdIbrF9LiFLRxKrziXtfXn5hnwZBT7oLcLNcw0s/LBjk
JQUoYeECgYEA3Q8q3PTWS8V5EMbyKTxyrOvqEPBVBmvTmogksLaGNhJTtjaA7/jo
2Wl4xSc+raVo9vAUIp8GzxV8Jp/bNAH28pf5w/sJiBcVwHA8HMl8NovljyFgCftv
VK+557FeRyPJY/iw2V4FCOGo/nUAVVIMms0irFA+bhLp2KDenWFBuiECgYEAw7en
YK4JTLCzHF0nYjz50EUfa4qPY8kXAiSb5HnRm89zJZ/GvenpOpRzlu9Sv+f1or+7
hkJzuJaZ8mjBZzsA2VUANPetcLZHwX+YBs+dDDL4k1Pwb/NqE+PdRrijaUkMoJSt
M4c4K8iNhG3JsHewyl7ZNGX+ReFNY5f7rRLto8sCgYB9QTDaTeh2uoekl/VypAue
K3ZO7r5eiw41C1suvd1CGhRQtIVOc80ME5UYsOn03jqhYNsn2s+y2suj3wQHbe2M
+8vL3hxCfkIW7gFBlnDJP29tME4Ime01IPTHcVqoGIDuImWiZIGZzLNCquzrazg1
JnK1DCqzmAfkdRJuPkNNwQKBgEJWDDg7pNFGjt7NQB0O98k8tIKZyzISJWdHi0Ms
evwpmyikeBNEphWB3Y/J/C0pbNtFy0SdX2WwPeuoz+yyVf5Tziclz7aFQdr26Utd
sShCWnhtGfCH+2tUb1qaGGEGLm57Fh2B9mr4pea943+ZgeWFsm8NJtr+m2FnURl/
ceZzAoGAIw4IdELKWBJ2ajlYAXFmCrVIMhZ1EnrisMcOJkzrdiFB6LBj9OPmsl6H
M00yuDgbdvVwsB2cULp4D+OMjInNCICnmLP/+ysmRSfA15F0iezZrZj9kwNgYyR+
Kr3UJxzAu0HfzOvdrfzgmfUdHq82sS89GrExX0PzMuo6hh/Mcao=
-----END RSA PRIVATE KEY-----";

const TEST_ISSUER: &str = "https://test-idp.example.com";

fn generate_test_rsa_keys() -> (rsa::RsaPrivateKey, rsa::RsaPublicKey) {
    let private_key =
        rsa::RsaPrivateKey::from_pkcs1_pem(TEST_RSA_PEM).expect("failed to parse test RSA key");
    let public_key = private_key.to_public_key();
    (private_key, public_key)
}

fn build_jwk_from_public_key(public_key: &rsa::RsaPublicKey, kid: &str) -> serde_json::Value {
    use base64::Engine;
    use rsa::traits::PublicKeyParts;
    let n = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
    let e = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

    json!({
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": n,
        "e": e,
    })
}

fn sign_test_token(
    private_key: &rsa::RsaPrivateKey,
    kid: &str,
    claims: &serde_json::Value,
) -> String {
    let pem = private_key
        .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
        .expect("failed to encode PEM");
    let encoding_key =
        EncodingKey::from_rsa_pem(pem.as_bytes()).expect("failed to create encoding key");

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());

    jsonwebtoken::encode(&header, claims, &encoding_key).expect("failed to encode JWT")
}

fn valid_oidc_claims(aud: &str) -> serde_json::Value {
    let now = chrono::Utc::now().timestamp();
    json!({
        "iss": TEST_ISSUER,
        "sub": "user-123",
        "aud": aud,
        "email": "user@company.com",
        "iat": now,
        "nbf": now,
        "exp": now + 300,
    })
}

async fn start_mock_jwks_server(
    jwks_json: serde_json::Value,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let app = Router::new().route(
        "/.well-known/openid-configuration/jwks",
        get(move || {
            let jwks = jwks_json.clone();
            async move { Json(jwks) }
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind");
    let addr = listener.local_addr().expect("failed to get addr");
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, handle)
}

#[tokio::test]
async fn test_jwks_client_fetches_and_caches_keys() {
    let (private_key, public_key) = generate_test_rsa_keys();
    let kid = "cache-test-kid";
    let expected_audience = "test-app";

    let jwk = build_jwk_from_public_key(&public_key, kid);
    let jwks_json = json!({ "keys": [jwk] });

    let (addr, _handle) = start_mock_jwks_server(jwks_json).await;
    let client = test_jwks_client(
        &format!("http://{addr}/.well-known/openid-configuration/jwks"),
        TEST_ISSUER,
        expected_audience,
    );

    let claims = valid_oidc_claims(expected_audience);
    let token = sign_test_token(&private_key, kid, &claims);

    let key1: Result<DecodingKey, IdpError> = client.get_key_for_token(&token).await;
    assert!(key1.is_ok(), "first fetch should succeed: {:?}", key1.err());

    let key2: Result<DecodingKey, IdpError> = client.get_key_for_token(&token).await;
    assert!(
        key2.is_ok(),
        "cached fetch should succeed: {:?}",
        key2.err()
    );
}

#[tokio::test]
async fn test_unknown_kid_returns_error() {
    let (private_key, public_key) = generate_test_rsa_keys();
    let known_kid = "known-kid";
    let unknown_kid = "unknown-kid";
    let expected_audience = "test-app";

    let jwk = build_jwk_from_public_key(&public_key, known_kid);
    let jwks_json = json!({ "keys": [jwk] });

    let (addr, _handle) = start_mock_jwks_server(jwks_json).await;
    let client = test_jwks_client(
        &format!("http://{addr}/.well-known/openid-configuration/jwks"),
        TEST_ISSUER,
        expected_audience,
    );

    let claims = valid_oidc_claims(expected_audience);
    let token = sign_test_token(&private_key, unknown_kid, &claims);

    match client.get_key_for_token(&token).await {
        Ok(_) => panic!("should fail for unknown kid"),
        Err(err) => {
            let msg = err.to_string();
            assert!(
                msg.contains("not found in JWKS"),
                "expected kid-not-found error, got: {msg}"
            );
        }
    }
}

#[tokio::test]
async fn test_malformed_token_rejected() {
    let jwks_json = json!({ "keys": [] });
    let (addr, _handle) = start_mock_jwks_server(jwks_json).await;
    let client = test_jwks_client(
        &format!("http://{addr}/.well-known/openid-configuration/jwks"),
        TEST_ISSUER,
        "test-app",
    );

    match client.get_key_for_token("not.a.jwt").await {
        Ok(_) => panic!("should fail for malformed token"),
        Err(err) => {
            let msg = err.to_string();
            assert!(
                msg.contains("invalid JWT header"),
                "expected header error, got: {msg}"
            );
        }
    }
}

#[tokio::test]
async fn test_concurrent_requests_coalesce_fetches() {
    let (private_key, public_key) = generate_test_rsa_keys();
    let kid = "concurrent-kid";
    let expected_audience = "test-app";

    let fetch_count = Arc::new(AtomicU32::new(0));
    let fetch_count_clone = fetch_count.clone();

    let jwk = build_jwk_from_public_key(&public_key, kid);
    let jwks_response = json!({ "keys": [jwk] });

    let app = Router::new().route(
        "/.well-known/openid-configuration/jwks",
        get(move || {
            let count = fetch_count_clone.clone();
            let resp = jwks_response.clone();
            async move {
                count.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(Duration::from_millis(100)).await;
                Json(resp)
            }
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = Arc::new(test_jwks_client(
        &format!("http://{addr}/.well-known/openid-configuration/jwks"),
        TEST_ISSUER,
        expected_audience,
    ));

    let claims = valid_oidc_claims(expected_audience);
    let token = sign_test_token(&private_key, kid, &claims);

    let mut handles = Vec::new();
    for _ in 0..5 {
        let client = client.clone();
        let token = token.clone();
        handles.push(tokio::spawn(async move {
            client.get_key_for_token(&token).await
        }));
    }

    for handle in handles {
        let result: Result<DecodingKey, IdpError> = handle.await.unwrap();
        assert!(result.is_ok(), "verification failed: {:?}", result.err());
    }

    let total_fetches = fetch_count.load(Ordering::Relaxed);
    assert!(
        total_fetches <= 2,
        "expected at most 2 fetches (coalesced), got {total_fetches}"
    );
}
