use std::collections::HashMap;
use std::sync::LazyLock;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
use rsa::traits::PublicKeyParts;
use serde_json::json;
use tokio::net::TcpListener;

// Pre-generated 2048-bit RSA key — used only in tests, never in production.
// Same key used in auths-oidc-bridge tests for consistency.
// Generated with: openssl genrsa 2048 | openssl rsa -traditional
const TEST_RSA_PRIVATE_KEY_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----
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

const TEST_KID: &str = "mcp-test-kid-1";

struct TestKeys {
    encoding_key: EncodingKey,
    jwks_json: serde_json::Value,
}

static KEYS: LazyLock<TestKeys> = LazyLock::new(|| {
    let private_key = rsa::RsaPrivateKey::from_pkcs1_pem(TEST_RSA_PRIVATE_KEY_PEM)
        .expect("failed to parse test RSA key");
    let public_key = private_key.to_public_key();

    let n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
    let e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

    let jwks_json = json!({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": TEST_KID,
            "n": n,
            "e": e,
        }]
    });

    let pem = private_key
        .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
        .expect("PEM encoding must work");
    let encoding_key =
        EncodingKey::from_rsa_pem(pem.as_bytes()).expect("encoding key from PEM must work");

    TestKeys {
        encoding_key,
        jwks_json,
    }
});

/// Shared mock JWKS server — started once per process, reused across tests.
static SHARED_JWKS_URL: tokio::sync::OnceCell<String> = tokio::sync::OnceCell::const_new();

/// Starts a mock JWKS server serving the static test key.
/// First call starts the server; subsequent calls return the cached URL.
pub(super) async fn start_mock_jwks_server() -> (String, tokio::task::JoinHandle<()>) {
    let url = SHARED_JWKS_URL
        .get_or_init(|| async {
            let (url, handle) = start_mock_jwks_server_inner().await;
            std::mem::forget(handle); // keep server alive for process lifetime
            url
        })
        .await
        .clone();
    let noop_handle = tokio::spawn(async {});
    (url, noop_handle)
}

async fn start_mock_jwks_server_inner() -> (String, tokio::task::JoinHandle<()>) {
    let jwks = KEYS.jwks_json.clone();

    let app = axum::Router::new().route(
        "/.well-known/jwks.json",
        axum::routing::get(move || {
            let jwks = jwks.clone();
            async move { axum::Json(jwks) }
        }),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    (format!("http://127.0.0.1:{}", addr.port()), handle)
}

/// Signs a JWT with the static test RSA key.
pub(super) fn sign_test_jwt(claims: &serde_json::Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(TEST_KID.to_string());
    jsonwebtoken::encode(&header, claims, &KEYS.encoding_key).expect("JWT encoding must work")
}

/// Creates valid OidcClaims-shaped JSON for the given issuer/audience/capabilities.
pub(super) fn valid_mcp_claims(
    issuer: &str,
    audience: &str,
    capabilities: &[&str],
) -> serde_json::Value {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    json!({
        "iss": issuer,
        "sub": "did:keri:ETestAgent123",
        "aud": audience,
        "exp": now + 3600,
        "iat": now,
        "jti": "test-jti-1",
        "keri_prefix": "ETestAgent123",
        "capabilities": capabilities,
    })
}

/// Creates expired OidcClaims-shaped JSON.
pub(super) fn expired_mcp_claims(issuer: &str, audience: &str) -> serde_json::Value {
    json!({
        "iss": issuer,
        "sub": "did:keri:ETestAgent123",
        "aud": audience,
        "exp": 1000,
        "iat": 900,
        "jti": "test-jti-expired",
        "keri_prefix": "ETestAgent123",
        "capabilities": ["fs:read"],
    })
}

/// Default tool-capability mapping for tests.
pub(super) fn test_tool_capabilities() -> HashMap<String, String> {
    HashMap::from([
        ("read_file".to_string(), "fs:read".to_string()),
        ("write_file".to_string(), "fs:write".to_string()),
        ("deploy".to_string(), "deploy:staging".to_string()),
    ])
}

/// Creates a test router backed by the mock JWKS server.
pub(super) fn test_router(jwks_base_url: &str) -> axum::Router {
    let config = auths_mcp_server::McpServerConfig::default()
        .with_jwks_url(format!("{jwks_base_url}/.well-known/jwks.json"))
        .with_expected_issuer(jwks_base_url)
        .with_expected_audience("auths-mcp-server")
        .with_tool_capabilities(test_tool_capabilities())
        .with_leeway(10);
    let state = auths_mcp_server::McpServerState::new(config.clone());
    auths_mcp_server::router(state, &config)
}
