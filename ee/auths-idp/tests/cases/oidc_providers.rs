use std::time::Duration;

use axum::{Json, Router, routing::get};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
use serde_json::json;

use auths_idp::jwks::test_jwks_client;
use auths_idp::oidc::IdpVerifier;
use auths_idp::oidc::entra::EntraIdpVerifier;
use auths_idp::oidc::google::GoogleIdpVerifier;
use auths_idp::oidc::okta::OktaIdpVerifier;

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

// ─── Okta tests ───

#[tokio::test]
async fn test_oidc_okta_valid_token() {
    let (private_key, public_key) = generate_test_rsa_keys();
    let kid = "okta-kid";
    let issuer = "https://company.okta.com";
    let audience = "okta-client-id";

    let jwk = build_jwk_from_public_key(&public_key, kid);
    let (addr, _handle) = start_mock_jwks_server(json!({ "keys": [jwk] })).await;

    let jwks_client = test_jwks_client(
        &format!("http://{addr}/.well-known/openid-configuration/jwks"),
        issuer,
        audience,
    );
    let verifier = OktaIdpVerifier::new(issuer, audience, jwks_client);

    let now = chrono::Utc::now();
    let claims = json!({
        "iss": issuer,
        "sub": "okta-user-123",
        "aud": audience,
        "email": "user@company.com",
        "auth_time": now.timestamp(),
        "acr": "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
        "iat": now.timestamp(),
        "exp": now.timestamp() + 300,
    });
    let token = sign_test_token(&private_key, kid, &claims);

    let identity = verifier.verify(token.as_bytes(), now).await.unwrap();
    assert_eq!(identity.subject, "okta-user-123");
    assert_eq!(identity.idp_issuer, issuer);
    assert_eq!(identity.subject_email.as_deref(), Some("user@company.com"));
    assert_eq!(identity.idp_protocol, auths_idp::IdpProtocol::Oidc);
    assert_eq!(verifier.provider_name(), "okta");
}

#[tokio::test]
async fn test_oidc_okta_expired_token_rejected() {
    let (private_key, public_key) = generate_test_rsa_keys();
    let kid = "okta-kid-exp";
    let issuer = "https://company.okta.com";
    let audience = "okta-client-id";

    let jwk = build_jwk_from_public_key(&public_key, kid);
    let (addr, _handle) = start_mock_jwks_server(json!({ "keys": [jwk] })).await;

    let jwks_client = test_jwks_client(
        &format!("http://{addr}/.well-known/openid-configuration/jwks"),
        issuer,
        audience,
    );
    let verifier = OktaIdpVerifier::new(issuer, audience, jwks_client);

    let now = chrono::Utc::now();
    let claims = json!({
        "iss": issuer,
        "sub": "okta-user-123",
        "aud": audience,
        "iat": now.timestamp() - 600,
        "exp": now.timestamp() - 300,
    });
    let token = sign_test_token(&private_key, kid, &claims);

    let result = verifier.verify(token.as_bytes(), now).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("expired"));
}

#[tokio::test]
async fn test_oidc_okta_wrong_audience_rejected() {
    let (private_key, public_key) = generate_test_rsa_keys();
    let kid = "okta-kid-aud";
    let issuer = "https://company.okta.com";
    let audience = "okta-client-id";

    let jwk = build_jwk_from_public_key(&public_key, kid);
    let (addr, _handle) = start_mock_jwks_server(json!({ "keys": [jwk] })).await;

    let jwks_client = test_jwks_client(
        &format!("http://{addr}/.well-known/openid-configuration/jwks"),
        issuer,
        audience,
    );
    let verifier = OktaIdpVerifier::new(issuer, audience, jwks_client);

    let now = chrono::Utc::now();
    let claims = json!({
        "iss": issuer,
        "sub": "okta-user-123",
        "aud": "wrong-audience",
        "iat": now.timestamp(),
        "exp": now.timestamp() + 300,
    });
    let token = sign_test_token(&private_key, kid, &claims);

    let result = verifier.verify(token.as_bytes(), now).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("audience"));
}

// ─── Entra ID tests ───

#[tokio::test]
async fn test_oidc_entra_uses_oid_tid_as_subject() {
    let (private_key, public_key) = generate_test_rsa_keys();
    let kid = "entra-kid";
    let tenant = "tenant-uuid-123";
    let issuer = format!("https://login.microsoftonline.com/{tenant}/v2.0");
    let audience = "entra-app-client-id";

    let jwk = build_jwk_from_public_key(&public_key, kid);
    let (addr, _handle) = start_mock_jwks_server(json!({ "keys": [jwk] })).await;

    let jwks_client = test_jwks_client(
        &format!("http://{addr}/.well-known/openid-configuration/jwks"),
        &issuer,
        audience,
    );
    let verifier = EntraIdpVerifier::new(&issuer, audience, jwks_client);

    let now = chrono::Utc::now();
    let claims = json!({
        "iss": issuer,
        "sub": "pairwise-sub-abc",
        "aud": audience,
        "email": "user@company.onmicrosoft.com",
        "preferred_username": "user@company.com",
        "oid": "object-id-456",
        "tid": tenant,
        "auth_time": now.timestamp(),
        "iat": now.timestamp(),
        "exp": now.timestamp() + 300,
    });
    let token = sign_test_token(&private_key, kid, &claims);

    let identity = verifier.verify(token.as_bytes(), now).await.unwrap();
    assert_eq!(identity.subject, format!("object-id-456@{tenant}"));
    assert_eq!(identity.idp_issuer, issuer);
    assert_eq!(verifier.provider_name(), "entra-id");
}

#[tokio::test]
async fn test_oidc_entra_falls_back_to_sub_without_oid() {
    let (private_key, public_key) = generate_test_rsa_keys();
    let kid = "entra-kid-nosub";
    let issuer = "https://login.microsoftonline.com/tenant/v2.0";
    let audience = "entra-app-client-id";

    let jwk = build_jwk_from_public_key(&public_key, kid);
    let (addr, _handle) = start_mock_jwks_server(json!({ "keys": [jwk] })).await;

    let jwks_client = test_jwks_client(
        &format!("http://{addr}/.well-known/openid-configuration/jwks"),
        issuer,
        audience,
    );
    let verifier = EntraIdpVerifier::new(issuer, audience, jwks_client);

    let now = chrono::Utc::now();
    let claims = json!({
        "iss": issuer,
        "sub": "pairwise-sub-xyz",
        "aud": audience,
        "iat": now.timestamp(),
        "exp": now.timestamp() + 300,
    });
    let token = sign_test_token(&private_key, kid, &claims);

    let identity = verifier.verify(token.as_bytes(), now).await.unwrap();
    assert_eq!(identity.subject, "pairwise-sub-xyz");
}

// ─── Google Workspace tests ───

#[tokio::test]
async fn test_oidc_google_valid_token_with_hd() {
    let (private_key, public_key) = generate_test_rsa_keys();
    let kid = "google-kid";
    let issuer = "https://accounts.google.com";
    let audience = "client-id.apps.googleusercontent.com";

    let jwk = build_jwk_from_public_key(&public_key, kid);
    let (addr, _handle) = start_mock_jwks_server(json!({ "keys": [jwk] })).await;

    let jwks_client = test_jwks_client(
        &format!("http://{addr}/.well-known/openid-configuration/jwks"),
        issuer,
        audience,
    );
    let verifier =
        GoogleIdpVerifier::new(issuer, audience, jwks_client).with_required_domain("company.com");

    let now = chrono::Utc::now();
    let claims = json!({
        "iss": issuer,
        "sub": "123456789",
        "aud": audience,
        "email": "user@company.com",
        "email_verified": true,
        "hd": "company.com",
        "auth_time": now.timestamp(),
        "iat": now.timestamp(),
        "exp": now.timestamp() + 300,
    });
    let token = sign_test_token(&private_key, kid, &claims);

    let identity = verifier.verify(token.as_bytes(), now).await.unwrap();
    assert_eq!(identity.subject, "123456789");
    assert_eq!(identity.idp_issuer, issuer);
    assert_eq!(identity.subject_email.as_deref(), Some("user@company.com"));
    assert_eq!(verifier.provider_name(), "google-workspace");
}

#[tokio::test]
async fn test_oidc_google_missing_hd_rejected_when_required() {
    let (private_key, public_key) = generate_test_rsa_keys();
    let kid = "google-kid-nohd";
    let issuer = "https://accounts.google.com";
    let audience = "client-id.apps.googleusercontent.com";

    let jwk = build_jwk_from_public_key(&public_key, kid);
    let (addr, _handle) = start_mock_jwks_server(json!({ "keys": [jwk] })).await;

    let jwks_client = test_jwks_client(
        &format!("http://{addr}/.well-known/openid-configuration/jwks"),
        issuer,
        audience,
    );
    let verifier =
        GoogleIdpVerifier::new(issuer, audience, jwks_client).with_required_domain("company.com");

    let now = chrono::Utc::now();
    let claims = json!({
        "iss": issuer,
        "sub": "123456789",
        "aud": audience,
        "email": "user@gmail.com",
        "iat": now.timestamp(),
        "exp": now.timestamp() + 300,
    });
    let token = sign_test_token(&private_key, kid, &claims);

    let result = verifier.verify(token.as_bytes(), now).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("hd"));
}

#[tokio::test]
async fn test_oidc_google_wrong_domain_rejected() {
    let (private_key, public_key) = generate_test_rsa_keys();
    let kid = "google-kid-wronghd";
    let issuer = "https://accounts.google.com";
    let audience = "client-id.apps.googleusercontent.com";

    let jwk = build_jwk_from_public_key(&public_key, kid);
    let (addr, _handle) = start_mock_jwks_server(json!({ "keys": [jwk] })).await;

    let jwks_client = test_jwks_client(
        &format!("http://{addr}/.well-known/openid-configuration/jwks"),
        issuer,
        audience,
    );
    let verifier =
        GoogleIdpVerifier::new(issuer, audience, jwks_client).with_required_domain("company.com");

    let now = chrono::Utc::now();
    let claims = json!({
        "iss": issuer,
        "sub": "123456789",
        "aud": audience,
        "email": "user@evil.com",
        "hd": "evil.com",
        "iat": now.timestamp(),
        "exp": now.timestamp() + 300,
    });
    let token = sign_test_token(&private_key, kid, &claims);

    let result = verifier.verify(token.as_bytes(), now).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("domain mismatch"));
}

#[tokio::test]
async fn test_oidc_google_accepts_without_domain_restriction() {
    let (private_key, public_key) = generate_test_rsa_keys();
    let kid = "google-kid-nodomainreq";
    let issuer = "https://accounts.google.com";
    let audience = "client-id.apps.googleusercontent.com";

    let jwk = build_jwk_from_public_key(&public_key, kid);
    let (addr, _handle) = start_mock_jwks_server(json!({ "keys": [jwk] })).await;

    let jwks_client = test_jwks_client(
        &format!("http://{addr}/.well-known/openid-configuration/jwks"),
        issuer,
        audience,
    );
    let verifier = GoogleIdpVerifier::new(issuer, audience, jwks_client);

    let now = chrono::Utc::now();
    let claims = json!({
        "iss": issuer,
        "sub": "987654321",
        "aud": audience,
        "email": "user@gmail.com",
        "iat": now.timestamp(),
        "exp": now.timestamp() + 300,
    });
    let token = sign_test_token(&private_key, kid, &claims);

    let identity = verifier.verify(token.as_bytes(), now).await.unwrap();
    assert_eq!(identity.subject, "987654321");
}
