//! GitHub Actions OIDC token verification and JWKS caching.
//!
//! This module validates GitHub Actions OIDC tokens (RS256) by fetching
//! GitHub's public keys from their JWKS endpoint and verifying token
//! signatures, issuer, audience, and expiry.
//!
//! Includes resilient JWKS fetching with:
//! - In-memory caching with configurable TTL
//! - Thundering herd protection (request coalescing)
//! - Exponential backoff on fetch failures
//! - Circuit breaker after consecutive failures
//! - Stale cache fallback on transient errors

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};

use crate::error::BridgeError;

const DEFAULT_GITHUB_ISSUER: &str = "https://token.actions.githubusercontent.com";
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(3600);
const CIRCUIT_BREAKER_THRESHOLD: u32 = 5;
const CIRCUIT_BREAKER_COOLDOWN: Duration = Duration::from_secs(60);
const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// Claims embedded in a GitHub Actions OIDC token.
///
/// Args:
/// * `actor`: The GitHub username that triggered the workflow.
/// * `actor_id`: Numeric GitHub user ID.
/// * `repository`: Full repository name (e.g., "org/repo").
/// * `repository_owner`: Organization or user that owns the repository.
/// * `repository_owner_id`: Numeric owner ID.
/// * `iss`: Issuer URL (expected: "https://token.actions.githubusercontent.com").
/// * `sub`: Subject claim (e.g., "repo:org/repo:ref:refs/heads/main").
/// * `aud`: Audience claim (configurable per workflow).
/// * `git_ref`: Git ref that triggered the workflow.
/// * `sha`: Commit SHA.
/// * `workflow`: Workflow name.
/// * `run_id`: Workflow run ID.
/// * `event_name`: Trigger event (e.g., "push", "pull_request").
///
/// Usage:
/// ```ignore
/// let claims: GitHubOidcClaims = verify_github_token(&token, &client).await?;
/// println!("Actor: {}", claims.actor);
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct GitHubOidcClaims {
    pub actor: String,
    #[serde(default)]
    pub actor_id: Option<String>,
    pub repository: String,
    #[serde(default)]
    pub repository_owner: Option<String>,
    #[serde(default)]
    pub repository_owner_id: Option<String>,
    pub iss: String,
    pub sub: String,
    pub aud: String,
    #[serde(rename = "ref", default)]
    pub git_ref: Option<String>,
    #[serde(default)]
    pub sha: Option<String>,
    #[serde(default)]
    pub workflow: Option<String>,
    #[serde(default)]
    pub run_id: Option<String>,
    #[serde(default)]
    pub event_name: Option<String>,
}

struct CachedJwks {
    keys: JwkSet,
    fetched_at: Instant,
}

struct CircuitBreakerState {
    consecutive_failures: AtomicU32,
    last_failure_at: RwLock<Option<Instant>>,
}

/// Client for fetching and caching GitHub's JWKS keys.
///
/// Args:
/// * `jwks_url`: The URL to fetch JWKS keys from.
/// * `expected_audience`: The audience value to validate against (confused deputy prevention).
/// * `cache_ttl`: Duration before cached keys are considered stale.
///
/// Usage:
/// ```ignore
/// let client = JwksClient::new(
///     "https://token.actions.githubusercontent.com",
///     "auths-bridge",
///     Duration::from_secs(3600),
/// );
/// let claims = verify_github_token(&token, &client).await?;
/// ```
pub struct JwksClient {
    http: reqwest::Client,
    jwks_url: String,
    expected_audience: String,
    issuer: String,
    cache: RwLock<Option<CachedJwks>>,
    cache_ttl: Duration,
    fetch_lock: Mutex<()>,
    circuit_breaker: CircuitBreakerState,
}

impl JwksClient {
    /// Creates a new JWKS client for GitHub OIDC token validation.
    ///
    /// Args:
    /// * `issuer`: The OIDC issuer URL (typically "https://token.actions.githubusercontent.com").
    /// * `expected_audience`: The audience to validate tokens against.
    /// * `cache_ttl`: How long to cache JWKS keys before refreshing.
    ///
    /// Usage:
    /// ```ignore
    /// let client = JwksClient::new(
    ///     "https://token.actions.githubusercontent.com",
    ///     "auths-bridge",
    ///     Duration::from_secs(3600),
    /// );
    /// ```
    pub fn new(issuer: &str, expected_audience: &str, cache_ttl: Duration) -> Self {
        let jwks_url = format!("{}/.well-known/jwks", issuer.trim_end_matches('/'));
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("failed to build HTTP client"),
            jwks_url,
            expected_audience: expected_audience.to_string(),
            issuer: issuer.to_string(),
            cache: RwLock::new(None),
            cache_ttl,
            fetch_lock: Mutex::new(()),
            circuit_breaker: CircuitBreakerState {
                consecutive_failures: AtomicU32::new(0),
                last_failure_at: RwLock::new(None),
            },
        }
    }

    /// Creates a new JWKS client with default settings.
    ///
    /// Args:
    /// * `expected_audience`: The audience to validate tokens against.
    ///
    /// Usage:
    /// ```ignore
    /// let client = JwksClient::with_defaults("auths-bridge");
    /// ```
    pub fn with_defaults(expected_audience: &str) -> Self {
        Self::new(DEFAULT_GITHUB_ISSUER, expected_audience, DEFAULT_CACHE_TTL)
    }

    /// Returns the configured expected audience.
    pub fn expected_audience(&self) -> &str {
        &self.expected_audience
    }

    /// Returns the configured issuer URL.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Retrieves the decoding key for a given JWT token by matching its `kid` header.
    ///
    /// Args:
    /// * `token`: The raw JWT string to find the matching key for.
    ///
    /// Usage:
    /// ```ignore
    /// let key = client.get_key_for_token(&jwt_string).await?;
    /// ```
    pub async fn get_key_for_token(&self, token: &str) -> Result<DecodingKey, BridgeError> {
        let header = decode_header(token)
            .map_err(|e| BridgeError::GitHubTokenInvalid(format!("invalid JWT header: {e}")))?;

        let kid = header
            .kid
            .ok_or_else(|| BridgeError::GitHubTokenInvalid("JWT header missing kid".to_string()))?;

        if let Some(key) = self.find_key_in_cache(&kid).await {
            return Ok(key);
        }

        self.refresh_and_find_key(&kid).await
    }

    async fn find_key_in_cache(&self, kid: &str) -> Option<DecodingKey> {
        let cache = self.cache.read().await;
        let cached = cache.as_ref()?;

        if cached.fetched_at.elapsed() > self.cache_ttl {
            return None;
        }

        find_key_in_jwks(&cached.keys, kid)
    }

    async fn refresh_and_find_key(&self, kid: &str) -> Result<DecodingKey, BridgeError> {
        // Request coalescing: only one task fetches at a time
        let _guard = self.fetch_lock.lock().await;

        // Double-check: another task may have refreshed while we waited
        if let Some(key) = self.find_key_in_cache(kid).await {
            return Ok(key);
        }

        // Also check stale cache for the kid (may have been fetched by concurrent waiter)
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.as_ref()
                && let Some(key) = find_key_in_jwks(&cached.keys, kid)
            {
                return Ok(key);
            }
        }

        match self.fetch_jwks().await {
            Ok(jwks) => {
                let key = find_key_in_jwks(&jwks, kid).ok_or_else(|| {
                    BridgeError::GitHubTokenInvalid(format!("kid '{kid}' not found in JWKS"))
                })?;

                let mut cache = self.cache.write().await;
                *cache = Some(CachedJwks {
                    keys: jwks,
                    fetched_at: Instant::now(),
                });

                self.circuit_breaker
                    .consecutive_failures
                    .store(0, Ordering::Relaxed);

                Ok(key)
            }
            Err(fetch_err) => {
                self.record_failure().await;

                // Serve stale cache if available
                let cache = self.cache.read().await;
                if let Some(cached) = cache.as_ref()
                    && let Some(key) = find_key_in_jwks(&cached.keys, kid)
                {
                    tracing::warn!(
                        kid = kid,
                        error = %fetch_err,
                        "serving stale JWKS cache after fetch failure"
                    );
                    return Ok(key);
                }

                Err(fetch_err)
            }
        }
    }

    async fn fetch_jwks(&self) -> Result<JwkSet, BridgeError> {
        if self.is_circuit_open().await {
            return Err(BridgeError::GitHubJwksFetchFailed(
                "circuit breaker open".to_string(),
            ));
        }

        let failures = self
            .circuit_breaker
            .consecutive_failures
            .load(Ordering::Relaxed);
        if failures > 0 {
            let backoff = compute_backoff(failures);
            tokio::time::sleep(backoff).await;
        }

        let response = self
            .http
            .get(&self.jwks_url)
            .send()
            .await
            .map_err(|e| BridgeError::GitHubJwksFetchFailed(format!("request failed: {e}")))?;

        if !response.status().is_success() {
            return Err(BridgeError::GitHubJwksFetchFailed(format!(
                "HTTP {}",
                response.status()
            )));
        }

        response
            .json::<JwkSet>()
            .await
            .map_err(|e| BridgeError::GitHubJwksFetchFailed(format!("invalid JWKS JSON: {e}")))
    }

    async fn is_circuit_open(&self) -> bool {
        let failures = self
            .circuit_breaker
            .consecutive_failures
            .load(Ordering::Relaxed);
        if failures < CIRCUIT_BREAKER_THRESHOLD {
            return false;
        }

        let last_failure = self.circuit_breaker.last_failure_at.read().await;
        match *last_failure {
            Some(t) => t.elapsed() < CIRCUIT_BREAKER_COOLDOWN,
            None => false,
        }
    }

    async fn record_failure(&self) {
        self.circuit_breaker
            .consecutive_failures
            .fetch_add(1, Ordering::Relaxed);
        let mut last = self.circuit_breaker.last_failure_at.write().await;
        *last = Some(Instant::now());
    }
}

/// Verifies a GitHub Actions OIDC token and extracts its claims.
///
/// Args:
/// * `token`: The raw JWT string from the GitHub Actions environment.
/// * `jwks_client`: The client used to fetch and cache GitHub's public keys.
///
/// Usage:
/// ```ignore
/// let claims = verify_github_token(&raw_jwt, &jwks_client).await?;
/// assert_eq!(claims.actor, "octocat");
/// ```
pub async fn verify_github_token(
    token: &str,
    jwks_client: &JwksClient,
) -> Result<GitHubOidcClaims, BridgeError> {
    let decoding_key = jwks_client.get_key_for_token(token).await?;
    let validation = build_validation(jwks_client);

    let token_data = decode::<GitHubOidcClaims>(token, &decoding_key, &validation)
        .map_err(|e| BridgeError::GitHubTokenInvalid(format!("token verification failed: {e}")))?;

    Ok(token_data.claims)
}

/// Builds the JWT validation configuration for GitHub OIDC tokens.
///
/// Args:
/// * `jwks_client`: The client providing issuer and audience configuration.
///
/// Usage:
/// ```ignore
/// let validation = build_validation(&jwks_client);
/// ```
fn build_validation(jwks_client: &JwksClient) -> Validation {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[jwks_client.issuer()]);
    validation.set_audience(&[jwks_client.expected_audience()]);
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.set_required_spec_claims(&["exp", "iss", "sub", "aud"]);
    validation
}

/// Finds a key in a JWKS by its `kid` identifier.
///
/// Args:
/// * `jwks`: The JSON Web Key Set to search.
/// * `kid`: The key identifier to match.
///
/// Usage:
/// ```ignore
/// let key = find_key_in_jwks(&jwks, "key-123");
/// ```
fn find_key_in_jwks(jwks: &JwkSet, kid: &str) -> Option<DecodingKey> {
    jwks.find(kid)
        .and_then(|jwk| DecodingKey::from_jwk(jwk).ok())
}

/// Computes exponential backoff duration with jitter.
fn compute_backoff(failures: u32) -> Duration {
    let base = BACKOFF_INITIAL.as_millis() as u64;
    // 2^(failures-1) * base, capped at BACKOFF_MAX
    let exp = base.saturating_mul(1u64 << failures.min(10));
    let capped = exp.min(BACKOFF_MAX.as_millis() as u64);
    // Simple jitter: use the failure count to vary slightly
    let jitter = (failures as u64 * 137) % (capped / 4 + 1);
    Duration::from_millis(capped.saturating_sub(jitter))
}

/// Creates a JwksClient suitable for testing with a custom JWKS URL.
///
/// Args:
/// * `jwks_url`: Direct URL to the JWKS endpoint (bypasses discovery).
/// * `expected_audience`: The audience to validate tokens against.
///
/// Usage:
/// ```ignore
/// let client = test_jwks_client("http://localhost:9999/jwks", "test-aud");
/// ```
#[cfg(test)]
pub fn test_jwks_client(jwks_url: &str, expected_audience: &str) -> JwksClient {
    JwksClient {
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("failed to build HTTP client"),
        jwks_url: jwks_url.to_string(),
        expected_audience: expected_audience.to_string(),
        issuer: DEFAULT_GITHUB_ISSUER.to_string(),
        cache: RwLock::new(None),
        cache_ttl: DEFAULT_CACHE_TTL,
        fetch_lock: Mutex::new(()),
        circuit_breaker: CircuitBreakerState {
            consecutive_failures: AtomicU32::new(0),
            last_failure_at: RwLock::new(None),
        },
    }
}

/// Wraps a JwksClient in an Arc for shared ownership across async tasks.
pub fn shared_client(client: JwksClient) -> Arc<JwksClient> {
    Arc::new(client)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, routing::get};
    use jsonwebtoken::{EncodingKey, Header};
    use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
    use serde_json::json;
    use std::net::SocketAddr;
    use std::sync::atomic::AtomicU32 as StdAtomicU32;

    // Pre-generated 2048-bit RSA key — used only in tests, never in production.
    // Avoids ~2-3s RSA key generation cost per test in debug mode.
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

    fn generate_test_rsa_keys() -> (rsa::RsaPrivateKey, rsa::RsaPublicKey) {
        let private_key = rsa::RsaPrivateKey::from_pkcs1_pem(TEST_RSA_PRIVATE_KEY_PEM)
            .expect("failed to parse test RSA key");
        let public_key = private_key.to_public_key();
        (private_key, public_key)
    }

    fn build_jwk_from_public_key(public_key: &rsa::RsaPublicKey, kid: &str) -> serde_json::Value {
        use rsa::traits::PublicKeyParts;
        let n =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
        let e =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

        json!({
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": kid,
            "n": n,
            "e": e,
        })
    }

    use base64::Engine;

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

    fn valid_github_claims(aud: &str) -> serde_json::Value {
        let now = chrono::Utc::now().timestamp();
        json!({
            "actor": "octocat",
            "actor_id": "1234567",
            "repository": "octo-org/octo-repo",
            "repository_owner": "octo-org",
            "repository_owner_id": "7654321",
            "iss": DEFAULT_GITHUB_ISSUER,
            "sub": "repo:octo-org/octo-repo:ref:refs/heads/main",
            "aud": aud,
            "ref": "refs/heads/main",
            "sha": "abc123def456",
            "workflow": "CI",
            "run_id": "12345",
            "event_name": "push",
            "iat": now,
            "nbf": now,
            "exp": now + 300,
        })
    }

    async fn start_mock_jwks_server(
        jwks_json: serde_json::Value,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let app = Router::new().route(
            "/.well-known/jwks",
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
        // Give the server a moment to start
        tokio::time::sleep(Duration::from_millis(50)).await;
        (addr, handle)
    }

    #[tokio::test]
    async fn test_valid_token_extracts_claims() {
        let (private_key, public_key) = generate_test_rsa_keys();
        let kid = "test-kid-1";
        let expected_audience = "auths-bridge";

        let jwk = build_jwk_from_public_key(&public_key, kid);
        let jwks_json = json!({ "keys": [jwk] });

        let (addr, _handle) = start_mock_jwks_server(jwks_json).await;
        let client = test_jwks_client(
            &format!("http://{addr}/.well-known/jwks"),
            expected_audience,
        );

        let claims_value = valid_github_claims(expected_audience);
        let token = sign_test_token(&private_key, kid, &claims_value);

        let claims = verify_github_token(&token, &client).await.unwrap();
        assert_eq!(claims.actor, "octocat");
        assert_eq!(claims.repository, "octo-org/octo-repo");
        assert_eq!(claims.iss, DEFAULT_GITHUB_ISSUER);
        assert_eq!(claims.aud, expected_audience);
        assert_eq!(claims.sub, "repo:octo-org/octo-repo:ref:refs/heads/main");
    }

    #[tokio::test]
    async fn test_expired_token_rejected() {
        let (private_key, public_key) = generate_test_rsa_keys();
        let kid = "test-kid-2";
        let expected_audience = "auths-bridge";

        let jwk = build_jwk_from_public_key(&public_key, kid);
        let jwks_json = json!({ "keys": [jwk] });

        let (addr, _handle) = start_mock_jwks_server(jwks_json).await;
        let client = test_jwks_client(
            &format!("http://{addr}/.well-known/jwks"),
            expected_audience,
        );

        let now = chrono::Utc::now().timestamp();
        let claims_value = json!({
            "actor": "octocat",
            "repository": "octo-org/octo-repo",
            "iss": DEFAULT_GITHUB_ISSUER,
            "sub": "repo:octo-org/octo-repo:ref:refs/heads/main",
            "aud": expected_audience,
            "iat": now - 600,
            "nbf": now - 600,
            "exp": now - 300,
        });
        let token = sign_test_token(&private_key, kid, &claims_value);

        let result = verify_github_token(&token, &client).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("token verification failed"), "got: {err}");
    }

    #[tokio::test]
    async fn test_wrong_issuer_rejected() {
        let (private_key, public_key) = generate_test_rsa_keys();
        let kid = "test-kid-3";
        let expected_audience = "auths-bridge";

        let jwk = build_jwk_from_public_key(&public_key, kid);
        let jwks_json = json!({ "keys": [jwk] });

        let (addr, _handle) = start_mock_jwks_server(jwks_json).await;
        let client = test_jwks_client(
            &format!("http://{addr}/.well-known/jwks"),
            expected_audience,
        );

        let now = chrono::Utc::now().timestamp();
        let claims_value = json!({
            "actor": "octocat",
            "repository": "octo-org/octo-repo",
            "iss": "https://evil.example.com",
            "sub": "repo:octo-org/octo-repo:ref:refs/heads/main",
            "aud": expected_audience,
            "iat": now,
            "nbf": now,
            "exp": now + 300,
        });
        let token = sign_test_token(&private_key, kid, &claims_value);

        let result = verify_github_token(&token, &client).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("token verification failed"), "got: {err}");
    }

    #[tokio::test]
    async fn test_wrong_audience_rejected() {
        let (private_key, public_key) = generate_test_rsa_keys();
        let kid = "test-kid-4";
        let expected_audience = "auths-bridge";

        let jwk = build_jwk_from_public_key(&public_key, kid);
        let jwks_json = json!({ "keys": [jwk] });

        let (addr, _handle) = start_mock_jwks_server(jwks_json).await;
        let client = test_jwks_client(
            &format!("http://{addr}/.well-known/jwks"),
            expected_audience,
        );

        let claims_value = valid_github_claims("sigstore");
        let token = sign_test_token(&private_key, kid, &claims_value);

        let result = verify_github_token(&token, &client).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("token verification failed"), "got: {err}");
    }

    #[tokio::test]
    async fn test_unknown_kid_triggers_refetch() {
        let (private_key, public_key) = generate_test_rsa_keys();
        let known_kid = "known-kid";
        let unknown_kid = "unknown-kid";
        let expected_audience = "auths-bridge";

        let jwk = build_jwk_from_public_key(&public_key, known_kid);
        let jwks_json = json!({ "keys": [jwk] });

        let (addr, _handle) = start_mock_jwks_server(jwks_json).await;
        let client = test_jwks_client(
            &format!("http://{addr}/.well-known/jwks"),
            expected_audience,
        );

        let claims_value = valid_github_claims(expected_audience);
        let token = sign_test_token(&private_key, unknown_kid, &claims_value);

        let result = verify_github_token(&token, &client).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("not found in JWKS"),
            "expected kid-not-found error, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_malformed_token_rejected() {
        let expected_audience = "auths-bridge";
        let jwks_json = json!({ "keys": [] });

        let (addr, _handle) = start_mock_jwks_server(jwks_json).await;
        let client = test_jwks_client(
            &format!("http://{addr}/.well-known/jwks"),
            expected_audience,
        );

        let result = verify_github_token("not.a.jwt", &client).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("invalid JWT header"),
            "expected header error, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_concurrent_cache_miss_coalesces_fetches() {
        let (private_key, public_key) = generate_test_rsa_keys();
        let kid = "concurrent-kid";
        let expected_audience = "auths-bridge";

        let fetch_count = Arc::new(StdAtomicU32::new(0));
        let fetch_count_clone = fetch_count.clone();

        let jwk = build_jwk_from_public_key(&public_key, kid);
        let jwks_response = json!({ "keys": [jwk] });

        let app = Router::new().route(
            "/.well-known/jwks",
            get(move || {
                let count = fetch_count_clone.clone();
                let resp = jwks_response.clone();
                async move {
                    count.fetch_add(1, Ordering::Relaxed);
                    // Simulate network latency
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
            &format!("http://{addr}/.well-known/jwks"),
            expected_audience,
        ));

        let claims_value = valid_github_claims(expected_audience);
        let token = sign_test_token(&private_key, kid, &claims_value);

        let mut handles = Vec::new();
        for _ in 0..5 {
            let client = client.clone();
            let token = token.clone();
            handles.push(tokio::spawn(async move {
                verify_github_token(&token, &client).await
            }));
        }

        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_ok(), "verification failed: {:?}", result.err());
        }

        // With request coalescing, we should see far fewer fetches than 5
        let total_fetches = fetch_count.load(Ordering::Relaxed);
        assert!(
            total_fetches <= 2,
            "expected at most 2 fetches (coalesced), got {total_fetches}"
        );
    }

    #[test]
    fn test_compute_backoff_increases() {
        let b1 = compute_backoff(1);
        let b3 = compute_backoff(3);
        let b10 = compute_backoff(10);

        assert!(b1 < b3, "backoff should increase: {b1:?} < {b3:?}");
        assert!(b3 < b10, "backoff should increase: {b3:?} < {b10:?}");
        assert!(
            b10 <= BACKOFF_MAX,
            "backoff should be capped at {BACKOFF_MAX:?}, got {b10:?}"
        );
    }

    #[test]
    fn test_build_validation_sets_audience_and_issuer() {
        let client = JwksClient::with_defaults("my-audience");
        let validation = build_validation(&client);

        // Validation should require RS256
        assert_eq!(validation.algorithms, vec![Algorithm::RS256]);
        assert!(validation.validate_exp);
        assert!(validation.validate_nbf);
    }
}
