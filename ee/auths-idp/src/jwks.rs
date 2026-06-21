//! Generic OIDC JWKS client with caching, circuit-breaker, and request coalescing.
//!
//! Extracted from the GitHub-specific `JwksClient` in `auths-oidc-bridge`,
//! generalized for any OIDC provider (Okta, Entra ID, Google Workspace, etc.).

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use jsonwebtoken::DecodingKey;
use jsonwebtoken::jwk::JwkSet;
use tokio::sync::{Mutex, RwLock};

use crate::error::IdpError;

const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(3600);
const CIRCUIT_BREAKER_THRESHOLD: u32 = 5;
const CIRCUIT_BREAKER_COOLDOWN: Duration = Duration::from_secs(60);
const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

struct CachedJwks {
    keys: JwkSet,
    fetched_at: Instant,
}

struct CircuitBreakerState {
    consecutive_failures: AtomicU32,
    last_failure_at: RwLock<Option<Instant>>,
}

/// Generic OIDC JWKS client with resilient fetching.
///
/// Provides caching with configurable TTL, thundering-herd protection
/// via request coalescing, exponential backoff on failures, circuit-breaker
/// after consecutive failures, and stale-cache fallback on transient errors.
///
/// Args:
/// * `issuer`: The OIDC issuer URL (used to derive the JWKS endpoint).
/// * `expected_audience`: Audience to validate tokens against (confused-deputy prevention).
/// * `cache_ttl`: How long to cache JWKS keys before refreshing.
///
/// Usage:
/// ```ignore
/// let client = OidcJwksClient::new(
///     "https://company.okta.com",
///     "my-app-client-id",
///     Duration::from_secs(3600),
/// );
/// let key = client.get_key_for_token(&jwt).await?;
/// ```
pub struct OidcJwksClient {
    http: reqwest::Client,
    jwks_url: String,
    expected_audience: String,
    issuer: String,
    cache: RwLock<Option<CachedJwks>>,
    cache_ttl: Duration,
    fetch_lock: Mutex<()>,
    circuit_breaker: CircuitBreakerState,
}

impl OidcJwksClient {
    /// Creates a new JWKS client.
    ///
    /// Args:
    /// * `issuer`: The OIDC issuer URL.
    /// * `expected_audience`: The audience to validate tokens against.
    /// * `cache_ttl`: How long to cache JWKS keys before refreshing.
    ///
    /// Usage:
    /// ```ignore
    /// let client = OidcJwksClient::new(
    ///     "https://login.microsoftonline.com/{tenant}/v2.0",
    ///     "client-id",
    ///     Duration::from_secs(3600),
    /// );
    /// ```
    pub fn new(issuer: &str, expected_audience: &str, cache_ttl: Duration) -> Self {
        let jwks_url = format!(
            "{}/.well-known/openid-configuration/jwks",
            issuer.trim_end_matches('/')
        );
        Self {
            // INVARIANT: reqwest Client::builder with only timeout cannot fail
            #[allow(clippy::expect_used)]
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

    /// Creates a new JWKS client with default 1-hour cache TTL.
    ///
    /// Args:
    /// * `issuer`: The OIDC issuer URL.
    /// * `expected_audience`: The audience to validate tokens against.
    ///
    /// Usage:
    /// ```ignore
    /// let client = OidcJwksClient::with_defaults("https://company.okta.com", "client-id");
    /// ```
    pub fn with_defaults(issuer: &str, expected_audience: &str) -> Self {
        Self::new(issuer, expected_audience, DEFAULT_CACHE_TTL)
    }

    /// Returns the configured expected audience.
    pub fn expected_audience(&self) -> &str {
        &self.expected_audience
    }

    /// Returns the configured issuer URL.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Returns the JWKS endpoint URL.
    pub fn jwks_url(&self) -> &str {
        &self.jwks_url
    }

    /// Retrieves the decoding key for a JWT by matching its `kid` header.
    ///
    /// Args:
    /// * `token`: The raw JWT string to find the matching key for.
    ///
    /// Usage:
    /// ```ignore
    /// let key = client.get_key_for_token(&jwt_string).await?;
    /// ```
    pub async fn get_key_for_token(&self, token: &str) -> Result<DecodingKey, IdpError> {
        let header = jsonwebtoken::decode_header(token)
            .map_err(|e| IdpError::TokenInvalid(format!("invalid JWT header: {e}")))?;

        let kid = header
            .kid
            .ok_or_else(|| IdpError::TokenInvalid("JWT header missing kid".to_string()))?;

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

    async fn refresh_and_find_key(&self, kid: &str) -> Result<DecodingKey, IdpError> {
        let _guard = self.fetch_lock.lock().await;

        if let Some(key) = self.find_key_in_cache(kid).await {
            return Ok(key);
        }

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
                    IdpError::TokenInvalid(format!("kid '{kid}' not found in JWKS"))
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

    async fn fetch_jwks(&self) -> Result<JwkSet, IdpError> {
        if self.is_circuit_open().await {
            return Err(IdpError::JwksFetchFailed(
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
            .map_err(|e| IdpError::JwksFetchFailed(format!("request failed: {e}")))?;

        if !response.status().is_success() {
            return Err(IdpError::JwksFetchFailed(format!(
                "HTTP {}",
                response.status()
            )));
        }

        response
            .json::<JwkSet>()
            .await
            .map_err(|e| IdpError::JwksFetchFailed(format!("invalid JWKS JSON: {e}")))
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

/// Creates an `OidcJwksClient` with a custom JWKS URL for testing.
///
/// Args:
/// * `jwks_url`: Direct URL to the JWKS endpoint (bypasses discovery).
/// * `issuer`: The issuer URL for token validation.
/// * `expected_audience`: The audience to validate tokens against.
///
/// Usage:
/// ```ignore
/// let client = test_jwks_client("http://localhost:9999/jwks", "https://idp.example.com", "test-aud");
/// ```
pub fn test_jwks_client(jwks_url: &str, issuer: &str, expected_audience: &str) -> OidcJwksClient {
    OidcJwksClient {
        // INVARIANT: reqwest Client::builder with only timeout cannot fail
        #[allow(clippy::expect_used)]
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("failed to build HTTP client"),
        jwks_url: jwks_url.to_string(),
        expected_audience: expected_audience.to_string(),
        issuer: issuer.to_string(),
        cache: RwLock::new(None),
        cache_ttl: DEFAULT_CACHE_TTL,
        fetch_lock: Mutex::new(()),
        circuit_breaker: CircuitBreakerState {
            consecutive_failures: AtomicU32::new(0),
            last_failure_at: RwLock::new(None),
        },
    }
}

fn find_key_in_jwks(jwks: &JwkSet, kid: &str) -> Option<DecodingKey> {
    jwks.find(kid)
        .and_then(|jwk| DecodingKey::from_jwk(jwk).ok())
}

fn compute_backoff(failures: u32) -> Duration {
    let base = BACKOFF_INITIAL.as_millis() as u64;
    let exp = base.saturating_mul(1u64 << failures.min(10));
    let capped = exp.min(BACKOFF_MAX.as_millis() as u64);
    let jitter = (failures as u64 * 137) % (capped / 4 + 1);
    Duration::from_millis(capped.saturating_sub(jitter))
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_jwks_url_construction() {
        let client = OidcJwksClient::new("https://company.okta.com", "aud", DEFAULT_CACHE_TTL);
        assert_eq!(
            client.jwks_url(),
            "https://company.okta.com/.well-known/openid-configuration/jwks"
        );
    }

    #[test]
    fn test_jwks_url_strips_trailing_slash() {
        let client = OidcJwksClient::new("https://company.okta.com/", "aud", DEFAULT_CACHE_TTL);
        assert_eq!(
            client.jwks_url(),
            "https://company.okta.com/.well-known/openid-configuration/jwks"
        );
    }
}
