//! JWKS client for fetching and caching the OIDC bridge's public keys.

use std::time::{Duration, Instant};

use jsonwebtoken::DecodingKey;
use jsonwebtoken::jwk::JwkSet;
use tokio::sync::{Mutex, RwLock};

use crate::error::McpServerError;

struct CachedJwks {
    keys: JwkSet,
    fetched_at: Instant,
}

/// Client that fetches and caches JWKS from the OIDC bridge.
///
/// Args:
/// * `jwks_url`: The bridge's `/.well-known/jwks.json` endpoint.
/// * `cache_ttl`: How long to cache JWKS keys before refreshing.
///
/// Usage:
/// ```ignore
/// let client = JwksCache::new("http://localhost:3300/.well-known/jwks.json", Duration::from_secs(3600));
/// let key = client.get_key_for_kid("abc123").await?;
/// ```
pub struct JwksCache {
    http: reqwest::Client,
    jwks_url: String,
    cache: RwLock<Option<CachedJwks>>,
    cache_ttl: Duration,
    fetch_lock: Mutex<()>,
}

impl JwksCache {
    /// Creates a new JWKS cache.
    ///
    /// Args:
    /// * `jwks_url`: The JWKS endpoint URL.
    /// * `cache_ttl`: Cache duration before refresh.
    pub fn new(jwks_url: impl Into<String>, cache_ttl: Duration) -> Self {
        // INVARIANT: reqwest Client::builder with only timeout cannot fail
        #[allow(clippy::expect_used)]
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("failed to build HTTP client");

        Self {
            http,
            jwks_url: jwks_url.into(),
            cache: RwLock::new(None),
            cache_ttl,
            fetch_lock: Mutex::new(()),
        }
    }

    /// Retrieves the decoding key matching the given `kid`.
    ///
    /// Args:
    /// * `kid`: The key identifier from the JWT header.
    pub async fn get_key_for_kid(&self, kid: &str) -> Result<DecodingKey, McpServerError> {
        if let Some(key) = self.find_in_cache(kid).await {
            return Ok(key);
        }

        self.refresh_and_find(kid).await
    }

    async fn find_in_cache(&self, kid: &str) -> Option<DecodingKey> {
        let cache = self.cache.read().await;
        let cached = cache.as_ref()?;

        if cached.fetched_at.elapsed() > self.cache_ttl {
            return None;
        }

        find_key_in_jwks(&cached.keys, kid)
    }

    async fn refresh_and_find(&self, kid: &str) -> Result<DecodingKey, McpServerError> {
        let _guard = self.fetch_lock.lock().await;

        // Double-check after acquiring lock
        if let Some(key) = self.find_in_cache(kid).await {
            return Ok(key);
        }

        let jwks = self.fetch_jwks().await?;
        let key = find_key_in_jwks(&jwks, kid).ok_or_else(|| {
            McpServerError::TokenInvalid(format!("kid '{kid}' not found in JWKS"))
        })?;

        let mut cache = self.cache.write().await;
        *cache = Some(CachedJwks {
            keys: jwks,
            fetched_at: Instant::now(),
        });

        Ok(key)
    }

    async fn fetch_jwks(&self) -> Result<JwkSet, McpServerError> {
        let response = self
            .http
            .get(&self.jwks_url)
            .send()
            .await
            .map_err(|e| McpServerError::JwksError(format!("request failed: {e}")))?;

        if !response.status().is_success() {
            return Err(McpServerError::JwksError(format!(
                "HTTP {}",
                response.status()
            )));
        }

        response
            .json::<JwkSet>()
            .await
            .map_err(|e| McpServerError::JwksError(format!("invalid JWKS JSON: {e}")))
    }
}

fn find_key_in_jwks(jwks: &JwkSet, kid: &str) -> Option<DecodingKey> {
    jwks.find(kid)
        .and_then(|jwk| DecodingKey::from_jwk(jwk).ok())
}
