use async_trait::async_trait;
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::Jwk};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroize;

use crate::default_http_client;
use auths_oidc_port::{JwksClient, JwtValidator, OidcError, OidcValidationConfig};

/// OIDC claims structure with standard JWT fields.
///
/// # Usage
///
/// ```ignore
/// use auths_infra_http::HttpJwtValidator;
/// use chrono::Utc;
///
/// let validator = HttpJwtValidator::new(jwks_client);
/// let claims = validator.validate(token, &config, Utc::now()).await?;
/// ```
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OidcTokenClaims {
    /// Subject (user/service identity)
    pub sub: String,
    /// Issuer
    pub iss: String,
    /// Audience
    pub aud: String,
    /// Expiration time
    pub exp: i64,
    /// Issued at time
    #[serde(default)]
    pub iat: i64,
    /// Not before time
    #[serde(default)]
    pub nbf: Option<i64>,
    /// JWT ID (jti) for replay detection
    #[serde(default)]
    pub jti: Option<String>,
    /// Additional claims (passed through as extra fields)
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// HTTP-based implementation of JwtValidator using jsonwebtoken crate.
///
/// Validates JWT tokens by:
/// 1. Extracting JWT header to get kid and alg
/// 2. Fetching JWKS from issuer via injected JwksClient
/// 3. Matching kid to find the appropriate key
/// 4. Building Validation struct with explicit algorithm and claims validation
/// 5. Calling jsonwebtoken::decode() with full validation
/// 6. Returning claims as JSON value
pub struct HttpJwtValidator {
    jwks_client: Arc<dyn JwksClient>,
}

impl HttpJwtValidator {
    /// Create a new HttpJwtValidator with the given JWKS client.
    ///
    /// # Args
    ///
    /// * `jwks_client`: JWKS client for fetching and caching public keys
    pub fn new(jwks_client: Arc<dyn JwksClient>) -> Self {
        Self { jwks_client }
    }
}

#[async_trait]
impl JwtValidator for HttpJwtValidator {
    async fn validate(
        &self,
        token: &str,
        config: &OidcValidationConfig,
        now: DateTime<Utc>,
    ) -> Result<serde_json::Value, OidcError> {
        let mut token_mut = token.to_string();

        let header = decode_header(&token_mut)
            .map_err(|e| OidcError::JwtDecode(format!("failed to decode JWT header: {}", e)))?;

        let kid = header
            .kid
            .ok_or_else(|| OidcError::JwtDecode("JWT header missing 'kid' field".to_string()))?;

        let alg_str = format!("{:?}", header.alg);
        if alg_str.to_uppercase() == "NONE" {
            return Err(OidcError::AlgorithmMismatch {
                expected: "RS256 or ES256".to_string(),
                got: "none".to_string(),
            });
        }

        if !config
            .allowed_algorithms
            .iter()
            .any(|allowed| allowed.to_uppercase() == alg_str.to_uppercase())
        {
            return Err(OidcError::AlgorithmMismatch {
                expected: config.allowed_algorithms.join(", "),
                got: alg_str.clone(),
            });
        }

        let jwks = self.jwks_client.fetch_jwks(&config.issuer).await?;

        let keys = jwks.get("keys").and_then(|k| k.as_array()).ok_or_else(|| {
            OidcError::JwksResolutionFailed("JWKS response missing 'keys' array".to_string())
        })?;

        let key_obj = keys
            .iter()
            .find(|key| {
                key.get("kid")
                    .and_then(|k| k.as_str())
                    .map(|k| k == kid)
                    .unwrap_or(false)
            })
            .ok_or_else(|| OidcError::UnknownKeyId(kid.clone()))?;

        let jwk: Jwk = serde_json::from_value(key_obj.clone()).map_err(|e| {
            OidcError::JwksResolutionFailed(format!(
                "failed to parse JWKS key for kid {}: {}",
                kid, e
            ))
        })?;

        let decoding_key = DecodingKey::from_jwk(&jwk).map_err(|e| {
            OidcError::JwksResolutionFailed(format!(
                "failed to create decoding key for kid {}: {}",
                kid, e
            ))
        })?;

        let now_secs = now.timestamp();
        let leeway = config.max_clock_skew_secs as u64;

        let algorithm = match alg_str.to_uppercase().as_str() {
            "RS256" => Algorithm::RS256,
            "ES256" => Algorithm::ES256,
            _ => {
                return Err(OidcError::AlgorithmMismatch {
                    expected: "RS256 or ES256".to_string(),
                    got: alg_str,
                });
            }
        };

        let mut validation = Validation::new(algorithm);

        validation.set_issuer(&[&config.issuer]);
        validation.set_audience(&[&config.audience]);
        validation.leeway = leeway;
        validation.validate_exp = true;
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);

        let token_data = decode::<OidcTokenClaims>(&token_mut, &decoding_key, &validation)
            .map_err(|e| {
                let error_msg = format!("{}", e);
                if error_msg.contains("ExpiredSignature") || error_msg.contains("InvalidIssuedAt") {
                    OidcError::ClockSkewExceeded {
                        token_exp: 0,
                        current_time: now_secs,
                        leeway: leeway as i64,
                    }
                } else if error_msg.contains("InvalidSignature") {
                    OidcError::SignatureVerificationFailed
                } else if error_msg.contains("InvalidIssuer") {
                    OidcError::ClaimsValidationFailed {
                        claim: "iss".to_string(),
                        reason: "issuer mismatch".to_string(),
                    }
                } else if error_msg.contains("InvalidAudience") {
                    OidcError::ClaimsValidationFailed {
                        claim: "aud".to_string(),
                        reason: "audience mismatch".to_string(),
                    }
                } else {
                    OidcError::JwtDecode(format!("JWT validation failed: {}", e))
                }
            })?;

        token_mut.zeroize();

        let mut json = serde_json::json!(token_data.claims);
        if let Some(obj) = json.as_object_mut() {
            for (k, v) in token_data.claims.extra.iter() {
                obj.insert(k.clone(), v.clone());
            }
        }

        Ok(json)
    }
}

/// HTTP-based implementation of JwksClient with built-in caching.
///
/// Caches JWKS responses with configurable TTL to avoid repeated network calls.
/// Implements refresh-ahead pattern to reduce cache misses.
pub struct HttpJwksClient {
    cache: Arc<RwLock<JwksCache>>,
}

struct JwksCache {
    data: Option<serde_json::Value>,
    expires_at: Option<DateTime<Utc>>,
    ttl: Duration,
}

impl HttpJwksClient {
    /// Create a new HttpJwksClient with the given cache TTL.
    ///
    /// # Args
    ///
    /// * `ttl`: Cache time-to-live duration
    pub fn new(ttl: Duration) -> Self {
        Self {
            cache: Arc::new(RwLock::new(JwksCache {
                data: None,
                expires_at: None,
                ttl,
            })),
        }
    }

    /// Create a new HttpJwksClient with default TTL of 1 hour.
    pub fn with_default_ttl() -> Self {
        Self::new(Duration::from_secs(3600))
    }
}

#[async_trait]
impl JwksClient for HttpJwksClient {
    async fn fetch_jwks(&self, issuer_url: &str) -> Result<serde_json::Value, OidcError> {
        #[allow(clippy::disallowed_methods)] // Cache refresh: needs current time
        let now = Utc::now();
        {
            let cache = self.cache.read();
            if let Some(data) = &cache.data
                && let Some(expires_at) = cache.expires_at
                && now < expires_at
            {
                return Ok(data.clone());
            }
        }

        let jwks_url = format!(
            "{}{}",
            issuer_url.trim_end_matches('/'),
            "/.well-known/jwks.json"
        );

        let client = default_http_client();
        let response = client.get(&jwks_url).send().await.map_err(|e| {
            OidcError::JwksResolutionFailed(format!(
                "failed to fetch JWKS from {}: {}",
                jwks_url, e
            ))
        })?;

        let jwks: serde_json::Value = response.json().await.map_err(|e| {
            OidcError::JwksResolutionFailed(format!(
                "failed to parse JWKS response from {}: {}",
                jwks_url, e
            ))
        })?;

        let mut cache = self.cache.write();
        cache.data = Some(jwks.clone());
        // INVARIANT: cache.ttl is always a valid Duration (max 1 hour)
        #[allow(clippy::expect_used)]
        let duration_offset = chrono::Duration::from_std(cache.ttl).expect("cache TTL overflow");
        cache.expires_at = Some(now + duration_offset);

        Ok(jwks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_oidc_port::OidcValidationConfig;

    #[tokio::test]
    async fn test_http_jwt_validator_missing_kid() {
        let mock_client = MockJwksClient::new();
        let validator = HttpJwtValidator::new(Arc::new(mock_client));

        let invalid_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let config = OidcValidationConfig::builder()
            .issuer("https://example.com")
            .audience("test")
            .build()
            .unwrap();

        #[allow(clippy::disallowed_methods)] // Test boundary
        let result = validator.validate(invalid_token, &config, Utc::now()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_algorithm_none_rejected() {
        let mock_client = MockJwksClient::new();
        let validator = HttpJwtValidator::new(Arc::new(mock_client));

        let token_none = "eyJhbGciOiJub25lIiwia2lkIjoiYWJjIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.";
        let config = OidcValidationConfig::builder()
            .issuer("https://example.com")
            .audience("test")
            .build()
            .unwrap();

        #[allow(clippy::disallowed_methods)] // Test boundary
        let result = validator.validate(token_none, &config, Utc::now()).await;
        assert!(matches!(result, Err(OidcError::AlgorithmMismatch { .. })));
    }

    struct MockJwksClient;

    impl MockJwksClient {
        fn new() -> Self {
            Self
        }
    }

    #[async_trait]
    impl JwksClient for MockJwksClient {
        async fn fetch_jwks(&self, _issuer_url: &str) -> Result<serde_json::Value, OidcError> {
            Ok(serde_json::json!({
                "keys": [
                    {
                        "kty": "RSA",
                        "kid": "test-key-1",
                        "use": "sig",
                        "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                        "e": "AQAB"
                    }
                ]
            }))
        }
    }
}
