use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::OidcError;

/// Configuration for OIDC token validation.
///
/// # Usage
///
/// ```ignore
/// use auths_oidc_port::{OidcValidationConfig, OidcValidationConfigBuilder};
///
/// let config = OidcValidationConfig::builder()
///     .issuer("https://token.actions.githubusercontent.com")
///     .audience("sigstore")
///     .allowed_algorithms(vec!["RS256".to_string()])
///     .max_clock_skew_secs(60)
///     .jwks_cache_ttl_secs(3600)
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct OidcValidationConfig {
    /// The expected JWT issuer (e.g., "https://token.actions.githubusercontent.com" for GitHub Actions)
    pub issuer: String,
    /// The expected JWT audience (e.g., "sigstore")
    pub audience: String,
    /// Allowed JWT algorithms (e.g., vec!["RS256"])
    pub allowed_algorithms: Vec<String>,
    /// Maximum clock skew tolerance in seconds
    pub max_clock_skew_secs: i64,
    /// JWKS cache TTL in seconds
    pub jwks_cache_ttl_secs: u64,
}

impl OidcValidationConfig {
    /// Create a new builder for `OidcValidationConfig`.
    pub fn builder() -> OidcValidationConfigBuilder {
        OidcValidationConfigBuilder::default()
    }
}

/// Builder for `OidcValidationConfig`.
#[derive(Debug, Default)]
pub struct OidcValidationConfigBuilder {
    issuer: Option<String>,
    audience: Option<String>,
    allowed_algorithms: Option<Vec<String>>,
    max_clock_skew_secs: Option<i64>,
    jwks_cache_ttl_secs: Option<u64>,
}

impl OidcValidationConfigBuilder {
    /// Set the expected JWT issuer.
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Set the expected JWT audience.
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Set the allowed JWT algorithms.
    pub fn allowed_algorithms(mut self, algorithms: Vec<String>) -> Self {
        self.allowed_algorithms = Some(algorithms);
        self
    }

    /// Set the maximum clock skew tolerance in seconds.
    pub fn max_clock_skew_secs(mut self, secs: i64) -> Self {
        self.max_clock_skew_secs = Some(secs);
        self
    }

    /// Set the JWKS cache TTL in seconds.
    pub fn jwks_cache_ttl_secs(mut self, secs: u64) -> Self {
        self.jwks_cache_ttl_secs = Some(secs);
        self
    }

    /// Build the `OidcValidationConfig`.
    pub fn build(self) -> Result<OidcValidationConfig, String> {
        Ok(OidcValidationConfig {
            issuer: self
                .issuer
                .ok_or_else(|| "issuer is required".to_string())?,
            audience: self
                .audience
                .ok_or_else(|| "audience is required".to_string())?,
            allowed_algorithms: self
                .allowed_algorithms
                .unwrap_or_else(|| vec!["RS256".to_string(), "ES256".to_string()]),
            max_clock_skew_secs: self.max_clock_skew_secs.unwrap_or(60),
            jwks_cache_ttl_secs: self.jwks_cache_ttl_secs.unwrap_or(3600),
        })
    }
}

/// Configuration for RFC 3161 timestamp authority operations.
///
/// # Usage
///
/// ```ignore
/// use auths_oidc_port::TimestampConfig;
///
/// let config = TimestampConfig {
///     tsa_uri: Some("http://timestamp.sigstore.dev/api/v1/timestamp".to_string()),
///     timeout_secs: 10,
///     fallback_on_error: true,
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestampConfig {
    /// Optional URI to the RFC 3161 Timestamp Authority
    pub tsa_uri: Option<String>,
    /// Timeout in seconds for TSA requests
    pub timeout_secs: u64,
    /// Whether to gracefully degrade if TSA is unavailable
    pub fallback_on_error: bool,
}

impl Default for TimestampConfig {
    fn default() -> Self {
        Self {
            tsa_uri: Some("http://timestamp.sigstore.dev/api/v1/timestamp".to_string()),
            timeout_secs: 10,
            fallback_on_error: true,
        }
    }
}

/// Port trait for JWT validation.
///
/// Implementations of this trait handle JWT decoding, signature verification via JWKS,
/// and claims validation with configurable clock skew tolerance.
///
/// # Usage
///
/// ```ignore
/// use auths_oidc_port::{JwtValidator, OidcValidationConfig};
/// use chrono::Utc;
///
/// async fn validate_token(validator: &dyn JwtValidator, token: &str) {
///     let config = OidcValidationConfig::builder()
///         .issuer("https://token.actions.githubusercontent.com")
///         .audience("sigstore")
///         .build()
///         .unwrap();
///
///     let claims = validator.validate(token, &config, Utc::now()).await;
/// }
/// ```
#[async_trait::async_trait]
pub trait JwtValidator: Send + Sync {
    /// Validate and extract claims from a JWT token.
    ///
    /// # Args
    ///
    /// * `token`: The raw JWT string
    /// * `config`: OIDC validation configuration
    /// * `now`: Current UTC time for expiry checking
    ///
    /// # Returns
    ///
    /// Validated claims as a JSON value, or OidcError if validation fails
    async fn validate(
        &self,
        token: &str,
        config: &OidcValidationConfig,
        now: DateTime<Utc>,
    ) -> Result<serde_json::Value, OidcError>;
}

/// Port trait for JWKS (JSON Web Key Set) resolution and caching.
///
/// Implementations fetch and cache JWKS from OIDC provider endpoints.
/// Caching strategy (TTL, refresh-ahead) is implementation-dependent.
///
/// # Usage
///
/// ```ignore
/// use auths_oidc_port::JwksClient;
///
/// async fn fetch_keys(client: &dyn JwksClient) {
///     let jwks = client.fetch_jwks("https://token.actions.githubusercontent.com").await;
/// }
/// ```
#[async_trait::async_trait]
pub trait JwksClient: Send + Sync {
    /// Fetch the JWKS from the specified issuer endpoint.
    ///
    /// Implementations should cache the result to avoid repeated network calls.
    /// TTL and refresh strategies are implementation-defined.
    ///
    /// # Args
    ///
    /// * `issuer_url`: The base URL of the OIDC provider
    ///
    /// # Returns
    ///
    /// The JWKS (as a JSON object containing a "keys" array), or OidcError if fetch fails
    async fn fetch_jwks(&self, issuer_url: &str) -> Result<serde_json::Value, OidcError>;
}

/// Port trait for RFC 3161 timestamp authority operations.
///
/// Optional timestamp authority integration for proving signature creation time.
/// Graceful degradation if the TSA is unavailable or not configured.
///
/// # Usage
///
/// ```ignore
/// use auths_oidc_port::{TimestampClient, TimestampConfig};
///
/// async fn timestamp_signature(client: &dyn TimestampClient, data: &[u8]) {
///     let config = TimestampConfig::default();
///     let token = client.timestamp(data, &config).await;
/// }
/// ```
#[async_trait::async_trait]
pub trait TimestampClient: Send + Sync {
    /// Create an RFC 3161 timestamp for the given data.
    ///
    /// If TSA is not configured or unavailable, returns Ok(None) if fallback_on_error is true.
    ///
    /// # Args
    ///
    /// * `data`: The data to timestamp
    /// * `config`: Timestamp authority configuration
    ///
    /// # Returns
    ///
    /// RFC 3161 timestamp response (ASN.1 DER encoded), or None if TSA unavailable and fallback enabled
    async fn timestamp(
        &self,
        data: &[u8],
        config: &TimestampConfig,
    ) -> Result<Option<Vec<u8>>, OidcError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oidc_validation_config_builder() {
        let config = OidcValidationConfig::builder()
            .issuer("https://token.actions.githubusercontent.com")
            .audience("sigstore")
            .allowed_algorithms(vec!["RS256".to_string()])
            .max_clock_skew_secs(120)
            .jwks_cache_ttl_secs(7200)
            .build();

        assert!(config.is_ok());
        let cfg = config.unwrap();
        assert_eq!(cfg.issuer, "https://token.actions.githubusercontent.com");
        assert_eq!(cfg.audience, "sigstore");
        assert_eq!(cfg.allowed_algorithms, vec!["RS256"]);
        assert_eq!(cfg.max_clock_skew_secs, 120);
        assert_eq!(cfg.jwks_cache_ttl_secs, 7200);
    }

    #[test]
    fn test_oidc_validation_config_defaults() {
        let config = OidcValidationConfig::builder()
            .issuer("https://example.com")
            .audience("test")
            .build();

        assert!(config.is_ok());
        let cfg = config.unwrap();
        assert_eq!(cfg.max_clock_skew_secs, 60);
        assert_eq!(cfg.jwks_cache_ttl_secs, 3600);
        assert_eq!(
            cfg.allowed_algorithms,
            vec!["RS256".to_string(), "ES256".to_string()]
        );
    }

    #[test]
    fn test_oidc_validation_config_missing_issuer() {
        let config = OidcValidationConfig::builder().audience("test").build();

        assert!(config.is_err());
    }

    #[test]
    fn test_oidc_validation_config_missing_audience() {
        let config = OidcValidationConfig::builder()
            .issuer("https://example.com")
            .build();

        assert!(config.is_err());
    }

    #[test]
    fn test_timestamp_config_default() {
        let config = TimestampConfig::default();
        assert!(config.tsa_uri.is_some());
        assert_eq!(config.timeout_secs, 10);
        assert!(config.fallback_on_error);
    }

    #[test]
    fn test_timestamp_config_custom() {
        let config = TimestampConfig {
            tsa_uri: Some("http://custom-tsa.example.com".to_string()),
            timeout_secs: 20,
            fallback_on_error: false,
        };
        assert_eq!(
            config.tsa_uri,
            Some("http://custom-tsa.example.com".to_string())
        );
        assert_eq!(config.timeout_secs, 20);
        assert!(!config.fallback_on_error);
    }
}
