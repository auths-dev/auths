//! Bridge configuration.

use std::net::SocketAddr;
use std::path::PathBuf;

use crate::audience::AudienceValidation;

/// Configuration for the OIDC bridge server.
#[derive(Debug, Clone)]
pub struct BridgeConfig {
    /// Address to bind the server to.
    pub bind_addr: SocketAddr,

    /// OIDC issuer URL (must match `iss` claim in issued JWTs).
    pub issuer_url: String,

    /// Default audience for issued tokens.
    pub default_audience: Option<String>,

    /// If set, only these audiences are allowed in exchange requests.
    pub allowed_audiences: Option<Vec<String>>,

    /// Path to RSA private key PEM file.
    pub signing_key_path: Option<PathBuf>,

    /// Inline RSA private key PEM (alternative to file path).
    pub signing_key_pem: Option<String>,

    /// Default token TTL in seconds.
    pub default_ttl_secs: u64,

    /// Maximum allowed TTL in seconds.
    pub max_ttl_secs: u64,

    /// Whether rate limiting is enabled.
    pub rate_limit_enabled: bool,

    /// Maximum requests per minute per KERI prefix.
    pub rate_limit_rpm: u32,

    /// Burst size (max tokens in the bucket).
    pub rate_limit_burst: u32,

    /// Audience format validation mode.
    pub audience_validation: AudienceValidation,

    /// Admin token for key rotation endpoint.
    pub admin_token: Option<String>,

    /// Enable CORS for browser access.
    pub enable_cors: bool,

    /// Log level filter.
    pub log_level: String,

    /// Maximum delegation depth for RFC 8693 token exchange `act` claim nesting.
    pub max_delegation_depth: u32,

    /// Path to a JSON file containing the workload policy expression.
    #[cfg(feature = "oidc-policy")]
    pub workload_policy_path: Option<PathBuf>,

    /// Inline JSON string containing the workload policy expression.
    #[cfg(feature = "oidc-policy")]
    pub workload_policy_json: Option<String>,

    /// Path to a JSON file containing trust registry entries.
    #[cfg(feature = "oidc-trust")]
    pub trust_registry_path: Option<PathBuf>,

    /// GitHub OIDC issuer URL (default: "https://token.actions.githubusercontent.com").
    #[cfg(feature = "github-oidc")]
    pub github_oidc_issuer: Option<String>,

    /// Expected audience for GitHub OIDC tokens (confused deputy prevention).
    #[cfg(feature = "github-oidc")]
    pub github_expected_audience: Option<String>,

    /// Cache TTL for GitHub JWKS keys in seconds (default: 3600).
    #[cfg(feature = "github-oidc")]
    pub github_jwks_cache_ttl_secs: u64,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            bind_addr: std::net::SocketAddr::from(([0, 0, 0, 0], 3300)),
            issuer_url: "http://localhost:3300".to_string(),
            default_audience: None,
            allowed_audiences: None,
            signing_key_path: None,
            signing_key_pem: None,
            default_ttl_secs: 900,
            max_ttl_secs: 3600,
            rate_limit_enabled: true,
            rate_limit_rpm: 30,
            rate_limit_burst: 5,
            audience_validation: AudienceValidation::default(),
            admin_token: None,
            enable_cors: false,
            log_level: "info".to_string(),
            max_delegation_depth: 5,
            #[cfg(feature = "oidc-policy")]
            workload_policy_path: None,
            #[cfg(feature = "oidc-policy")]
            workload_policy_json: None,
            #[cfg(feature = "oidc-trust")]
            trust_registry_path: None,
            #[cfg(feature = "github-oidc")]
            github_oidc_issuer: None,
            #[cfg(feature = "github-oidc")]
            github_expected_audience: None,
            #[cfg(feature = "github-oidc")]
            github_jwks_cache_ttl_secs: 3600,
        }
    }
}

impl BridgeConfig {
    /// Set the bind address.
    pub fn with_addr(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = addr;
        self
    }

    /// Set the issuer URL.
    pub fn with_issuer_url(mut self, url: impl Into<String>) -> Self {
        self.issuer_url = url.into();
        self
    }

    /// Set the default audience.
    pub fn with_default_audience(mut self, audience: impl Into<String>) -> Self {
        self.default_audience = Some(audience.into());
        self
    }

    /// Set the allowed audiences.
    pub fn with_allowed_audiences(mut self, audiences: Vec<String>) -> Self {
        self.allowed_audiences = Some(audiences);
        self
    }

    /// Set the signing key PEM file path.
    pub fn with_signing_key_path(mut self, path: PathBuf) -> Self {
        self.signing_key_path = Some(path);
        self
    }

    /// Set the signing key PEM inline.
    pub fn with_signing_key_pem(mut self, pem: impl Into<String>) -> Self {
        self.signing_key_pem = Some(pem.into());
        self
    }

    /// Set the default TTL.
    pub fn with_default_ttl(mut self, secs: u64) -> Self {
        self.default_ttl_secs = secs;
        self
    }

    /// Set the maximum TTL.
    pub fn with_max_ttl(mut self, secs: u64) -> Self {
        self.max_ttl_secs = secs;
        self
    }

    /// Set whether rate limiting is enabled.
    pub fn with_rate_limit_enabled(mut self, enabled: bool) -> Self {
        self.rate_limit_enabled = enabled;
        self
    }

    /// Set the rate limit requests per minute.
    pub fn with_rate_limit_rpm(mut self, rpm: u32) -> Self {
        self.rate_limit_rpm = rpm;
        self
    }

    /// Set the rate limit burst size.
    pub fn with_rate_limit_burst(mut self, burst: u32) -> Self {
        self.rate_limit_burst = burst;
        self
    }

    /// Set the audience validation mode.
    pub fn with_audience_validation(mut self, mode: AudienceValidation) -> Self {
        self.audience_validation = mode;
        self
    }

    /// Set the admin token for key rotation.
    pub fn with_admin_token(mut self, token: impl Into<String>) -> Self {
        self.admin_token = Some(token.into());
        self
    }

    /// Enable CORS.
    pub fn with_cors(mut self, enable: bool) -> Self {
        self.enable_cors = enable;
        self
    }

    /// Set log level.
    pub fn with_log_level(mut self, level: impl Into<String>) -> Self {
        self.log_level = level.into();
        self
    }

    /// Set the maximum delegation depth for RFC 8693 token exchange.
    pub fn with_max_delegation_depth(mut self, depth: u32) -> Self {
        self.max_delegation_depth = depth;
        self
    }

    /// Set the workload policy JSON file path.
    #[cfg(feature = "oidc-policy")]
    pub fn with_workload_policy_path(mut self, path: PathBuf) -> Self {
        self.workload_policy_path = Some(path);
        self
    }

    /// Set the workload policy as an inline JSON string.
    #[cfg(feature = "oidc-policy")]
    pub fn with_workload_policy_json(mut self, json: impl Into<String>) -> Self {
        self.workload_policy_json = Some(json.into());
        self
    }

    /// Set the trust registry JSON file path.
    #[cfg(feature = "oidc-trust")]
    pub fn with_trust_registry_path(mut self, path: PathBuf) -> Self {
        self.trust_registry_path = Some(path);
        self
    }

    /// Set the GitHub OIDC issuer URL.
    #[cfg(feature = "github-oidc")]
    pub fn with_github_oidc_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.github_oidc_issuer = Some(issuer.into());
        self
    }

    /// Set the expected GitHub OIDC audience.
    #[cfg(feature = "github-oidc")]
    pub fn with_github_expected_audience(mut self, audience: impl Into<String>) -> Self {
        self.github_expected_audience = Some(audience.into());
        self
    }

    /// Set the GitHub JWKS cache TTL in seconds.
    #[cfg(feature = "github-oidc")]
    pub fn with_github_jwks_cache_ttl(mut self, secs: u64) -> Self {
        self.github_jwks_cache_ttl_secs = secs;
        self
    }
}
