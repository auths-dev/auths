//! OIDC claim types embedded in Auths-issued JWTs.

use serde::{Deserialize, Serialize};

/// RFC 8693 actor claim — identifies the acting party in a delegation chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorClaim {
    /// The DID of the acting agent.
    pub sub: String,
    /// Signer type of the actor (auths-specific extension).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_type: Option<String>,
    /// Nested actor claim for multi-hop delegation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub act: Option<Box<ActorClaim>>,
}

/// OIDC claims embedded in Auths-issued JWTs.
///
/// Usage:
/// ```ignore
/// let claims: OidcClaims = serde_json::from_str(&payload)?;
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcClaims {
    /// Issuer URL.
    pub iss: String,
    /// Subject (KERI DID from the attestation chain root).
    pub sub: String,
    /// Audience.
    pub aud: String,
    /// Expiration time (Unix timestamp).
    pub exp: u64,
    /// Issued-at time (Unix timestamp).
    pub iat: u64,
    /// JWT ID (unique per token).
    pub jti: String,
    /// KERI prefix of the root identity.
    pub keri_prefix: String,
    /// Detected target cloud provider (e.g. "aws", "gcp", "azure").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_provider: Option<String>,
    /// Capabilities granted by the attestation chain.
    pub capabilities: Vec<String>,
    /// Witness quorum info (if witnesses were used).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness_quorum: Option<WitnessQuorumClaim>,
    /// GitHub actor (populated when GitHub OIDC cross-reference succeeds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_actor: Option<String>,
    /// GitHub repository (populated when GitHub OIDC cross-reference succeeds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_repository: Option<String>,
    /// RFC 8693 actor claim — present when attestation chain depth > 0.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub act: Option<ActorClaim>,
    /// SPIFFE ID from verified X.509-SVID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spiffe_id: Option<String>,
    /// IdP binding data (populated when identity has an enterprise IdP binding).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idp_binding: Option<IdpBindingClaim>,
}

/// IdP binding claim embedded in the JWT when an identity is bound to an enterprise IdP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdpBindingClaim {
    /// IdP issuer URL (e.g. "https://company.okta.com") or SAML entity ID.
    pub idp_issuer: String,
    /// IdP protocol used for the binding.
    pub idp_protocol: String,
    /// IdP-side subject identifier (oid@tid for Entra, sub for others).
    pub subject: String,
    /// Subject email for display/audit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_email: Option<String>,
    /// When the IdP authentication occurred (Unix timestamp).
    pub auth_time: u64,
    /// Authentication context class reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_context_class: Option<String>,
}

/// Witness quorum info embedded in the JWT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessQuorumClaim {
    /// Number of witness receipts required.
    pub required: usize,
    /// Number of witness receipts verified.
    pub verified: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_base_claims() -> OidcClaims {
        OidcClaims {
            iss: "https://auth.example.com".into(),
            sub: "did:keri:ETest".into(),
            aud: "api.example.com".into(),
            exp: 1700000000,
            iat: 1699999000,
            jti: "test-jti".into(),
            keri_prefix: "ETest".into(),
            target_provider: None,
            capabilities: vec!["sign-commit".into()],
            witness_quorum: None,
            github_actor: None,
            github_repository: None,
            act: None,
            spiffe_id: None,
            idp_binding: None,
        }
    }

    #[test]
    fn claims_without_idp_binding_omits_field() {
        let claims = make_base_claims();
        let json = serde_json::to_string(&claims).unwrap();
        assert!(!json.contains("idp_binding"));
    }

    #[test]
    fn claims_without_idp_binding_deserializes_to_none() {
        let json = r#"{
            "iss": "https://auth.example.com",
            "sub": "did:keri:ETest",
            "aud": "api.example.com",
            "exp": 1700000000,
            "iat": 1699999000,
            "jti": "test-jti",
            "keri_prefix": "ETest",
            "capabilities": ["sign-commit"]
        }"#;
        let claims: OidcClaims = serde_json::from_str(json).unwrap();
        assert!(claims.idp_binding.is_none());
    }

    #[test]
    fn claims_with_idp_binding_roundtrips() {
        let mut claims = make_base_claims();
        claims.idp_binding = Some(IdpBindingClaim {
            idp_issuer: "https://company.okta.com".into(),
            idp_protocol: "oidc".into(),
            subject: "alice@company.com".into(),
            subject_email: Some("alice@company.com".into()),
            auth_time: 1699998000,
            auth_context_class: Some(
                "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport".into(),
            ),
        });

        let json = serde_json::to_string(&claims).unwrap();
        assert!(json.contains("idp_binding"));
        assert!(json.contains("company.okta.com"));

        let parsed: OidcClaims = serde_json::from_str(&json).unwrap();
        let binding = parsed.idp_binding.unwrap();
        assert_eq!(binding.idp_issuer, "https://company.okta.com");
        assert_eq!(binding.idp_protocol, "oidc");
        assert_eq!(binding.subject, "alice@company.com");
        assert_eq!(binding.subject_email.as_deref(), Some("alice@company.com"));
        assert_eq!(binding.auth_time, 1699998000);
    }

    #[test]
    fn idp_binding_claim_optional_fields_skipped() {
        let binding = IdpBindingClaim {
            idp_issuer: "https://company.okta.com".into(),
            idp_protocol: "oidc".into(),
            subject: "alice".into(),
            subject_email: None,
            auth_time: 1699998000,
            auth_context_class: None,
        };
        let json = serde_json::to_string(&binding).unwrap();
        assert!(!json.contains("subject_email"));
        assert!(!json.contains("auth_context_class"));
    }
}

/// OIDC claims from CI/CD platform (GitHub Actions, GitLab CI, CircleCI).
///
/// # Usage
///
/// ```ignore
/// let workload_claims = WorkloadClaims {
///     issuer: "https://token.actions.githubusercontent.com".to_string(),
///     sub: "repo:owner/repo:ref:refs/heads/main".to_string(),
///     aud: "sigstore".to_string(),
///     jti: "unique-id-123".to_string(),
///     exp: 1699998000,
///     iat: 1699997400,
///     nbf: Some(1699997400),
///     actor: Some("alice".to_string()),
///     repository: Some("owner/repo".to_string()),
///     workflow: Some("publish".to_string()),
///     ci_config_ref: None,
///     run_id: Some("run-123".to_string()),
///     raw_claims: serde_json::json!({}),
/// };
/// ```
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WorkloadClaims {
    /// OIDC issuer (e.g., https://token.actions.githubusercontent.com for GitHub)
    pub issuer: String,
    /// Subject claim (platform-specific, e.g., repo:owner/repo:ref:... for GitHub)
    pub sub: String,
    /// Audience claim (CI platform specific)
    pub aud: String,
    /// JWT ID for replay detection
    pub jti: String,
    /// Expiration time (Unix timestamp)
    pub exp: i64,
    /// Issued-at time (Unix timestamp)
    pub iat: i64,
    /// Not-before time (Unix timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    /// Actor (user/service that triggered the job)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// Repository name (for GitHub/GitLab)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    /// Workflow name (for GitHub Actions)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow: Option<String>,
    /// CI config reference (for GitLab: ci_config_ref_uri)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ci_config_ref: Option<String>,
    /// Run/pipeline identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    /// Platform-specific claims (passed through)
    #[serde(flatten)]
    pub raw_claims: serde_json::Value,
}

/// OIDC validation configuration for CI/CD platforms.
///
/// # Usage
///
/// ```ignore
/// let config = PlatformOidcConfig::github()
///     .with_custom_issuer("https://custom-idp.example.com");
/// ```
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PlatformOidcConfig {
    /// Platform identifier (github, gitlab, circleci)
    pub platform: String,
    /// Expected JWT issuer
    pub issuer: String,
    /// Expected JWT audience
    pub audience: String,
    /// Allowed JWT algorithms
    pub allowed_algorithms: Vec<String>,
    /// Maximum clock skew tolerance (seconds)
    pub max_clock_skew: u64,
    /// JWKS cache TTL (seconds)
    pub jwks_cache_ttl: u64,
}

#[allow(dead_code)]
impl PlatformOidcConfig {
    /// Create a configuration for GitHub Actions OIDC.
    fn github() -> Self {
        Self {
            platform: "github".to_string(),
            issuer: "https://token.actions.githubusercontent.com".to_string(),
            audience: "sigstore".to_string(),
            allowed_algorithms: vec!["RS256".to_string()],
            max_clock_skew: 60,
            jwks_cache_ttl: 3600,
        }
    }

    /// Create a configuration for GitLab CI OIDC.
    fn gitlab() -> Self {
        Self {
            platform: "gitlab".to_string(),
            issuer: "https://gitlab.com".to_string(),
            audience: "sigstore".to_string(),
            allowed_algorithms: vec!["RS256".to_string(), "ES256".to_string()],
            max_clock_skew: 60,
            jwks_cache_ttl: 3600,
        }
    }

    /// Create a configuration for CircleCI OIDC.
    fn circleci() -> Self {
        Self {
            platform: "circleci".to_string(),
            issuer: "https://oidc.circleci.com/org".to_string(),
            audience: "sigstore".to_string(),
            allowed_algorithms: vec!["RS256".to_string()],
            max_clock_skew: 60,
            jwks_cache_ttl: 3600,
        }
    }

    /// Set a custom issuer URL.
    fn with_custom_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = issuer.into();
        self
    }

    /// Set a custom audience.
    fn with_custom_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = audience.into();
        self
    }

    /// Set custom allowed algorithms.
    fn with_allowed_algorithms(mut self, algorithms: Vec<String>) -> Self {
        self.allowed_algorithms = algorithms;
        self
    }

    /// Set maximum clock skew tolerance.
    fn with_max_clock_skew(mut self, seconds: u64) -> Self {
        self.max_clock_skew = seconds;
        self
    }

    /// Set JWKS cache TTL.
    fn with_jwks_cache_ttl(mut self, seconds: u64) -> Self {
        self.jwks_cache_ttl = seconds;
        self
    }
}

#[cfg(test)]
mod tests_workload_claims {
    use super::*;

    #[test]
    fn test_workload_claims_roundtrip() {
        let claims = WorkloadClaims {
            issuer: "https://token.actions.githubusercontent.com".to_string(),
            sub: "repo:owner/repo:ref:refs/heads/main".to_string(),
            aud: "sigstore".to_string(),
            jti: "unique-123".to_string(),
            exp: 1699998000,
            iat: 1699997400,
            nbf: Some(1699997400),
            actor: Some("alice".to_string()),
            repository: Some("owner/repo".to_string()),
            workflow: Some("publish".to_string()),
            ci_config_ref: None,
            run_id: Some("run-123".to_string()),
            raw_claims: serde_json::json!({"custom": "field"}),
        };

        let json = serde_json::to_string(&claims).unwrap();
        let parsed: WorkloadClaims = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.issuer, claims.issuer);
        assert_eq!(parsed.sub, claims.sub);
        assert_eq!(parsed.actor, claims.actor);
    }

    #[test]
    fn test_workload_claims_optional_fields() {
        let claims = WorkloadClaims {
            issuer: "https://token.actions.githubusercontent.com".to_string(),
            sub: "repo:owner/repo:ref:refs/heads/main".to_string(),
            aud: "sigstore".to_string(),
            jti: "unique-123".to_string(),
            exp: 1699998000,
            iat: 1699997400,
            nbf: None,
            actor: None,
            repository: None,
            workflow: None,
            ci_config_ref: None,
            run_id: None,
            raw_claims: serde_json::json!({}),
        };

        let json = serde_json::to_string(&claims).unwrap();
        assert!(!json.contains("nbf"));
        assert!(!json.contains("actor"));
        assert!(!json.contains("workflow"));
    }

    #[test]
    fn test_platform_config_github() {
        let config = PlatformOidcConfig::github();
        assert_eq!(config.platform, "github");
        assert_eq!(config.issuer, "https://token.actions.githubusercontent.com");
        assert_eq!(config.audience, "sigstore");
        assert!(config.allowed_algorithms.contains(&"RS256".to_string()));
    }

    #[test]
    fn test_platform_config_gitlab() {
        let config = PlatformOidcConfig::gitlab();
        assert_eq!(config.platform, "gitlab");
        assert!(config.allowed_algorithms.contains(&"RS256".to_string()));
        assert!(config.allowed_algorithms.contains(&"ES256".to_string()));
    }

    #[test]
    fn test_platform_config_circleci() {
        let config = PlatformOidcConfig::circleci();
        assert_eq!(config.platform, "circleci");
        assert_eq!(config.issuer, "https://oidc.circleci.com/org");
    }

    #[test]
    fn test_platform_config_builder() {
        let config = PlatformOidcConfig::github()
            .with_custom_issuer("https://custom.example.com")
            .with_custom_audience("my-app")
            .with_max_clock_skew(120)
            .with_jwks_cache_ttl(7200);

        assert_eq!(config.issuer, "https://custom.example.com");
        assert_eq!(config.audience, "my-app");
        assert_eq!(config.max_clock_skew, 120);
        assert_eq!(config.jwks_cache_ttl, 7200);
    }
}
