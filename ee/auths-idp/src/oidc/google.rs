//! Google Workspace OIDC verifier.
//!
//! Standard OIDC discovery with numeric `sub` (globally unique).
//! Validates `hd` (hosted domain) claim for org membership verification.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, Validation, decode};

use crate::error::IdpError;
use crate::jwks::OidcJwksClient;
use crate::oidc::{IdpVerifier, validate_standard_claims};
use crate::types::{IdpProtocol, VerifiedIdpIdentity};

/// Google-specific claims extending standard OIDC.
#[derive(Debug, Clone, serde::Deserialize)]
struct GoogleClaims {
    iss: String,
    sub: String,
    aud: serde_json::Value,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    email_verified: Option<bool>,
    #[serde(default)]
    auth_time: Option<i64>,
    #[serde(default)]
    acr: Option<String>,
    /// Hosted domain — present for Google Workspace accounts.
    #[serde(default)]
    hd: Option<String>,
    pub iat: i64,
    pub exp: i64,
}

/// Google Workspace OIDC identity provider verifier.
///
/// Args:
/// * `issuer`: The Google issuer URL (typically "https://accounts.google.com").
/// * `audience`: The expected OAuth client ID.
/// * `jwks_client`: The JWKS client for key fetching.
/// * `required_domain`: If set, rejects tokens without a matching `hd` claim.
///
/// Usage:
/// ```ignore
/// let verifier = GoogleIdpVerifier::new(
///     "https://accounts.google.com",
///     "client-id.apps.googleusercontent.com",
///     OidcJwksClient::with_defaults("https://accounts.google.com", "client-id"),
/// ).with_required_domain("company.com");
/// let identity = verifier.verify(jwt_bytes, Utc::now()).await?;
/// ```
pub struct GoogleIdpVerifier {
    issuer: String,
    audience: String,
    jwks_client: OidcJwksClient,
    required_domain: Option<String>,
}

impl GoogleIdpVerifier {
    /// Creates a new Google Workspace verifier.
    ///
    /// Args:
    /// * `issuer`: The Google issuer URL.
    /// * `audience`: The expected OAuth client ID.
    /// * `jwks_client`: JWKS client for key fetching.
    pub fn new(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        jwks_client: OidcJwksClient,
    ) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            jwks_client,
            required_domain: None,
        }
    }

    /// Restricts verification to a specific Google Workspace domain.
    ///
    /// Args:
    /// * `domain`: The required hosted domain (e.g., "company.com").
    pub fn with_required_domain(mut self, domain: impl Into<String>) -> Self {
        self.required_domain = Some(domain.into());
        self
    }
}

#[async_trait]
impl IdpVerifier for GoogleIdpVerifier {
    async fn verify(
        &self,
        credential: &[u8],
        now: DateTime<Utc>,
    ) -> Result<VerifiedIdpIdentity, IdpError> {
        let token = std::str::from_utf8(credential)
            .map_err(|_| IdpError::TokenInvalid("credential is not valid UTF-8".to_string()))?;

        let key = self.jwks_client.get_key_for_token(token).await?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = false;
        validation.validate_aud = false;
        validation.set_required_spec_claims(&["exp", "iss", "sub", "aud"]);

        let token_data = decode::<GoogleClaims>(token, &key, &validation)
            .map_err(|e| IdpError::TokenInvalid(format!("JWT decode failed: {e}")))?;

        let claims = token_data.claims;

        let standard = crate::oidc::StandardOidcClaims {
            iss: claims.iss.clone(),
            sub: claims.sub.clone(),
            aud: claims.aud.clone(),
            email: claims.email.clone(),
            auth_time: claims.auth_time,
            acr: claims.acr.clone(),
            iat: claims.iat,
            exp: claims.exp,
        };
        validate_standard_claims(&standard, &self.issuer, &self.audience, now)?;

        if let Some(required_domain) = &self.required_domain {
            match &claims.hd {
                Some(hd) if hd == required_domain => {}
                Some(hd) => {
                    return Err(IdpError::TokenInvalid(format!(
                        "hosted domain mismatch: expected '{required_domain}', got '{hd}'"
                    )));
                }
                None => {
                    return Err(IdpError::TokenInvalid(format!(
                        "missing 'hd' claim: token is not from a Google Workspace account (expected domain: '{required_domain}')"
                    )));
                }
            }
        }

        let auth_time = claims
            .auth_time
            .and_then(|ts| DateTime::from_timestamp(ts, 0))
            .unwrap_or(now);

        Ok(VerifiedIdpIdentity {
            idp_issuer: claims.iss,
            idp_protocol: IdpProtocol::Oidc,
            subject: claims.sub,
            subject_email: claims.email,
            auth_time,
            auth_context_class: claims.acr,
        })
    }

    fn provider_name(&self) -> &str {
        "google-workspace"
    }

    fn protocol(&self) -> IdpProtocol {
        IdpProtocol::Oidc
    }
}
