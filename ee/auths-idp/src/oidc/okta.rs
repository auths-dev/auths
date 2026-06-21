//! Okta OIDC IdP verifier.
//!
//! Standard OIDC discovery, `sub` claim as stable subject identifier.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, Validation, decode};

use crate::error::IdpError;
use crate::jwks::OidcJwksClient;
use crate::oidc::{IdpVerifier, StandardOidcClaims, validate_standard_claims};
use crate::types::{IdpProtocol, VerifiedIdpIdentity};

/// Okta OIDC identity provider verifier.
///
/// Args:
/// * `issuer`: The Okta org URL (e.g., "https://company.okta.com").
/// * `audience`: The expected audience (client ID).
/// * `jwks_client`: The JWKS client for key fetching.
///
/// Usage:
/// ```ignore
/// let verifier = OktaIdpVerifier::new(
///     "https://company.okta.com",
///     "client-id",
///     OidcJwksClient::with_defaults("https://company.okta.com", "client-id"),
/// );
/// let identity = verifier.verify(jwt_bytes, Utc::now()).await?;
/// ```
pub struct OktaIdpVerifier {
    issuer: String,
    audience: String,
    jwks_client: OidcJwksClient,
}

impl OktaIdpVerifier {
    /// Creates a new Okta verifier.
    ///
    /// Args:
    /// * `issuer`: The Okta org URL.
    /// * `audience`: The expected client ID / audience.
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
        }
    }
}

#[async_trait]
impl IdpVerifier for OktaIdpVerifier {
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

        let token_data = decode::<StandardOidcClaims>(token, &key, &validation)
            .map_err(|e| IdpError::TokenInvalid(format!("JWT decode failed: {e}")))?;

        let claims = token_data.claims;
        validate_standard_claims(&claims, &self.issuer, &self.audience, now)?;

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
        "okta"
    }

    fn protocol(&self) -> IdpProtocol {
        IdpProtocol::Oidc
    }
}
