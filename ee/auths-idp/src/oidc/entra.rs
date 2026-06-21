//! Azure AD / Entra ID OIDC verifier.
//!
//! Entra ID uses pairwise `sub` claims — different per application.
//! This verifier uses `oid` (Object ID) + `tid` (Tenant ID) as the
//! compound subject identifier: `"{oid}@{tid}"`.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, Validation, decode};

use crate::error::IdpError;
use crate::jwks::OidcJwksClient;
use crate::oidc::{IdpVerifier, validate_standard_claims};
use crate::types::{IdpProtocol, VerifiedIdpIdentity};

/// Entra ID-specific claims extending standard OIDC.
#[derive(Debug, Clone, serde::Deserialize)]
struct EntraClaims {
    iss: String,
    sub: String,
    aud: serde_json::Value,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    preferred_username: Option<String>,
    #[serde(default)]
    auth_time: Option<i64>,
    #[serde(default)]
    acr: Option<String>,
    /// Object ID — stable, globally unique within the tenant.
    #[serde(default)]
    oid: Option<String>,
    /// Tenant ID — identifies the Azure AD tenant.
    #[serde(default)]
    tid: Option<String>,
    pub iat: i64,
    pub exp: i64,
}

/// Entra ID (Azure AD) OIDC identity provider verifier.
///
/// Args:
/// * `issuer`: The Entra ID issuer URL (e.g., "https://login.microsoftonline.com/{tenant}/v2.0").
/// * `audience`: The expected application (client) ID.
/// * `jwks_client`: The JWKS client for key fetching.
///
/// Usage:
/// ```ignore
/// let verifier = EntraIdpVerifier::new(
///     "https://login.microsoftonline.com/{tenant}/v2.0",
///     "app-client-id",
///     OidcJwksClient::with_defaults("https://login.microsoftonline.com/{tenant}/v2.0", "app-client-id"),
/// );
/// let identity = verifier.verify(jwt_bytes, Utc::now()).await?;
/// assert!(identity.subject.contains('@'));
/// ```
pub struct EntraIdpVerifier {
    issuer: String,
    audience: String,
    jwks_client: OidcJwksClient,
}

impl EntraIdpVerifier {
    /// Creates a new Entra ID verifier.
    ///
    /// Args:
    /// * `issuer`: The Entra ID issuer URL.
    /// * `audience`: The expected application (client) ID.
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
impl IdpVerifier for EntraIdpVerifier {
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

        let token_data = decode::<EntraClaims>(token, &key, &validation)
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

        // Entra ID: use oid@tid as compound subject (pairwise sub is app-specific)
        let subject = match (&claims.oid, &claims.tid) {
            (Some(oid), Some(tid)) => format!("{oid}@{tid}"),
            _ => claims.sub.clone(),
        };

        let subject_email = claims.email.or(claims.preferred_username);

        let auth_time = claims
            .auth_time
            .and_then(|ts| DateTime::from_timestamp(ts, 0))
            .unwrap_or(now);

        Ok(VerifiedIdpIdentity {
            idp_issuer: claims.iss,
            idp_protocol: IdpProtocol::Oidc,
            subject,
            subject_email,
            auth_time,
            auth_context_class: claims.acr,
        })
    }

    fn provider_name(&self) -> &str {
        "entra-id"
    }

    fn protocol(&self) -> IdpProtocol {
        IdpProtocol::Oidc
    }
}
