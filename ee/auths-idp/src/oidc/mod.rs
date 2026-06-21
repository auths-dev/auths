//! OIDC IdP verification — shared logic, trait, and provider implementations.

#[cfg(feature = "oidc")]
pub mod entra;
#[cfg(feature = "oidc")]
pub mod google;
#[cfg(feature = "oidc")]
pub mod okta;

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::error::IdpError;
use crate::types::{IdpProtocol, VerifiedIdpIdentity};

/// Trait for verifying enterprise IdP credentials.
///
/// Implementations handle provider-specific token validation (OIDC JWT
/// verification, SAML assertion parsing) and return a normalized
/// `VerifiedIdpIdentity`.
///
/// Args:
/// * `credential`: Raw credential bytes (JWT string for OIDC, XML for SAML).
/// * `now`: Current timestamp for expiry and freshness checks.
///
/// Usage:
/// ```ignore
/// let identity = verifier.verify(jwt_bytes, Utc::now()).await?;
/// println!("Verified: {} from {}", identity.subject, identity.idp_issuer);
/// ```
#[async_trait]
pub trait IdpVerifier: Send + Sync {
    /// Verifies a credential and returns the verified identity.
    ///
    /// Args:
    /// * `credential`: Raw credential bytes (JWT for OIDC, XML for SAML).
    /// * `now`: Current time for expiry validation (injected for testability).
    async fn verify(
        &self,
        credential: &[u8],
        now: DateTime<Utc>,
    ) -> Result<VerifiedIdpIdentity, IdpError>;

    /// Human-readable provider name (e.g., "okta", "entra-id", "google-workspace").
    fn provider_name(&self) -> &str;

    /// The protocol this verifier handles.
    fn protocol(&self) -> IdpProtocol;
}

/// Standard OIDC claims shared by all providers.
#[cfg(feature = "oidc")]
#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct StandardOidcClaims {
    pub iss: String,
    pub sub: String,
    pub aud: serde_json::Value,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub auth_time: Option<i64>,
    #[serde(default)]
    pub acr: Option<String>,
    #[allow(dead_code)]
    pub iat: i64,
    pub exp: i64,
}

/// Validates standard OIDC claims (issuer, audience, expiry).
///
/// Args:
/// * `claims`: The deserialized OIDC claims.
/// * `expected_issuer`: The expected issuer URL.
/// * `expected_audience`: The expected audience.
/// * `now`: Current time for expiry validation.
#[cfg(feature = "oidc")]
pub(crate) fn validate_standard_claims(
    claims: &StandardOidcClaims,
    expected_issuer: &str,
    expected_audience: &str,
    now: DateTime<Utc>,
) -> Result<(), IdpError> {
    if claims.iss != expected_issuer {
        return Err(IdpError::TokenInvalid(format!(
            "issuer mismatch: expected '{}', got '{}'",
            expected_issuer, claims.iss
        )));
    }

    let aud_matches = match &claims.aud {
        serde_json::Value::String(s) => s == expected_audience,
        serde_json::Value::Array(arr) => arr.iter().any(|v| v.as_str() == Some(expected_audience)),
        _ => false,
    };
    if !aud_matches {
        return Err(IdpError::TokenInvalid(format!(
            "audience mismatch: expected '{expected_audience}'"
        )));
    }

    let now_ts = now.timestamp();
    if claims.exp < now_ts {
        return Err(IdpError::TokenInvalid("token expired".to_string()));
    }

    Ok(())
}
