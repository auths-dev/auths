//! Core types for IdP verification.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Protocol used by the identity provider.
///
/// Args:
/// * `Oidc`: OpenID Connect (Okta, Entra ID, Google Workspace).
/// * `Saml2`: SAML 2.0 (generic enterprise IdPs).
///
/// Usage:
/// ```
/// use auths_idp::IdpProtocol;
/// let proto = IdpProtocol::Oidc;
/// assert_eq!(proto.as_str(), "oidc");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IdpProtocol {
    Oidc,
    Saml2,
}

impl IdpProtocol {
    /// Returns the protocol as a lowercase string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Oidc => "oidc",
            Self::Saml2 => "saml2",
        }
    }
}

/// Verified identity extracted from an IdP token or assertion.
///
/// Args:
/// * `idp_issuer`: The IdP's issuer URL or SAML entity ID.
/// * `idp_protocol`: Whether this came from OIDC or SAML.
/// * `subject`: The stable subject identifier (oid+tid for Entra ID, sub for others).
/// * `subject_email`: Email address, if available (for display/audit only).
/// * `auth_time`: When the user authenticated at the IdP.
/// * `auth_context_class`: The authentication context class reference (ACR/AuthnContextClassRef).
///
/// Usage:
/// ```ignore
/// let identity = verifier.verify(token, now).await?;
/// println!("Authenticated {} via {}", identity.subject, identity.idp_issuer);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedIdpIdentity {
    pub idp_issuer: String,
    pub idp_protocol: IdpProtocol,
    pub subject: String,
    pub subject_email: Option<String>,
    pub auth_time: DateTime<Utc>,
    pub auth_context_class: Option<String>,
}
