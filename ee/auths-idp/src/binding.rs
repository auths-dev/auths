//! IdP binding attestation type and binding workflow.
//!
//! Validates an IdP credential and constructs a canonicalized binding
//! attestation suitable for KEL anchoring via `anchor_data()`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::IdpError;
use crate::oidc::IdpVerifier;
use crate::types::IdpProtocol;

/// An attestation that a DID was authenticated by an enterprise IdP.
///
/// Stored as a canonicalized JSON blob referenced by SAID in the KEL.
/// No expiration — the binding records a fact ("this DID was authenticated
/// by $IdP at time T"). Freshness enforcement belongs to the policy layer.
///
/// Args:
/// * `version`: Schema version (currently 1).
/// * `idp_issuer`: The IdP's issuer URL or SAML entity ID.
/// * `idp_protocol`: Whether this binding came from OIDC or SAML.
/// * `subject`: The stable IdP subject identifier (oid@tid for Entra ID).
/// * `subject_email`: Email, if available (display/audit only).
/// * `auth_time`: When the user authenticated at the IdP.
/// * `auth_context_class`: ACR / AuthnContextClassRef.
/// * `bound_did`: The `did:keri:...` identity being linked.
/// * `timestamp`: When this binding attestation was created.
///
/// Usage:
/// ```ignore
/// let attestation = IdpBindingAttestation {
///     version: 1,
///     idp_issuer: "https://company.okta.com".into(),
///     idp_protocol: IdpProtocol::Oidc,
///     subject: "user-123".into(),
///     subject_email: Some("user@company.com".into()),
///     auth_time: Utc::now(),
///     auth_context_class: None,
///     bound_did: "did:keri:Eabc123".into(),
///     timestamp: Utc::now(),
/// };
/// let canonical = attestation.canonicalize()?;
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdpBindingAttestation {
    pub version: u8,
    pub idp_issuer: String,
    pub idp_protocol: IdpProtocol,
    pub subject: String,
    pub subject_email: Option<String>,
    pub auth_time: DateTime<Utc>,
    pub auth_context_class: Option<String>,
    pub bound_did: String,
    pub timestamp: DateTime<Utc>,
}

impl IdpBindingAttestation {
    /// Produces the canonicalized JSON representation (per RFC 8785 / json-canon).
    ///
    /// Usage:
    /// ```ignore
    /// let canonical_bytes = attestation.canonicalize()?;
    /// ```
    pub fn canonicalize(&self) -> Result<Vec<u8>, IdpError> {
        let value = serde_json::to_value(self)
            .map_err(|e| IdpError::ProviderConfig(format!("serialization failed: {e}")))?;
        json_canon::to_vec(&value)
            .map_err(|e| IdpError::ProviderConfig(format!("canonicalization failed: {e}")))
    }
}

/// Result of a successful IdP binding operation.
///
/// Contains the attestation and its canonical form, ready for KEL anchoring.
///
/// Args:
/// * `attestation`: The full binding attestation.
/// * `canonical_bytes`: The canonicalized JSON bytes (for signing / SAID computation).
///
/// Usage:
/// ```ignore
/// let result = bind_identity_to_idp(&verifier, credential, did, now).await?;
/// // Anchor result.canonical_bytes with SealType::IdpBinding
/// ```
#[derive(Debug, Clone)]
pub struct BindingResult {
    pub attestation: IdpBindingAttestation,
    pub canonical_bytes: Vec<u8>,
}

/// Validates an IdP credential and constructs a binding attestation.
///
/// This performs the verification and attestation construction. The caller
/// is responsible for anchoring the result in the KEL via `anchor_data()`
/// with `SealType::IdpBinding`.
///
/// Args:
/// * `verifier`: The IdP-specific verifier (Okta, Entra, Google, SAML).
/// * `credential`: Raw credential bytes (JWT for OIDC, XML for SAML).
/// * `bound_did`: The `did:keri:...` identity to bind.
/// * `now`: Current time (injected for testability).
///
/// Usage:
/// ```ignore
/// let result = bind_identity_to_idp(&okta_verifier, jwt_bytes, "did:keri:Eabc", now).await?;
/// let ixn_said = anchor_data(&identity, SealType::IdpBinding, &result.canonical_bytes)?;
/// ```
pub async fn bind_identity_to_idp(
    verifier: &dyn IdpVerifier,
    credential: &[u8],
    bound_did: &str,
    now: DateTime<Utc>,
) -> Result<BindingResult, IdpError> {
    let identity = verifier.verify(credential, now).await?;

    let attestation = IdpBindingAttestation {
        version: 1,
        idp_issuer: identity.idp_issuer,
        idp_protocol: identity.idp_protocol,
        subject: identity.subject,
        subject_email: identity.subject_email,
        auth_time: identity.auth_time,
        auth_context_class: identity.auth_context_class,
        bound_did: bound_did.to_string(),
        timestamp: now,
    };

    let canonical_bytes = attestation.canonicalize()?;

    Ok(BindingResult {
        attestation,
        canonical_bytes,
    })
}
