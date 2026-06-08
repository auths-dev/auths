//! SAML 2.0 attestor parity for Active Directory / legacy enterprise IdPs.
//!
//! Normalizes a verified SAML assertion onto the **same** typed [`AttestationContent`]
//! and closed [`LifecycleClaim`] enum as the OIDC path — one attestation type, two
//! protocols — so a SAML fact rides the identical KEL-anchoring + policy-signal
//! pipeline with no new path to authority.
//!
//! XML-DSig canonicalization is notoriously fiddly, so the cryptographic signature
//! check lives behind the [`SamlAssertionVerifier`] port (production wraps a SAML
//! library; the in-band semantic verification — audience, the `NotBefore` /
//! `NotOnOrAfter` window, attribute→claim mapping — is implemented here and tested
//! with a verifier double).

use std::collections::BTreeMap;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};

use super::error::FederationError;
use super::types::{AttestationContent, IdpId, LifecycleClaim, Nonce};

/// A verified SAML assertion's semantic content (signature already checked).
#[derive(Debug, Clone)]
pub struct SamlAssertion {
    /// The IdP entity id (`Issuer`) — the attestor.
    pub issuer: String,
    /// The `Subject`/`NameID` value at the IdP.
    pub name_id: String,
    /// The `AudienceRestriction` audiences.
    pub audiences: Vec<String>,
    /// `Conditions/@NotBefore`.
    pub not_before: Option<DateTime<Utc>>,
    /// `Conditions/@NotOnOrAfter`.
    pub not_on_or_after: Option<DateTime<Utc>>,
    /// The assertion `ID` — the one-time anti-replay token (maps to the nonce).
    pub assertion_id: String,
    /// `AttributeStatement` attributes (name → values).
    pub attributes: BTreeMap<String, Vec<String>>,
}

/// Verifies a SAML response's XML signature against the IdP's assertion-time cert
/// and parses it into a [`SamlAssertion`].
///
/// This is the c14n/XML-DSig boundary. The production implementation wraps a SAML
/// library; tests use a double. Mirrors the OIDC `JwtValidator` port.
#[async_trait]
pub trait SamlAssertionVerifier: Send + Sync {
    /// Verify the XML signature (assertion-time cert) and return the assertion.
    ///
    /// Args:
    /// * `response_xml`: The raw SAML response bytes.
    /// * `now`: Current time (injected) for any signature-time checks.
    ///
    /// Usage:
    /// ```ignore
    /// let assertion = verifier.verify(xml, now).await?;
    /// ```
    async fn verify(
        &self,
        response_xml: &[u8],
        now: DateTime<Utc>,
    ) -> Result<SamlAssertion, FederationError>;
}

/// What a SAML assertion is asked to attest (the SAML analogue of the OIDC request).
#[derive(Debug, Clone)]
pub struct SamlAttestationRequest {
    /// The self-certifying subject the IdP attests about (it never owns this key).
    pub subject: auths_verifier::IdentityDID,
    /// The typed lifecycle fact to attest.
    pub claim: LifecycleClaim,
    /// The audience the assertion's `AudienceRestriction` must contain.
    pub expected_audience: String,
    /// Attestation validity window in seconds (`expires_at = now + ttl`).
    pub ttl_secs: i64,
}

/// Attribute names AD / SAML IdPs commonly use to carry group membership.
const GROUP_ATTRIBUTE_NAMES: &[&str] = &[
    "groups",
    "memberOf",
    "http://schemas.xmlsoap.org/claims/Group",
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
];

/// Verify a SAML assertion and build the attestation content.
///
/// Checks the audience restriction and the `NotBefore`/`NotOnOrAfter` window, maps
/// the claimed fact onto the typed [`LifecycleClaim`] (group membership is checked
/// against the assertion's group attributes — never coerced from a string), and
/// yields the **same** [`AttestationContent`] the OIDC path produces. The XML
/// signature is verified by `verifier`.
///
/// Args:
/// * `verifier`: The SAML signature/parse port.
/// * `response_xml`: The raw SAML response.
/// * `request`: Subject, claim, expected audience, and attestation TTL.
/// * `now`: Current time (injected).
///
/// Usage:
/// ```ignore
/// let content = verify_saml_attestation(&verifier, xml, &request, now).await?;
/// ```
pub async fn verify_saml_attestation(
    verifier: &dyn SamlAssertionVerifier,
    response_xml: &[u8],
    request: &SamlAttestationRequest,
    now: DateTime<Utc>,
) -> Result<AttestationContent, FederationError> {
    let assertion = verifier.verify(response_xml, now).await?;

    if !assertion
        .audiences
        .iter()
        .any(|a| a == &request.expected_audience)
    {
        return Err(FederationError::ClaimNotInToken(format!(
            "audience '{}' not in assertion AudienceRestriction",
            request.expected_audience
        )));
    }

    if let Some(not_before) = assertion.not_before
        && now < not_before
    {
        return Err(FederationError::TokenInvalid(
            "SAML assertion is not yet valid (NotBefore)".to_string(),
        ));
    }
    if let Some(not_on_or_after) = assertion.not_on_or_after
        && now >= not_on_or_after
    {
        return Err(FederationError::TokenInvalid(
            "SAML assertion has expired (NotOnOrAfter)".to_string(),
        ));
    }

    validate_saml_claim(&request.claim, &assertion)?;

    let idp = IdpId::new(&assertion.issuer)?;
    let nonce = Nonce::new(&assertion.assertion_id)?;

    Ok(AttestationContent {
        subject: request.subject.clone(),
        idp,
        claim: request.claim.clone(),
        nonce,
        expires_at: now + Duration::seconds(request.ttl_secs),
    })
}

/// Verify a SAML assertion and anchor the attestation into the subject's KEL.
///
/// Args:
/// * `ctx`: Auths context.
/// * `verifier` / `response_xml`: SAML verification inputs.
/// * `request`: Subject, claim, expected audience, and attestation TTL.
/// * `subject_alias`: Keychain alias of the subject's signing key (anchors the `ixn`).
/// * `now`: Current time (injected).
///
/// Usage:
/// ```ignore
/// let attestation =
///     attest_saml(&ctx, &verifier, xml, &request, &subject_alias, now).await?;
/// ```
pub async fn attest_saml(
    ctx: &crate::context::AuthsContext,
    verifier: &dyn SamlAssertionVerifier,
    response_xml: &[u8],
    request: &SamlAttestationRequest,
    subject_alias: &auths_core::storage::keychain::KeyAlias,
    now: DateTime<Utc>,
) -> Result<super::types::IdpAttestation, FederationError> {
    let content = verify_saml_attestation(verifier, response_xml, request, now).await?;
    let subject_prefix = auths_id::keri::parse_did_keri(content.subject.as_str())
        .map_err(|e| FederationError::InvalidSubject(e.to_string()))?;
    super::anchor::anchor_attestation(ctx, &subject_prefix, subject_alias, &content, now)
}

/// Validate the typed claim against the assertion's attributes.
///
/// A `GroupMember(g)` claim requires `g` to appear in one of the assertion's
/// recognized group attributes — unknown attributes are not coerced into a string
/// claim (impossible: the claim enum is closed), and a group not present is rejected.
fn validate_saml_claim(
    claim: &LifecycleClaim,
    assertion: &SamlAssertion,
) -> Result<(), FederationError> {
    if let LifecycleClaim::GroupMember(group) = claim {
        let present = GROUP_ATTRIBUTE_NAMES.iter().any(|name| {
            assertion
                .attributes
                .get(*name)
                .is_some_and(|values| values.iter().any(|v| v == group.as_str()))
        });
        if !present {
            return Err(FederationError::ClaimNotInToken(format!(
                "group '{}' not present in the SAML assertion's group attributes",
                group.as_str()
            )));
        }
    }
    Ok(())
}
