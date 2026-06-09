//! OIDC attestation verification.
//!
//! Verifies an OIDC `id_token` (Okta/Entra) against the issuer key valid at
//! issuance time via the `auths-oidc-port` [`JwtValidator`], binds the token's
//! `nonce` to the expected challenge, and yields the typed [`AttestationContent`].
//! This is pure verification — no KEL writes — so it is testable with an in-memory
//! validator. The attestation's own (mandatory) expiry is injected, distinct from
//! the token's `exp`.

use auths_oidc_port::{JwtValidator, OidcValidationConfig};
use auths_verifier::IdentityDID;
use chrono::{DateTime, Duration, Utc};

use super::error::FederationError;
use super::types::{AttestationContent, IdpId, LifecycleClaim, Nonce};

/// What an OIDC token is being asked to attest.
#[derive(Debug, Clone)]
pub struct OidcAttestationRequest {
    /// The self-certifying subject the IdP attests about (it never owns this key).
    pub subject: IdentityDID,
    /// The typed lifecycle fact to attest.
    pub claim: LifecycleClaim,
    /// The challenge nonce the token must carry (anti-replay).
    pub expected_nonce: Nonce,
    /// Attestation validity window in seconds (`expires_at = now + ttl`).
    pub ttl_secs: i64,
}

/// Verify an OIDC `id_token` and build the attestation content.
///
/// The validator checks signature (issuance-time key), issuer, audience, and `exp`
/// against `now`. This function additionally binds the `nonce`, derives the attestor
/// from the verified `iss`, and validates the claimed fact against the token where a
/// mapping exists (group membership). It performs no KEL writes.
///
/// Args:
/// * `validator`: The OIDC JWT validator port.
/// * `config`: Issuer/audience/algorithm validation config.
/// * `token`: The raw `id_token`.
/// * `request`: Subject, claim, expected nonce, and attestation TTL.
/// * `now`: Current time (injected).
///
/// Usage:
/// ```ignore
/// let content = verify_oidc_attestation(&validator, &config, token, &request, now).await?;
/// ```
pub async fn verify_oidc_attestation(
    validator: &dyn JwtValidator,
    config: &OidcValidationConfig,
    token: &str,
    request: &OidcAttestationRequest,
    now: DateTime<Utc>,
) -> Result<AttestationContent, FederationError> {
    let claims = validator
        .validate(token, config, now)
        .await
        .map_err(|e| FederationError::TokenInvalid(e.to_string()))?;

    let token_nonce = claims
        .get("nonce")
        .and_then(|v| v.as_str())
        .ok_or(FederationError::NonceMissing)?;
    if token_nonce != request.expected_nonce.as_str() {
        return Err(FederationError::NonceMismatch);
    }

    let issuer = claims
        .get("iss")
        .and_then(|v| v.as_str())
        .ok_or(FederationError::IssuerMissing)?;
    let idp = IdpId::new(issuer)?;

    validate_claim_against_token(&request.claim, &claims)?;

    Ok(AttestationContent {
        subject: request.subject.clone(),
        idp,
        claim: request.claim.clone(),
        nonce: request.expected_nonce.clone(),
        expires_at: now + Duration::seconds(request.ttl_secs),
    })
}

/// Validate the typed claim against the token's claims where a mapping exists.
///
/// A `GroupMember(g)` attestation requires `g` to appear in the token's `groups`
/// array — the fact is not coerced, it is checked. Other variants are asserted by
/// the authenticated IdP and bound by the verified token + nonce.
fn validate_claim_against_token(
    claim: &LifecycleClaim,
    claims: &serde_json::Value,
) -> Result<(), FederationError> {
    if let LifecycleClaim::GroupMember(group) = claim {
        let present = claims
            .get("groups")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().any(|g| g.as_str() == Some(group.as_str())))
            .unwrap_or(false);
        if !present {
            return Err(FederationError::ClaimNotInToken(format!(
                "group '{}' not present in token 'groups'",
                group.as_str()
            )));
        }
    }
    Ok(())
}
