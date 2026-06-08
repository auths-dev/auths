//! KEL anchoring for IdP attestations.
//!
//! The subject anchors the verified [`AttestationContent`] into **its own** KEL with
//! **its own** key (an `ixn` carrying the content's digest seal). The IdP signs
//! nothing here — it remains an attestor, never a root. [`attest_oidc`] is the
//! end-to-end entry point (verify the OIDC token, then anchor); [`anchor_attestation`]
//! is the protocol-agnostic anchor step reused by the SAML path.

use std::sync::Arc;

use auths_core::signing::StorageSigner;
use auths_core::storage::keychain::KeyAlias;
use auths_id::keri::parse_did_keri;
use auths_id::keri::types::Prefix;
use auths_oidc_port::{JwtValidator, OidcValidationConfig};
use chrono::{DateTime, Utc};

use super::error::FederationError;
use super::oidc::{OidcAttestationRequest, verify_oidc_attestation};
use super::types::{AttestationContent, IdpAttestation};
use crate::context::AuthsContext;

/// Anchor verified attestation content into the subject's KEL.
///
/// Anchors the content's canonical digest as a seal in an `ixn` authored by the
/// subject (`subject_alias`), and returns the full [`IdpAttestation`] tagged with
/// the resulting KEL sequence. The digest covers only the content — never the
/// `anchored_at_seq`, which is the anchor's result.
///
/// Args:
/// * `ctx`: Auths context (registry + keychain + clock).
/// * `subject_prefix`: The subject's KEL prefix.
/// * `subject_alias`: Keychain alias of the subject's signing key.
/// * `content`: The verified attestation content.
/// * `now`: Current time (injected).
///
/// Usage:
/// ```ignore
/// let attestation = anchor_attestation(&ctx, &subject_prefix, &subject_alias, &content, now)?;
/// ```
pub fn anchor_attestation(
    ctx: &AuthsContext,
    subject_prefix: &Prefix,
    subject_alias: &KeyAlias,
    content: &AttestationContent,
    now: DateTime<Utc>,
) -> Result<IdpAttestation, FederationError> {
    let storage_signer = StorageSigner::new(Arc::clone(&ctx.key_storage));
    let mut batch = auths_id::storage::registry::backend::AtomicWriteBatch::new();
    let (_said, ixn) = auths_id::keri::anchor_and_persist_via_backend(
        ctx.registry.as_ref(),
        &storage_signer,
        subject_alias,
        ctx.passphrase_provider.as_ref(),
        subject_prefix,
        content,
        &mut batch,
        &ctx.witness_params(),
        now,
    )
    .map_err(|e| FederationError::AnchorFailed(e.to_string()))?;

    Ok(IdpAttestation {
        content: content.clone(),
        anchored_at_seq: ixn.s.value(),
    })
}

/// Verify an OIDC token and anchor the resulting attestation into the subject's KEL.
///
/// Args:
/// * `ctx`: Auths context.
/// * `validator` / `config` / `token`: OIDC verification inputs.
/// * `request`: Subject, claim, expected nonce, and attestation TTL.
/// * `subject_alias`: Keychain alias of the subject's signing key (anchors the `ixn`).
/// * `now`: Current time (injected).
///
/// Usage:
/// ```ignore
/// let attestation =
///     attest_oidc(&ctx, &validator, &config, token, &request, &subject_alias, now).await?;
/// ```
#[allow(clippy::too_many_arguments)]
pub async fn attest_oidc(
    ctx: &AuthsContext,
    validator: &dyn JwtValidator,
    config: &OidcValidationConfig,
    token: &str,
    request: &OidcAttestationRequest,
    subject_alias: &KeyAlias,
    now: DateTime<Utc>,
) -> Result<IdpAttestation, FederationError> {
    let content = verify_oidc_attestation(validator, config, token, request, now).await?;
    let subject_prefix = parse_did_keri(content.subject.as_str())
        .map_err(|e| FederationError::InvalidSubject(e.to_string()))?;
    anchor_attestation(ctx, &subject_prefix, subject_alias, &content, now)
}
