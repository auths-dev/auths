//! Relying-party presentation authentication (Epic D1 / fn-151.5).
//!
//! The full relying-party flow that turns an `Auths-Presentation` request into a verified,
//! scoped principal: parse the wire shape (`auths_rp`), consume the single-use challenge
//! (`auths_rp`), resolve the issuer + subject + delegator KELs (the F.4 + D1 loader), run the
//! pure `auths_verifier::verify_presentation`, and map the verdict to an `auths_rp::VerifiedPrincipal`.
//! The expected audience is the relying party's own configured identity (NOT the wire header),
//! and witness policy is `Warn` (first-party; revocation freshness is the registry-pull cadence).

use auths_core::storage::keychain::KeyAlias;
use auths_crypto::RingCryptoProvider;
use auths_rp::{
    Audience, ChallengeError, ChallengeStore, Denied, NONCE_LEN, Nonce, VerifiedPrincipal,
    WireError, WirePresentation,
};
use auths_verifier::{PresentationBinding, VerifierWitnessPolicy, verify_presentation};
use chrono::{DateTime, Utc};

use crate::context::AuthsContext;
use crate::domains::credentials::error::CredentialError;
use crate::domains::credentials::present_inputs::load_presentation_inputs;

/// Errors from [`authenticate_presentation`] (`thiserror`, exhaustive).
#[derive(Debug, thiserror::Error)]
pub enum PresentationAuthError {
    /// The `Auths-Presentation` wire shape was malformed.
    #[error("wire: {0}")]
    Wire(WireError),
    /// The presented nonce was not exactly 32 bytes.
    #[error("nonce must be 32 bytes")]
    NonceLength,
    /// No live single-use challenge matched (absent, replayed, or expired).
    #[error("challenge: {0}")]
    Challenge(ChallengeError),
    /// The issuer/subject KELs or the credential could not be resolved.
    #[error("resolve: {0}")]
    Resolve(CredentialError),
    /// The presentation verified-as-a-process but was not honored (see the inner reason).
    #[error("denied: {0}")]
    Denied(Denied),
}

impl PresentationAuthError {
    /// The HTTP status: 400 for a malformed request, 403 for insufficient capability, else 401.
    pub fn http_status(&self) -> u16 {
        match self {
            PresentationAuthError::Wire(_) | PresentationAuthError::NonceLength => 400,
            PresentationAuthError::Denied(denied) => denied.http_status(),
            PresentationAuthError::Challenge(_) | PresentationAuthError::Resolve(_) => 401,
        }
    }
}

/// Authenticate an `Auths-Presentation` request, yielding a verified, scoped principal.
///
/// Flow: parse the wire shape → consume the single-use challenge (the only place single-use is
/// enforced) → resolve issuer + subject + delegator KELs → `verify_presentation` against the
/// relying party's **configured** audience → map the verdict to a [`VerifiedPrincipal`]. The
/// nonce is consumed only after the cheap wire parse, so a third party cannot burn a legitimate
/// client's nonce with garbage. This is the interactive challenge path (the v1 default); a TTL
/// binding has no store entry to consume and is therefore rejected here.
///
/// Args:
/// * `ctx`: Auths context (registry for KEL/TEL/credential resolution).
/// * `issuer_alias`: The pinned issuer whose namespace holds the presented credential.
/// * `challenges`: The relying party's single-use challenge store.
/// * `config_audience`: The relying party's own audience — the trust source, not the wire header.
/// * `wire`: The `WirePresentation` parsed from the `Authorization` header.
/// * `now`: Verification time, injected at the boundary.
///
/// Usage:
/// ```ignore
/// let principal = authenticate_presentation(&ctx, &issuer, &store, &audience, wire, now).await?;
/// let grant = principal.authorize(&needed_capability)?;
/// ```
pub async fn authenticate_presentation(
    ctx: &AuthsContext,
    issuer_alias: &KeyAlias,
    challenges: &dyn ChallengeStore,
    config_audience: &Audience,
    wire: WirePresentation,
    now: DateTime<Utc>,
) -> Result<VerifiedPrincipal, PresentationAuthError> {
    let (envelope, presented_audience) = wire.parse().map_err(PresentationAuthError::Wire)?;

    let nonce = binding_nonce(&envelope.binding)?;
    let expected = challenges
        .consume(&presented_audience, &nonce, now)
        .map_err(PresentationAuthError::Challenge)?;

    let inputs = load_presentation_inputs(ctx, issuer_alias, &envelope.credential_said)
        .map_err(PresentationAuthError::Resolve)?;

    let verdict = verify_presentation(
        &envelope,
        &inputs.signed,
        &inputs.issuer_kel,
        &inputs.tel,
        &inputs.receipts,
        VerifierWitnessPolicy::Warn,
        &inputs.subject_kel,
        &inputs.subject_delegator_kel,
        config_audience.as_str(),
        Some(expected.as_bytes()),
        now,
        &RingCryptoProvider,
    )
    .await;

    VerifiedPrincipal::from_verdict(verdict).map_err(PresentationAuthError::Denied)
}

/// Extract the 32-byte nonce from a presentation binding.
fn binding_nonce(binding: &PresentationBinding) -> Result<Nonce, PresentationAuthError> {
    let bytes = match binding {
        PresentationBinding::Challenge { nonce } => nonce.as_slice(),
        PresentationBinding::Ttl { nonce, .. } => nonce.as_slice(),
    };
    let arr: [u8; NONCE_LEN] = bytes
        .try_into()
        .map_err(|_| PresentationAuthError::NonceLength)?;
    Ok(Nonce::from_bytes(arr))
}
