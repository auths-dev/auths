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
use auths_verifier::{
    PresentationBinding, PresentationVerdict, VerifierWitnessPolicy, verify_presentation,
};
use chrono::{DateTime, Utc};

use auths_id::keri::types::Prefix;
use auths_id::policy::context_from_credential;

use crate::context::AuthsContext;
use crate::domains::credentials::error::CredentialError;
use crate::domains::credentials::present_inputs::load_presentation_inputs;
use crate::domains::org::error::OrgError;
use crate::domains::org::policy::{evaluate_with_org_policy, load_org_policy};

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
    /// The presentation verified and the holder is authenticated, but the issuer's org
    /// policy denied the principal (403, not 401 — authentication succeeded).
    #[error("org policy denied: {reason}")]
    PolicyDenied {
        /// The typed denial reason from the policy engine.
        reason: String,
    },
    /// The issuer's org policy could not be loaded or evaluated — fail closed (treated
    /// as a denial; the principal is not authorized when policy cannot be confirmed).
    #[error("org policy could not be evaluated: {0}")]
    Policy(OrgError),
}

impl PresentationAuthError {
    /// The HTTP status: 400 for a malformed request, 403 for insufficient capability or a
    /// policy denial, else 401.
    pub fn http_status(&self) -> u16 {
        match self {
            PresentationAuthError::Wire(_) | PresentationAuthError::NonceLength => 400,
            PresentationAuthError::Denied(denied) => denied.http_status(),
            PresentationAuthError::PolicyDenied { .. } | PresentationAuthError::Policy(_) => 403,
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
        // The presentation path now consumes freshness: the verdict is graded and the gate is
        // `is_trusted`. The independent fresher-issuer-tip source that makes a behind-slice fail
        // closed is resolved by the revocation-freshness refresh layer; until that is threaded
        // here, no fresher tip is supplied, so an offline-resolved slice grades Unknown and the
        // default policy tolerates it.
        &auths_verifier::freshness::FreshnessPolicy::default(),
        None,
        &RingCryptoProvider,
    )
    .await;

    enforce_issuer_policy(ctx, &verdict, now)?;

    VerifiedPrincipal::from_verdict(verdict).map_err(PresentationAuthError::Denied)
}

/// Enforce the issuer's org policy against a holder-verified presentation (E1 A4).
///
/// A no-op unless the verdict is `Valid` AND the issuer anchored an org policy. The
/// caps/role context comes from the holder-verified credential
/// ([`context_from_credential`]). A policy deny is a 403 ([`PresentationAuthError::PolicyDenied`])
/// — distinct from the 401 authentication failures — and a policy that cannot be
/// evaluated fails closed ([`PresentationAuthError::Policy`]). An issuer with no policy
/// leaves authentication unchanged (legacy allow).
fn enforce_issuer_policy(
    ctx: &AuthsContext,
    verdict: &PresentationVerdict,
    now: DateTime<Utc>,
) -> Result<(), PresentationAuthError> {
    let PresentationVerdict::Valid {
        issuer, subject, ..
    } = verdict
    else {
        return Ok(()); // non-Valid verdicts are handled by `from_verdict` (401).
    };
    let issuer_prefix = Prefix::new_unchecked(
        issuer
            .as_str()
            .strip_prefix("did:keri:")
            .unwrap_or(issuer.as_str())
            .to_string(),
    );

    let Some(policy) =
        load_org_policy(ctx, &issuer_prefix).map_err(PresentationAuthError::Policy)?
    else {
        return Ok(()); // issuer anchored no policy → legacy allow.
    };

    let eval_ctx = context_from_credential(verdict, now)
        .map_err(|e| PresentationAuthError::Policy(OrgError::InvalidDid(e.to_string())))?;
    let decision = evaluate_with_org_policy(&policy, &eval_ctx);
    // A5: record every enforcement decision (allow + deny). Gate stays pure.
    crate::audit::emit_policy_decision(ctx, "request", subject.as_str(), &decision);
    if decision.is_allowed() {
        Ok(())
    } else {
        Err(PresentationAuthError::PolicyDenied {
            reason: format!("{} [{}]", decision.message, decision.reason),
        })
    }
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
