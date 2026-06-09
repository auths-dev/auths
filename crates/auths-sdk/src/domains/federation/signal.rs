//! Federation signals feed policy as **evidence**, never as authority.
//!
//! An [`IdpAttestation`] projects to a [`FederationSignal`] that the policy engine
//! reads through [`evaluate_idp_signals`]. The honest, load-bearing asymmetry: a
//! negative lifecycle signal (suspended/terminated) can **deny**, but a positive
//! one can never **allow** — an IdP attestation is input to a predicate, not a
//! promotable authority. There is no path from a signal to a `Grant`.

use auths_policy::decision::{Decision, ReasonCode};
use auths_verifier::IdentityDID;
use chrono::{DateTime, Utc};

use super::types::{IdpAttestation, IdpId, LifecycleClaim};

/// The policy-facing projection of an attestation at a point in time.
#[derive(Debug, Clone, PartialEq)]
pub struct FederationSignal {
    /// The subject the IdP attests about.
    pub subject: IdentityDID,
    /// The attestor IdP.
    pub idp: IdpId,
    /// The typed lifecycle fact.
    pub claim: LifecycleClaim,
    /// Whether the attestation is unexpired at evaluation time.
    pub fresh: bool,
}

impl IdpAttestation {
    /// Project this attestation into a policy [`FederationSignal`] at `now`.
    ///
    /// Freshness is computed from the attestation's mandatory expiry; an expired
    /// attestation projects to a `fresh: false` signal that the predicate treats as
    /// "no signal", never as a still-valid grant.
    ///
    /// Args:
    /// * `now`: Evaluation time (injected).
    ///
    /// Usage:
    /// ```ignore
    /// let signal = attestation.as_signal(clock.now());
    /// ```
    pub fn as_signal(&self, now: DateTime<Utc>) -> FederationSignal {
        FederationSignal {
            subject: self.content.subject.clone(),
            idp: self.content.idp.clone(),
            claim: self.content.claim.clone(),
            fresh: self.content.expires_at > now,
        }
    }
}

/// Evaluate IdP signals into a [`Decision`] — evidence in, decision out.
///
/// A fresh suspended/terminated signal denies (a legitimate de-assertion the IdP is
/// authoritative over). A fresh employed/group-member signal yields
/// `Indeterminate` — it is corroborating evidence a policy may consume, but it can
/// **never** by itself allow, because federation is a signal, not the root of
/// trust. The return type is a [`Decision`]; there is intentionally no overload
/// returning a `Grant` or `Capability`.
///
/// Args:
/// * `signals`: The projected IdP signals for a subject.
///
/// Usage:
/// ```ignore
/// let decision = evaluate_idp_signals(&[attestation.as_signal(now)]);
/// ```
pub fn evaluate_idp_signals(signals: &[FederationSignal]) -> Decision {
    if let Some(deny) = signals.iter().find(|s| {
        s.fresh
            && matches!(
                s.claim,
                LifecycleClaim::Suspended | LifecycleClaim::Terminated
            )
    }) {
        return Decision::deny(
            ReasonCode::Revoked,
            format!(
                "IdP '{}' attests subject '{}' is no longer active",
                deny.idp.as_str(),
                deny.subject.as_str()
            ),
        );
    }

    let has_active = signals.iter().any(|s| {
        s.fresh
            && matches!(
                s.claim,
                LifecycleClaim::Employed | LifecycleClaim::GroupMember(_)
            )
    });

    if has_active {
        Decision::indeterminate(
            ReasonCode::AttrMismatch,
            "IdP attests an active lifecycle signal; this is corroborating evidence, \
             not an authority grant",
        )
    } else {
        Decision::indeterminate(
            ReasonCode::MissingField,
            "no fresh IdP lifecycle signal for this subject",
        )
    }
}
