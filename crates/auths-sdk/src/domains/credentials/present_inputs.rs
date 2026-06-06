//! Presentation-inputs loader (Epic D1 / fn-151.3).
//!
//! `auths_verifier::verify_presentation` is pure: it reports facts about the exact
//! issuer/subject KELs, TEL, and receipts it is handed. This module resolves all of them
//! for a credential SAID — including the genuinely-new parts: the **subject KEL** (from
//! `acdc.a.i`) and the subject's **delegator KEL** (the delegated subject's anchoring
//! seals, recovered from its `dip`/`drt`). Issuer-side resolution reuses the F.4 resolvers
//! in [`super::verify`]; only subject + delegator resolution is new.

use auths_core::storage::keychain::KeyAlias;
use auths_id::keri::Event;
use auths_id::keri::types::Prefix;
use auths_keri::witness::StoredReceipt;
use auths_keri::{Said, TelEvent};

use crate::context::AuthsContext;
use crate::domains::credentials::error::CredentialError;
use crate::domains::credentials::stored::StoredCredential;
use crate::domains::credentials::verify::{
    ResolvedAsOf, collect_lifecycle_receipts, resolve_kel, resolve_tel, tip_as_of,
};

/// Everything `auths_verifier::verify_presentation` needs to honor a presentation of a
/// credential, resolved from the local registry.
///
/// Issuer KEL/TEL/receipts come from the F.4 resolution layer; the subject KEL and the
/// subject's delegator KEL (empty for a non-delegated subject) are resolved here.
#[derive(Debug, Clone)]
pub struct PresentationInputs {
    /// The credential body + the issuer's detached signature (the F.5 input).
    pub signed: auths_verifier::SignedAcdc,
    /// The issuer identity's KEL (oldest first).
    pub issuer_kel: Vec<Event>,
    /// The credential's TEL (`vcp`/`iss`/optional `rev`).
    pub tel: Vec<TelEvent>,
    /// Witness receipts for the issuer's lifecycle anchors.
    pub receipts: Vec<StoredReceipt>,
    /// The subject (holder) AID's KEL, replayed by the verifier to recover its current key.
    pub subject_kel: Vec<Event>,
    /// The subject's delegator KEL (anchoring seals), or empty for a non-delegated subject.
    pub subject_delegator_kel: Vec<Event>,
    /// The resolved issuer-KEL tip the inputs are as-of.
    pub as_of: ResolvedAsOf,
}

/// Resolve the presentation inputs for a credential held under `issuer_alias`.
///
/// Loads the stored credential blob for `credential_said`, resolves the issuer KEL/TEL +
/// lifecycle receipts (reusing the F.4 resolvers), then resolves the **subject KEL** from
/// `acdc.a.i` and — when the subject is a delegated identifier — its **delegator KEL** from
/// the subject `dip`'s `di`. The delegator KEL is empty for a non-delegated subject.
///
/// Args:
/// * `ctx`: Auths context (registry + repo path for receipt lookup).
/// * `issuer_alias`: Keychain alias of the issuer whose namespace holds the credential.
/// * `credential_said`: The SAID (`acdc.d`) of the credential being presented.
///
/// Usage:
/// ```ignore
/// let inputs = load_presentation_inputs(&ctx, &issuer_alias, "ECred…")?;
/// let verdict = auths_verifier::verify_presentation(
///     &envelope, &inputs.signed, &inputs.issuer_kel, &inputs.tel, &inputs.receipts,
///     VerifierWitnessPolicy::Warn, &inputs.subject_kel, &inputs.subject_delegator_kel,
///     audience, Some(&nonce), now, &provider,
/// ).await;
/// ```
pub fn load_presentation_inputs(
    ctx: &AuthsContext,
    issuer_alias: &KeyAlias,
    credential_said: &str,
) -> Result<PresentationInputs, CredentialError> {
    let issuer_prefix =
        crate::domains::credentials::issue::resolve_issuer_prefix(ctx, issuer_alias)?;

    let cred = Said::new_unchecked(credential_said.to_string());
    let blob = ctx
        .registry
        .load_credential(&issuer_prefix, &cred)
        .map_err(|e| CredentialError::StaleOrUnresolvable {
            reason: format!("credential blob read failed: {e}"),
        })?
        .ok_or_else(|| CredentialError::StaleOrUnresolvable {
            reason: format!("credential not found: {credential_said}"),
        })?;
    let stored =
        StoredCredential::from_bytes(&blob).map_err(|e| CredentialError::StaleOrUnresolvable {
            reason: format!("credential blob parse failed: {e}"),
        })?;

    let issuer_kel = resolve_kel(ctx, &issuer_prefix)?;
    let tel = resolve_tel(ctx, &issuer_prefix, &stored.acdc.ri, &stored.acdc.d)?;
    let receipts = collect_lifecycle_receipts(ctx, &issuer_prefix, &issuer_kel, &tel);
    let as_of = tip_as_of(&issuer_kel);

    // The genuinely-new resolution: the SUBJECT KEL (acdc.a.i) and its delegator KEL.
    let subject_prefix = Prefix::new_unchecked(stored.acdc.a.i.to_string());
    let subject_kel = resolve_kel(ctx, &subject_prefix)?;
    let subject_delegator_kel = match subject_delegator_prefix(&subject_kel) {
        Some(delegator) => resolve_kel(ctx, &delegator)?,
        None => Vec::new(),
    };

    let signed = auths_verifier::SignedAcdc {
        acdc: stored.acdc.clone(),
        signature: stored.signature.clone(),
    };

    Ok(PresentationInputs {
        signed,
        issuer_kel,
        tel,
        receipts,
        subject_kel,
        subject_delegator_kel,
        as_of,
    })
}

/// The delegator prefix of a delegated subject (from its `dip`/`drt`), or `None` when the
/// subject is a non-delegated root identity.
fn subject_delegator_prefix(subject_kel: &[Event]) -> Option<Prefix> {
    subject_kel
        .iter()
        .find_map(|event| event.delegator().cloned())
}
