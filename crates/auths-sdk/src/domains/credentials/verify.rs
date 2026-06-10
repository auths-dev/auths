//! Credential verification — the resolution + freshness layer (Epic F.4).
//!
//! The pure verifier (F.5, [`auths_verifier::verify_credential`]) reports facts about
//! the exact KEL/TEL/receipts it is handed; it can neither resolve a KEL tip nor judge
//! staleness. This module owns both: it resolves the issuer KEL + the credential TEL,
//! collects the witness receipts for **every lifecycle anchor — the establishment
//! events AND the `vcp`/`iss`/`rev` anchoring `ixn`s — to the witnessed tip**, hands
//! them to the pure verifier, and then owns the freshness decision (fail-closed
//! [`CredentialVerdict::StaleOrUnresolvable`] when no fresh witnessed tip is reachable).
//!
//! ## The F.4 / F.5 split
//!
//! - **F.5 (pure):** quorum math, SAID/schema/signature/revocation checks → a verdict.
//! - **F.4 (here):** supply the receipts + judge freshness. F.4 never re-does the
//!   quorum math; it only refuses to ask F.5 when no fresh witnessed tip is reachable.

use std::ops::ControlFlow;

use auths_crypto::RingCryptoProvider;
use auths_id::keri::Event;
use auths_id::keri::credential_registry::{find_registry, read_credential_tel};
use auths_id::keri::types::Prefix;
use auths_id::storage::GitReceiptStorage;
use auths_id::storage::receipts::ReceiptStorage;
use auths_keri::witness::StoredReceipt;
use auths_keri::{Said, TelEvent};
use chrono::{DateTime, Utc};

pub use auths_verifier::VerifierWitnessPolicy;

use crate::context::AuthsContext;
use crate::domains::credentials::error::CredentialError;
use crate::domains::credentials::stored::StoredCredential;

/// The KEL position a verification verdict is as-of (the resolved witnessed tip).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAsOf {
    /// The tip sequence of the resolved issuer KEL.
    pub seq: u128,
    /// The SAID of the tip event.
    pub said: String,
}

/// The outcome of [`verify`], owning the freshness decision the pure verifier cannot make.
///
/// `Resolved` carries the pure verifier's verdict plus the resolved "as-of" position;
/// `StaleOrUnresolvable` is the SDK's fail-closed freshness verdict when no fresh
/// witnessed tip was reachable (the pure verifier is never asked to resolve).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialVerdict {
    /// The pure verifier (F.5) produced a verdict against the resolved witnessed tip.
    Resolved {
        /// The pure verifier's fact-reporting verdict.
        verdict: auths_verifier::CredentialVerdict,
        /// The resolved tip position the verdict is as-of.
        as_of: ResolvedAsOf,
    },
    /// No fresh-enough witnessed tip was reachable — fail-closed (F.4 owns this).
    StaleOrUnresolvable {
        /// The tip position that could not be confirmed witnessed.
        as_of: ResolvedAsOf,
        /// Why no fresh witnessed tip was reachable.
        reason: String,
    },
}

impl CredentialVerdict {
    /// Whether the credential verified (`Resolved` with a valid inner verdict).
    pub fn is_valid(&self) -> bool {
        matches!(
            self,
            CredentialVerdict::Resolved { verdict, .. } if verdict.is_valid()
        )
    }
}

/// Verify a stored credential, resolving the issuer KEL/TEL + lifecycle-anchor receipts.
///
/// The resolution + freshness layer: resolves the issuer KEL (from `acdc.i`) and the
/// credential's TEL, collects the witness receipts for **every lifecycle anchor — the
/// establishment events and the `vcp`/`iss`/`rev` anchoring `ixn`s — to the witnessed
/// tip**, hands them to the pure [`auths_verifier::verify_credential`], and owns the
/// freshness decision. Under [`VerifierWitnessPolicy::RequireWitnesses`], when the
/// issuer declares backers but no receipts are reachable for the lifecycle anchors,
/// no fresh witnessed tip exists and verification fails closed with
/// [`CredentialVerdict::StaleOrUnresolvable`] (the pure verifier is never asked).
///
/// Args:
/// * `ctx`: Auths context (registry + repo path for receipt lookup).
/// * `stored`: The credential body + the issuer's detached signature.
/// * `witness_policy`: `Warn` (TOFS) or `RequireWitnesses` (fail-closed).
/// * `now`: Verification time, injected at the boundary (the SDK passes `clock.now()`).
///
/// Usage:
/// ```ignore
/// let verdict = verify(&ctx, &stored, VerifierWitnessPolicy::RequireWitnesses, now).await?;
/// assert!(verdict.is_valid());
/// ```
pub async fn verify(
    ctx: &AuthsContext,
    stored: &StoredCredential,
    witness_policy: VerifierWitnessPolicy,
    now: DateTime<Utc>,
) -> Result<CredentialVerdict, CredentialError> {
    // The ACDC's `i` is already the issuer's bare KERI prefix (curve-tagged); no
    // `did:keri:` wrapper to parse.
    let issuer_prefix = Prefix::new_unchecked(stored.acdc.i.as_str().to_string());

    let issuer_kel = resolve_kel(ctx, &issuer_prefix)?;
    verify_with_issuer_kel(
        ctx,
        stored,
        &issuer_prefix,
        &issuer_kel,
        witness_policy,
        now,
    )
    .await
}

/// [`verify`] with a caller-resolved issuer KEL — no per-call KEL replay.
///
/// Batch consumers verifying many credentials from the same issuer should resolve
/// the issuer KEL once and call this per credential; [`verify`] re-resolves it on
/// every call.
///
/// Args:
/// * `ctx`: Auths context (registry + repo path for receipt lookup).
/// * `stored`: The credential body + the issuer's detached signature.
/// * `issuer_prefix`: The issuer's bare KERI prefix (must match `stored.acdc.i`).
/// * `issuer_kel`: The issuer's full KEL, oldest first.
/// * `witness_policy`: `Warn` (TOFS) or `RequireWitnesses` (fail-closed).
/// * `now`: Verification time, injected at the boundary.
///
/// Usage:
/// ```ignore
/// let kel = resolve_kel(&ctx, &issuer_prefix)?;
/// for stored in &credentials {
///     verify_with_issuer_kel(&ctx, stored, &issuer_prefix, &kel, policy, now).await?;
/// }
/// ```
pub async fn verify_with_issuer_kel(
    ctx: &AuthsContext,
    stored: &StoredCredential,
    issuer_prefix: &Prefix,
    issuer_kel: &[Event],
    witness_policy: VerifierWitnessPolicy,
    now: DateTime<Utc>,
) -> Result<CredentialVerdict, CredentialError> {
    if issuer_kel.is_empty() {
        return Err(CredentialError::StaleOrUnresolvable {
            reason: format!("issuer KEL not found: {issuer_prefix}"),
        });
    }

    let tel = resolve_tel(ctx, issuer_prefix, &stored.acdc.ri, &stored.acdc.d)?;

    let receipts = collect_lifecycle_receipts(ctx, issuer_prefix, issuer_kel, &tel);

    let as_of = tip_as_of(issuer_kel);

    // Freshness (F.4): under RequireWitnesses, if the issuer declares backers but the
    // witnessed tip is unreachable (no receipts at all for the lifecycle anchors),
    // there is no fresh witnessed tip — fail closed without asking the pure verifier.
    if let VerifierWitnessPolicy::RequireWitnesses = witness_policy
        && declares_backers(ctx, issuer_prefix)
        && receipts.is_empty()
    {
        return Ok(CredentialVerdict::StaleOrUnresolvable {
            as_of,
            reason:
                "issuer declares witnesses but no receipts were reachable for any lifecycle anchor"
                    .to_string(),
        });
    }

    let signed = auths_verifier::SignedAcdc {
        acdc: stored.acdc.clone(),
        signature: stored.signature.clone(),
    };
    let provider = RingCryptoProvider;
    let verdict = auths_verifier::verify_credential(
        &signed,
        issuer_kel,
        &tel,
        &receipts,
        witness_policy,
        now,
        &provider,
    )
    .await;

    Ok(CredentialVerdict::Resolved { verdict, as_of })
}

/// Verify a credential by its SAID, loading the stored envelope from the issuer.
///
/// The CLI-facing entry point: resolves the issuer's KEL prefix from its keychain
/// alias, loads the stored credential blob ([`StoredCredential`]) for `credential_said`,
/// and delegates to [`verify`]. The credential blob carries the issuer's signature, so
/// no separate signature input is needed.
///
/// Args:
/// * `ctx`: Auths context.
/// * `issuer_alias`: Keychain alias of the issuer whose namespace holds the credential.
/// * `credential_said`: The SAID of the credential to verify.
/// * `witness_policy`: `Warn` (TOFS) or `RequireWitnesses` (fail-closed).
/// * `now`: Verification time, injected at the boundary.
///
/// Usage:
/// ```ignore
/// let verdict = verify_by_said(&ctx, &issuer, "ECred…", policy, now).await?;
/// ```
pub async fn verify_by_said(
    ctx: &AuthsContext,
    issuer_alias: &auths_core::storage::keychain::KeyAlias,
    credential_said: &str,
    witness_policy: VerifierWitnessPolicy,
    now: DateTime<Utc>,
) -> Result<CredentialVerdict, CredentialError> {
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
    verify(ctx, &stored, witness_policy, now).await
}

/// Resolve a full KEL (oldest first) for any prefix via the registry.
pub(crate) fn resolve_kel(
    ctx: &AuthsContext,
    prefix: &Prefix,
) -> Result<Vec<Event>, CredentialError> {
    let mut events = Vec::new();
    ctx.registry
        .visit_events(prefix, 0, &mut |e| {
            events.push(e.clone());
            ControlFlow::Continue(())
        })
        .map_err(|e| CredentialError::StaleOrUnresolvable {
            reason: format!("issuer KEL read failed: {e}"),
        })?;
    Ok(events)
}

/// Resolve the credential's TEL (`vcp` + the `iss`/`rev` chain) under its registry.
pub(crate) fn resolve_tel(
    ctx: &AuthsContext,
    issuer_prefix: &Prefix,
    registry_said: &Said,
    credential_said: &Said,
) -> Result<Vec<TelEvent>, CredentialError> {
    let registry = match find_registry(ctx.registry.as_ref(), issuer_prefix)? {
        Some(reg) => reg,
        None => Said::new_unchecked(registry_said.as_str().to_string()),
    };
    Ok(read_credential_tel(
        ctx.registry.as_ref(),
        issuer_prefix,
        &registry,
        credential_said,
    )?)
}

/// The tip position of the resolved KEL (the as-of the verdict is reported against).
pub(crate) fn tip_as_of(issuer_kel: &[Event]) -> ResolvedAsOf {
    match issuer_kel.last() {
        Some(tip) => ResolvedAsOf {
            seq: tip.sequence().value(),
            said: tip.said().as_str().to_string(),
        },
        None => ResolvedAsOf {
            seq: 0,
            said: String::new(),
        },
    }
}

/// Whether the issuer's current key-state declares a non-empty backer (witness) set.
fn declares_backers(ctx: &AuthsContext, issuer_prefix: &Prefix) -> bool {
    ctx.registry
        .get_key_state(issuer_prefix)
        .map(|state| !state.backers.is_empty())
        .unwrap_or(false)
}

/// Collect the witness receipts for every lifecycle anchor to the witnessed tip.
///
/// The witnessed tip is established by receipts on the **establishment events**
/// (`icp`/`rot`/`dip`/`drt`) AND the **`vcp`/`iss`/`rev` anchoring `ixn`s**. This
/// gathers, for each establishment-event SAID and each TEL-event SAID, the stored
/// receipts and returns the de-duplicated union — exactly the set the pure verifier's
/// per-anchor quorum math (KAWA) filters against the in-force backer set.
pub(crate) fn collect_lifecycle_receipts(
    ctx: &AuthsContext,
    issuer_prefix: &Prefix,
    issuer_kel: &[Event],
    tel: &[TelEvent],
) -> Vec<StoredReceipt> {
    let Some(repo_path) = ctx.repo_path.as_ref() else {
        return Vec::new();
    };
    let lookup = GitReceiptStorage::new(repo_path.clone());

    let mut saids: Vec<Said> = Vec::new();
    for event in issuer_kel {
        if event.is_inception() || event.is_rotation() {
            push_unique(&mut saids, event.said().clone());
        }
    }
    for event in tel {
        push_unique(&mut saids, tel_event_said(event));
    }

    let mut receipts: Vec<StoredReceipt> = Vec::new();
    for said in &saids {
        if let Ok(Some(event_receipts)) = lookup.get_receipts(issuer_prefix, said) {
            for stored in event_receipts.receipts {
                receipts.push(stored);
            }
        }
    }
    receipts
}

/// Push `said` only if absent (the receipt-key set is de-duplicated).
fn push_unique(saids: &mut Vec<Said>, said: Said) {
    if !saids.contains(&said) {
        saids.push(said);
    }
}

/// The SAID of a TEL event (`vcp`/`iss`/`rev`).
fn tel_event_said(event: &TelEvent) -> Said {
    match event {
        TelEvent::Vcp(vcp) => vcp.d.clone(),
        TelEvent::Iss(iss) => iss.d.clone(),
        TelEvent::Rev(rev) => rev.d.clone(),
    }
}
