//! Offline verification of an air-gapped org bundle — a pure, zero-network function
//! of the bundle's contents.
//!
//! Reproduces the live org/member provenance verdict from a fn-154.5
//! [`AirGappedOrgBundle`] with the network cable unplugged: it recomputes every
//! bundled event's SAID (tamper-evident), confirms the org is a **pinned** root,
//! flags KEL duplicity, and classifies a member's authority at a signing position
//! **by KEL position, never wall-clock** (same ordering as
//! [`crate::domains::org::audit::classify_authority_at_signing`], read from the
//! bundle instead of a live registry).
//!
//! Fail-closed: a tampered event (SAID mismatch), a delegated member whose KEL is
//! missing, or a queried member with no delegation seal each yield a **named hard
//! error**, never "valid." A wrong/non-delegating pinned root is reported as
//! `root_pinned = false` (unauthorized), not an error.

use auths_id::keri::types::Prefix;
use auths_id::keri::{Event, Seal, verify_event_said};
use auths_verifier::duplicity::{KelEventRef, detect_duplicity};
use auths_verifier::types::IdentityDID;
use serde::Serialize;

use crate::domains::org::audit::AuthorityAtSigning;
use crate::domains::org::bundle::{AirGappedOrgBundle, BundledKel};
use crate::domains::org::error::OrgError;
use crate::domains::org::offboarding::find_revocation_event;

/// The result of verifying an air-gapped org bundle offline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OfflineVerifyReport {
    /// The org the bundle is for.
    pub org_did: IdentityDID,
    /// The org KEL position the bundle (and therefore this verdict) is verified
    /// as-of — "verified as-of KEL position X."
    pub as_of_org_seq: u128,
    /// Whether the org is in the caller's pinned trust roots. `false` =
    /// unauthorized (the verdict cannot be trusted), not an error.
    pub root_pinned: bool,
    /// Whether the org KEL shows duplicity (same seq, divergent SAIDs). Flagged,
    /// never silently accepted.
    pub duplicity_detected: bool,
    /// The queried member's authority at the signing position, when a member +
    /// position were supplied. Ordered by KEL position, never wall-clock.
    pub authority: Option<AuthorityAtSigning>,
}

/// Recompute and check every event's SAID in a bundled KEL (tamper detection).
fn check_kel_integrity(kel: &BundledKel) -> Result<(), OrgError> {
    for event in &kel.events {
        verify_event_said(event).map_err(|e| OrgError::BundleIntegrity {
            id: kel.prefix.as_str().to_string(),
            reason: e.to_string(),
        })?;
    }
    Ok(())
}

/// Authenticate a bundled KEL (RT-002): verify every event is SIGNED by the
/// controlling key-state, not just SAID-correct. Reconstructs `SignedEvent`s from
/// the parallel `events` × hex `attachments` and replays them through
/// `validate_signed_kel`. Fails closed on a length mismatch, an unparseable
/// attachment, or a signature that doesn't verify.
fn authenticate_bundled_kel(
    kel: &BundledKel,
    lookup: Option<&dyn auths_keri::DelegatorKelLookup>,
) -> Result<(), OrgError> {
    let integrity_err = |reason: String| OrgError::BundleIntegrity {
        id: kel.prefix.as_str().to_string(),
        reason,
    };
    if kel.attachments.len() != kel.events.len() {
        return Err(integrity_err(format!(
            "{} events but {} signature attachments — cannot authenticate",
            kel.events.len(),
            kel.attachments.len()
        )));
    }
    let mut signed = Vec::with_capacity(kel.events.len());
    for (event, att_hex) in kel.events.iter().zip(kel.attachments.iter()) {
        let bytes =
            hex::decode(att_hex).map_err(|e| integrity_err(format!("non-hex attachment: {e}")))?;
        // A delegated (dip/drt) event's attachment is `-A <sig> ++ -G <source seal>`;
        // a plain event's is just `-A <sig>`. `parse_delegated_attachment` handles both.
        let (sigs, seals) = auths_keri::parse_delegated_attachment(&bytes)
            .map_err(|e| integrity_err(format!("unparseable attachment: {e}")))?;
        // A dip/drt JSON body carries no source seal (it lives in the attachment);
        // restore it so the delegation binding can be authenticated.
        let event = rehydrate_event_source_seal(event.clone(), seals.into_iter().next());
        signed.push(auths_keri::SignedEvent::new(event, sigs));
    }
    auths_keri::validate_signed_kel(&signed, lookup)
        .map_err(|e| integrity_err(format!("KEL signature authentication failed (RT-002): {e}")))?;
    Ok(())
}

/// Re-attach a delegated event's source seal from its parsed attachment — the JSON
/// body of a `dip`/`drt` carries none (it lives in the `-G` group). Mirrors the
/// storage layer's `rehydrate_source_seal`.
fn rehydrate_event_source_seal(event: Event, seal: Option<auths_keri::SourceSeal>) -> Event {
    let Some(seal) = seal else {
        return event;
    };
    match event {
        Event::Dip(mut e) => {
            e.source_seal = Some(seal);
            Event::Dip(e)
        }
        Event::Drt(mut e) => {
            e.source_seal = Some(seal);
            Event::Drt(e)
        }
        other => other,
    }
}

/// Does the org KEL anchor a delegation `KeyEvent` seal for `member_prefix`?
fn is_delegated(org_kel: &[Event], member_prefix: &Prefix) -> bool {
    org_kel.iter().any(|event| {
        event.anchors().iter().any(
            |seal| matches!(seal, Seal::KeyEvent { i, .. } if i.as_str() == member_prefix.as_str()),
        )
    })
}

/// Classify a member's authority at `signed_at` from an air-gapped bundle's org KEL —
/// the offline mirror of [`crate::domains::org::audit::classify_authority_at_signing`],
/// for re-deriving compliance evidence-pack rows with zero network.
///
/// Args:
/// * `bundle`: The air-gapped org bundle (its org KEL is the authority source).
/// * `member_prefix`: The member to classify.
/// * `signed_at`: The artifact's in-band signing position, if any.
///
/// Usage:
/// ```ignore
/// let verdict = classify_authority_in_bundle(&bundle, &member, Some(41));
/// ```
pub fn classify_authority_in_bundle(
    bundle: &AirGappedOrgBundle,
    member_prefix: &Prefix,
    signed_at: Option<u128>,
) -> AuthorityAtSigning {
    classify_from_bundle(&bundle.org_kel.events, member_prefix, signed_at)
}

/// Classify a member's authority at `signed_at`, read purely from the bundle's org
/// KEL — the offline mirror of [`crate::domains::org::audit::classify_authority_at_signing`].
fn classify_from_bundle(
    org_kel: &[Event],
    member_prefix: &Prefix,
    signed_at: Option<u128>,
) -> AuthorityAtSigning {
    if !is_delegated(org_kel, member_prefix) {
        return AuthorityAtSigning::NeverDelegated;
    }
    match find_revocation_event(org_kel, member_prefix) {
        None => AuthorityAtSigning::AuthorizedBeforeRevocation,
        Some((_, revoked_at)) => match signed_at {
            None => AuthorityAtSigning::RejectedRevokedPositionUnknown { revoked_at },
            Some(seq) if seq < revoked_at => AuthorityAtSigning::AuthorizedBeforeRevocation,
            Some(_) => AuthorityAtSigning::RejectedAfterRevocation { revoked_at },
        },
    }
}

/// Verify an air-gapped org bundle offline.
///
/// Pure and network-free. Checks bundle integrity (every event's SAID), confirms the
/// org is pinned, flags org-KEL duplicity, and — when `query` supplies a member and
/// optional signing position — classifies that member's authority by KEL position.
///
/// Fail-closed errors (never "valid"): [`OrgError::BundleIntegrity`] (a tampered
/// event), [`OrgError::BundleMissingMemberKel`] (a delegated member's KEL is absent),
/// [`OrgError::BundleMissingDelegatorSeal`] (a queried member was never delegated).
///
/// Args:
/// * `bundle`: The air-gapped bundle to verify.
/// * `pinned_roots`: The caller's pinned trust roots (e.g. from `.auths/roots`).
/// * `query`: Optional `(member_prefix, signed_at)` to classify a specific artifact.
///
/// Usage:
/// ```ignore
/// let report = verify_org_bundle(&bundle, &roots, Some((&member, Some(41))))?;
/// assert!(report.root_pinned);
/// ```
pub fn verify_org_bundle(
    bundle: &AirGappedOrgBundle,
    pinned_roots: &[IdentityDID],
    query: Option<(&Prefix, Option<u128>)>,
) -> Result<OfflineVerifyReport, OrgError> {
    // 1. Integrity + AUTHENTICATION (RT-002): every bundled event must self-address
    //    (SAID) AND be signed by the controlling key-state — not just structurally
    //    valid. The org KEL is the root of trust (no delegator); member KELs are
    //    authenticated against the org as delegator.
    check_kel_integrity(&bundle.org_kel)?;
    authenticate_bundled_kel(&bundle.org_kel, None)?;
    let org_lookup = auths_keri::KelSealIndex::from_events(&bundle.org_kel.events);
    for member_kel in &bundle.member_kels {
        check_kel_integrity(member_kel)?;
        authenticate_bundled_kel(member_kel, Some(&org_lookup))?;
    }

    // 2. Completeness: every member the org delegated must ship its own KEL.
    for event in &bundle.org_kel.events {
        for seal in event.anchors() {
            if let Seal::KeyEvent { i, .. } = seal {
                let present = bundle
                    .member_kels
                    .iter()
                    .any(|m| m.prefix.as_str() == i.as_str());
                if !present {
                    return Err(OrgError::BundleMissingMemberKel {
                        member: format!("did:keri:{}", i.as_str()),
                    });
                }
            }
        }
    }

    // 3. Trust: is the org a pinned root? (false = unauthorized, not an error.)
    let root_pinned = pinned_roots
        .iter()
        .any(|r| r.as_str() == bundle.org_did.as_str());

    // 4. Duplicity: same-seq divergent SAIDs on the org KEL — flag, never accept.
    let org_did_str = bundle.org_did.as_str().to_string();
    let refs: Vec<KelEventRef<'_>> = bundle
        .org_kel
        .events
        .iter()
        .map(|e| KelEventRef {
            prefix: org_did_str.as_str(),
            seq: e.sequence().value() as u64,
            said: e.said().as_str(),
        })
        .collect();
    let duplicity_detected = detect_duplicity(&refs).is_diverging();

    // 5. Authority classification for the queried member, by KEL position.
    let authority = match query {
        Some((member_prefix, signed_at)) => {
            if !is_delegated(&bundle.org_kel.events, member_prefix) {
                return Err(OrgError::BundleMissingDelegatorSeal {
                    member: format!("did:keri:{}", member_prefix.as_str()),
                });
            }
            Some(classify_from_bundle(
                &bundle.org_kel.events,
                member_prefix,
                signed_at,
            ))
        }
        None => None,
    };

    Ok(OfflineVerifyReport {
        org_did: bundle.org_did.clone(),
        as_of_org_seq: bundle.built_at_org_seq,
        root_pinned,
        duplicity_detected,
        authority,
    })
}
