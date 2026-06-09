//! Air-gapped org provenance bundle — a self-contained, URL-free artifact.
//!
//! Packs everything an **offline** verifier needs to reproduce a first-party
//! org/member provenance verdict with the network cable unplugged: the org KEL
//! (which carries the delegation `KeyEvent` seals, delegator-anchored scope seals,
//! and revocation seals), each delegated member's own KEL, the durable off-boarding
//! records ([`crate::domains::org::offboarding`]), and the pinned trust roots.
//!
//! Distinct in name and type from the transparency-log [`OfflineBundle`] — that one
//! is Merkle/inclusion-proof based and built **server-side by the log registry**;
//! this one is **first-party**, KEL/delegation based, and has **zero log-server
//! dependency**. Do not conflate them in docs or the deployment kit.
//!
//! **URL-free:** the bundle contains no registry / OOBI / witness URLs — air-gapped
//! verification cannot phone home (enforced by tests). Identities are typed
//! ([`IdentityDID`] / [`Prefix`]) so a tampered or malformed identifier fails closed
//! at deserialization rather than flowing through as an opaque string.
//!
//! **Size:** [`build_org_bundle`] loads each KEL fully into memory (it reuses the
//! same `visit_events` collection [`crate::domains::org::delegation`] uses). For a
//! very large org this is O(total KEL bytes) resident; streaming/segmented bundles
//! are a tracked follow-up. Typical design-partner orgs are well within memory.
//!
//! [`OfflineBundle`]: https://docs.rs/auths-transparency

use std::ops::ControlFlow;

use auths_id::keri::Event;
use auths_id::keri::types::Prefix;
use auths_verifier::types::IdentityDID;
use serde::{Deserialize, Serialize};

use crate::context::AuthsContext;
use crate::domains::org::audit::list_offboarding_records;
use crate::domains::org::delegation::list_members;
use crate::domains::org::error::OrgError;
use crate::domains::org::offboarding::SignedOffboardingRecord;

/// Schema version of the air-gapped org bundle wire format. Bump on any
/// breaking change to [`AirGappedOrgBundle`].
pub const AIR_GAPPED_ORG_BUNDLE_SCHEMA_VERSION: u32 = 1;

/// One identifier's KEL plus its per-event signature attachments.
///
/// `attachments[i]` is the hex-encoded CESR attachment for `events[i]` (empty when
/// the backend exposes none for that position). Carried so an offline verifier can
/// check signatures, not just recompute SAIDs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BundledKel {
    /// The identifier's KEL prefix (validated on deserialize).
    pub prefix: Prefix,
    /// The KEL events, oldest first.
    pub events: Vec<Event>,
    /// Hex-encoded CESR signature attachments, parallel to `events`.
    pub attachments: Vec<String>,
}

/// A self-contained, URL-free bundle for offline first-party org/member provenance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AirGappedOrgBundle {
    /// Wire-format schema version ([`AIR_GAPPED_ORG_BUNDLE_SCHEMA_VERSION`]).
    pub schema_version: u32,
    /// The org's `did:keri:` (validated on deserialize).
    pub org_did: IdentityDID,
    /// The org's KEL prefix.
    pub org_prefix: Prefix,
    /// The org KEL sequence at build time — the offline verifier reports
    /// "verified as-of KEL position X".
    pub built_at_org_seq: u128,
    /// Build timestamp (RFC 3339). Provenance only — authority ordering is by KEL
    /// position, never this wall-clock value.
    pub built_at: String,
    /// The org's KEL (delegation, scope, and revocation seals all ride here).
    pub org_kel: BundledKel,
    /// Each delegated member's own KEL (live and revoked members both included so
    /// the verifier can classify any artifact).
    pub member_kels: Vec<BundledKel>,
    /// Durable, signed off-boarding records ([`crate::domains::org::offboarding`]).
    pub offboarding_records: Vec<SignedOffboardingRecord>,
    /// Pinned trust roots — for a first-party org bundle, the org itself. The
    /// verifier trusts these DIDs and reads their keys from the bundled KEL.
    pub pinned_roots: Vec<IdentityDID>,
}

impl AirGappedOrgBundle {
    /// Serialize the bundle to deterministic, canonical JSON (RFC 8785 via
    /// `json-canon`) — the on-disk/wire form.
    ///
    /// Usage:
    /// ```ignore
    /// std::fs::write(out, bundle.to_canonical_json()?)?;
    /// ```
    pub fn to_canonical_json(&self) -> Result<String, OrgError> {
        json_canon::to_string(self)
            .map_err(|e| OrgError::Signing(format!("canonicalize org bundle: {e}")))
    }

    /// Parse a bundle from its JSON form. Typed identifiers fail closed on malformed
    /// input.
    ///
    /// Usage:
    /// ```ignore
    /// let bundle = AirGappedOrgBundle::from_json(&std::fs::read_to_string(path)?)?;
    /// ```
    pub fn from_json(json: &str) -> Result<Self, OrgError> {
        serde_json::from_str(json).map_err(|e| OrgError::Signing(format!("parse org bundle: {e}")))
    }
}

/// Collect one identifier's KEL and per-event attachments into a [`BundledKel`].
fn collect_bundled_kel(ctx: &AuthsContext, prefix: &Prefix) -> Result<BundledKel, OrgError> {
    let mut events = Vec::new();
    ctx.registry
        .visit_events(prefix, 0, &mut |event| {
            events.push(event.clone());
            ControlFlow::Continue(())
        })
        .map_err(OrgError::Storage)?;

    let mut attachments = Vec::with_capacity(events.len());
    for event in &events {
        let seq = event.sequence().value();
        let attachment = ctx
            .registry
            .get_attachment(prefix, seq)
            .map_err(OrgError::Storage)?;
        attachments.push(attachment.map(hex::encode).unwrap_or_default());
    }

    Ok(BundledKel {
        prefix: prefix.clone(),
        events,
        attachments,
    })
}

/// Build a self-contained, URL-free air-gapped bundle for an org.
///
/// Reuses the KEL-authoritative roster ([`list_members`]) and off-boarding log
/// ([`list_offboarding_records`]); packs the org KEL, every delegated member's KEL
/// (live and revoked), the off-boarding records, and the org as the pinned root.
/// The clock is read from `ctx.clock`.
///
/// Args:
/// * `ctx`: Auths context (registry, clock).
/// * `org_prefix`: The org's KEL prefix.
///
/// Usage:
/// ```ignore
/// let bundle = build_org_bundle(&ctx, &org_prefix)?;
/// std::fs::write("acme.auths-offline", bundle.to_canonical_json()?)?;
/// ```
pub fn build_org_bundle(
    ctx: &AuthsContext,
    org_prefix: &Prefix,
) -> Result<AirGappedOrgBundle, OrgError> {
    let org_did = IdentityDID::from_prefix(org_prefix.as_str())
        .map_err(|e| OrgError::InvalidDid(e.to_string()))?;

    let org_kel = collect_bundled_kel(ctx, org_prefix)?;
    let built_at_org_seq = org_kel
        .events
        .last()
        .map(|e| e.sequence().value())
        .unwrap_or(0);

    let mut member_kels = Vec::new();
    for member in list_members(ctx, org_prefix)? {
        let member_prefix = Prefix::new_unchecked(member.member_prefix.clone());
        member_kels.push(collect_bundled_kel(ctx, &member_prefix)?);
    }

    let offboarding_records = list_offboarding_records(ctx, org_prefix)?;

    Ok(AirGappedOrgBundle {
        schema_version: AIR_GAPPED_ORG_BUNDLE_SCHEMA_VERSION,
        org_did: org_did.clone(),
        org_prefix: org_prefix.clone(),
        built_at_org_seq,
        built_at: ctx.clock.now().to_rfc3339(),
        org_kel,
        member_kels,
        offboarding_records,
        pinned_roots: vec![org_did],
    })
}
