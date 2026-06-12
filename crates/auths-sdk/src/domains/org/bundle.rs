//! Air-gapped org provenance bundle — the registry-walking **builder**.
//!
//! Packs everything an **offline** verifier needs to reproduce a first-party
//! org/member provenance verdict with the network cable unplugged: the org KEL
//! (which carries the delegation `KeyEvent` seals, delegator-anchored scope seals,
//! and revocation seals), each delegated member's own KEL, the durable off-boarding
//! records ([`crate::domains::org::offboarding`]), and the pinned trust roots.
//!
//! The wire types ([`AirGappedOrgBundle`], [`BundledKel`]) and the pure
//! verification live in [`auths_verifier::org_bundle`] so every surface —
//! native, FFI, browser WASM — shares one contract; this module re-exports
//! them and keeps only the builder, which needs a live registry.
//!
//! Distinct in name and type from the transparency-log `OfflineBundle` — that one
//! is Merkle/inclusion-proof based and built **server-side by the log registry**;
//! this one is **first-party**, KEL/delegation based, and has **zero log-server
//! dependency**. Do not conflate them in docs or the deployment kit.
//!
//! **Size:** [`build_org_bundle`] loads each KEL fully into memory (it reuses the
//! same `visit_events` collection [`crate::domains::org::delegation`] uses). For a
//! very large org this is O(total KEL bytes) resident; streaming/segmented bundles
//! are a tracked follow-up. Typical design-partner orgs are well within memory.

use std::ops::ControlFlow;

use auths_id::keri::types::Prefix;
use auths_verifier::types::IdentityDID;

pub use auths_verifier::org_bundle::{
    AIR_GAPPED_ORG_BUNDLE_SCHEMA_VERSION, AirGappedOrgBundle, BundledKel,
};

use crate::context::AuthsContext;
use crate::domains::org::audit::list_offboarding_records;
use crate::domains::org::delegation::list_members;
use crate::domains::org::error::OrgError;

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
