//! Air-gapped org provenance bundle — a self-contained, URL-free artifact.
//!
//! Packs everything an **offline** verifier needs to reproduce a first-party
//! org/member provenance verdict with the network cable unplugged: the org KEL
//! (which carries the delegation `KeyEvent` seals, delegator-anchored scope seals,
//! and revocation seals), each delegated member's own KEL, the durable off-boarding
//! records, and the pinned trust roots. The *builder* (which walks a live registry)
//! lives in `auths-sdk`; the wire types and their pure methods live here so every
//! verifier surface — native, FFI, browser WASM — shares one contract.
//!
//! **URL-free:** the bundle contains no registry / OOBI / witness URLs — air-gapped
//! verification cannot phone home. Identities are typed ([`IdentityDID`] /
//! [`Prefix`]) so a tampered or malformed identifier fails closed at
//! deserialization rather than flowing through as an opaque string.

use auths_keri::{Event, Prefix};
use serde::{Deserialize, Serialize};

use super::error::OrgBundleError;
use super::record::SignedOffboardingRecord;
use crate::types::IdentityDID;

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
    /// Durable, signed off-boarding records.
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
    pub fn to_canonical_json(&self) -> Result<String, OrgBundleError> {
        json_canon::to_string(self)
            .map_err(|e| OrgBundleError::Canonicalize(format!("org bundle: {e}")))
    }

    /// Parse a bundle from its JSON form. Typed identifiers fail closed on malformed
    /// input.
    ///
    /// Usage:
    /// ```ignore
    /// let bundle = AirGappedOrgBundle::from_json(&std::fs::read_to_string(path)?)?;
    /// ```
    pub fn from_json(json: &str) -> Result<Self, OrgBundleError> {
        serde_json::from_str(json).map_err(|e| OrgBundleError::Parse(format!("org bundle: {e}")))
    }

    /// The org's authenticated key state, derived from the bundled org KEL alone.
    ///
    /// Authenticates the embedded org KEL (RT-002 — every event SAID-correct AND
    /// signed by the controlling key-state, not merely structurally valid) and
    /// returns the resolved [`auths_keri::KeyState`]. The org KEL is the root of
    /// trust, so it authenticates with no delegator lookup.
    ///
    /// This is the one public call for "give me the org's authenticated key state
    /// from evidence alone" — the only trust-rooted source of the org's *current*
    /// verkey available offline (e.g. to verify a DSSE envelope the org signed).
    /// Every downstream verifier (CI gate, browser widget, third-party audit tool)
    /// shares it instead of re-implementing the authenticate-then-resolve path.
    ///
    /// Fails closed ([`OrgBundleError::Integrity`]) on a tampered event, a length
    /// mismatch between events and attachments, an unparseable attachment, or a
    /// signature that does not verify.
    ///
    /// Usage:
    /// ```ignore
    /// let state = bundle.authenticated_org_state()?;
    /// let org_verkey = state.current_key();
    /// ```
    pub fn authenticated_org_state(&self) -> Result<auths_keri::KeyState, OrgBundleError> {
        super::verify::authenticate_bundled_kel(&self.org_kel, None)
    }
}
