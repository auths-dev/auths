//! Offline verification of an air-gapped org provenance bundle.
//!
//! The pure, zero-network core of the org/member provenance story: a
//! self-contained [`AirGappedOrgBundle`] (the org KEL, every delegated
//! member's KEL, durable off-boarding records, pinned roots) verifies with
//! the network cable unplugged — every event's SAID recomputed, every event's
//! signature authenticated against the controlling key-state (RT-002),
//! duplicity flagged, and a member's authority at a signing position
//! classified **by KEL position, never wall-clock**.
//!
//! It lives in the verifier crate — the leaf dependency every surface shares
//! — so a CI gate, a third-party audit tool, or a **browser** (via the WASM
//! exports) reproduces the same verdict from evidence alone. The bundle
//! *builder* (which needs a live registry) stays in `auths-sdk`; that crate
//! re-exports these types so there is exactly one definition of the wire
//! contract.

/// Air-gapped bundle wire types.
pub mod bundle;
/// Typed failures for bundle and record verification.
pub mod error;
/// Durable, signed off-boarding records bound to on-KEL revocation seals.
pub mod record;
/// The offline verification engine.
pub mod verify;

pub use bundle::{AIR_GAPPED_ORG_BUNDLE_SCHEMA_VERSION, AirGappedOrgBundle, BundledKel};
pub use error::OrgBundleError;
pub use record::{
    OffboardingRecord, SignedOffboardingRecord, find_revocation_event, verify_offboarding_record,
};
pub use verify::{
    AuthorityAtSigning, OfflineVerifyReport, authenticate_bundled_kel,
    classify_authority_in_bundle, verify_org_bundle, verify_org_bundle_json,
};
