//! Domain services for org.

/// Authority-at-signing classification + off-boarding-log queries.
pub mod audit;
/// Air-gapped, URL-free org provenance bundle producer.
pub mod bundle;
/// KERI-native org membership — members as `dip`s delegated by the org AID.
pub mod delegation;
/// Org errors
pub mod error;
/// Fleet governance metrics ("what we measure").
pub mod metrics;
/// Off-boarding audit records — durable, signed, seal-bound revocation evidence.
pub mod offboarding;
/// Offline verification of an air-gapped org bundle (zero-network, fail-closed).
pub mod offline_verify;
/// Org-wide authorization policy: author/store/load + the fail-closed gate.
pub mod policy;
/// Org services
pub mod service;
/// Multi-hop delegation chain walker (accountability/traceability).
pub mod trace;
pub mod types;

pub use audit::{AuthorityAtSigning, classify_authority_at_signing, list_offboarding_records};
pub use bundle::{
    AIR_GAPPED_ORG_BUNDLE_SCHEMA_VERSION, AirGappedOrgBundle, BundledKel, build_org_bundle,
};
pub use delegation::{
    OrgMemberAuthority, OrgMemberResult, add_existing_member, add_member, list_members,
    member_policy_context, resolve_member_authority, revoke_member,
};
pub use metrics::{FleetMetrics, fleet_metrics};
pub use offboarding::{
    OffboardingRecord, SignedOffboardingRecord, load_offboarding_record, verify_offboarding_record,
};
pub use offline_verify::{OfflineVerifyReport, verify_org_bundle};
pub use policy::{
    Expr, LoadedOrgPolicy, OrgPolicySet, evaluate_with_org_policy, load_org_policy, set_org_policy,
};
pub use service::{OrgCreated, create_org};
pub use trace::{ChainHop, DelegationChain, MAX_CHAIN_DEPTH, walk_delegation_chain};
