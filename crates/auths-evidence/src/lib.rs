//! # auths-evidence — the single trust implementation behind evidence bundles
//!
//! One crate owns verification orchestration, spend re-derivation, chain
//! resolution, verdict computation, and canonical bundle signing — shared by the
//! gateway CLI, the first-party tool servers, and every language binding, so no
//! consumer ever reimplements trust logic (§0.1 of the receipts plan).
//!
//! The contract this crate implements (§2 of the plan):
//!
//! * **Every verdict is "as of head H."** Budget/authorization verdicts are
//!   absence proofs a truncated log can forge; the anchor (a head commitment by
//!   someone other than the producer) turns them into checkable facts. The bundle
//!   states which anchor tier it used — a verdict is never stronger than its tier.
//! * **The report is the only API.** Consumers read verdict fields; nothing
//!   downstream parses KELs or attachments out of evidence.
//! * **One audit walk.** The per-record replay lives in `auths-mcp-core`; this
//!   crate orchestrates and annotates it, never forks it.

pub mod anchor;
pub mod attestation;
pub mod bundle;
pub mod error;
pub mod judge;
pub mod kel_wire;
pub mod resolve_chain;
pub mod reversal;
pub mod types;
pub mod verify_spend;

pub use anchor::{
    AnchorCheck, TreasuryAnchorProof, WitnessAnchorProof, WitnessBinding, anchored_index_of,
    check_trail, composite_head, kel_digest, spend_binding_head, verify_anchor, witness_anchor,
};
// The AWN protocol core, re-exported so evidence consumers reach freshness and
// the finalized-anchor proof through one crate.
pub use attestation::{
    ACTIVITY_VERSION, ActivityAsOf, ActivityV1, activity_seed_id, activity_signing_bytes,
    monotonicity_violation, unsigned_activity_anchor, verify_activity,
    verify_activity_against_registry,
};
pub use auths_anchor::{Freshness, freshness};
pub use bundle::{
    BuildOpts, BundleSigner, OfflineVerdict, SignatureSuite, build_bundle, did_key_encode,
    signing_bytes, verify_offline,
};
pub use error::EvidenceError;
pub use judge::{ChainView, judge_call, judge_log, locate_call};
pub use kel_wire::{kel_from_wire, kel_to_wire};
pub use resolve_chain::{ChainInput, RegistrySource, ResolvedChain, TreasuryInput, resolve_chain};
pub use reversal::{
    HoldState, REVERSAL_VERSION, RailHint, ReversalAmount, ReversalAmountKind, ReversalBasis,
    ReversalDetermination, ReversalInputs, ReversalOutcome, ReversalParties, determine_reversal,
    reversal_signing_bytes, verify_determination,
};
pub use types::{
    AUDIT_VERSION, AnchorRef, AnchorTier, AuditCheckpoint, AuditV1, BudgetBasis, BundleCall,
    BundleGrant, BundleProof, BundleSettlement, CallVerdict, CounterpartyPolicy,
    CounterpartyPolicyKind, EvidenceBundle, LogVerdict, OnlineFreshness, PolicyDecision,
    RECEIPTS_VERSION, RevocationFact, Subject, TreasuryCheck, Verdicts,
};
pub use verify_spend::{VerifiedSpend, VerifyOpts, report_of, verify_spend};

/// The JSON schema for the `receipts/v1` wire contract, embedded so bindings and
/// tools can serve it without a filesystem.
pub const RECEIPTS_V1_SCHEMA: &str = include_str!("../schemas/receipts-v1.json");

/// The JSON schema for the `audit/v1` report.
pub const AUDIT_V1_SCHEMA: &str = include_str!("../schemas/audit-v1.json");

/// The JSON schema for the AWN duplicity proof (published beside `receipts/v1`).
pub const DUPLICITY_PROOF_V1_SCHEMA: &str = include_str!("../schemas/duplicity-proof-v1.json");
