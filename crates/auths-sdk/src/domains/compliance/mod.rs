//! Compliance domain services
//!
//! Approval workflows and attestation governance.

/// Compliance errors
pub mod error;
/// Compliance-as-a-query: deterministic, offline-verifiable evidence packs.
pub mod query;
/// Compliance services
pub mod service;
/// Compliance types and configuration
pub mod types;

pub use error::*;
pub use query::{
    ComplianceFramework, ComplianceQueryError, EvidencePack, EvidenceRow, ReleaseRecord,
    build_evidence_pack,
};
