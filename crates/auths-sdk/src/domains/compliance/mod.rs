//! Compliance domain services
//!
//! Approval workflows and attestation governance.

/// DSSE org-signing of evidence packs.
pub mod dsse;
/// Compliance errors
pub mod error;
/// Framework predicates (SLSA provenance + VSA, SPDX SBOM, CRA mapping).
pub mod frameworks;
/// Compliance-as-a-query: deterministic, offline-verifiable evidence packs.
pub mod query;
/// Compliance services
pub mod service;
/// Compliance types and configuration
pub mod types;

pub use dsse::{
    DSSE_INTOTO_PAYLOAD_TYPE, DsseEnvelope, DsseSignature, sign_evidence_pack,
    sign_framework_report,
};
pub use error::*;
pub use frameworks::{
    FrameworkReport, SignerVerifierAllowList, VsaParams, build_framework_report,
    sbom_document_sha256,
};
pub use query::{
    ComplianceFramework, ComplianceQueryError, EVIDENCE_PACK_SCHEMA_VERSION, EvidencePack,
    EvidenceRow, ReleaseRecord, RowVerdict, TransparencyInclusion, build_evidence_pack,
    build_offline_evidence_pack, load_witness_policy, verify_evidence_pack_offline,
};
