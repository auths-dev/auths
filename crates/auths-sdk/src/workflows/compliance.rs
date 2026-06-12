//! Re-exports from [`crate::domains::compliance`].
//!
//! All compliance-query logic lives in `domains::compliance`. This module exists
//! only to keep `use auths_sdk::workflows::compliance::*` imports working across
//! the CLI and other presentation layers, mirroring [`crate::workflows::org`].

pub use crate::domains::compliance::dsse::{
    DSSE_INTOTO_PAYLOAD_TYPE, DsseEnvelope, DsseSignature, VerifiedEvidencePack,
    sign_evidence_pack, sign_framework_report, verify_signed_evidence_pack_offline,
};
pub use crate::domains::compliance::frameworks::{
    FrameworkReport, RowTimeliness, SignerVerifierAllowList, VsaParams, build_framework_report,
    sbom_document_sha256,
};
pub use crate::domains::compliance::query::{
    ComplianceFramework, ComplianceQueryError, EVIDENCE_PACK_SCHEMA_VERSION, EvidencePack,
    EvidenceRow, ReleaseRecord, RowVerdict, TransparencyInclusion, build_evidence_pack,
    build_offline_evidence_pack, load_witness_policy, verify_evidence_pack_offline,
};
pub use crate::domains::compliance::releases::{
    AnchoredRelease, ArtifactDigest, ReleaseAttestation, ReleaseAttestationKind, attest_release,
    discover_releases,
};
