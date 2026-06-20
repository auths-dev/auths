//! Compliance-as-a-query: turn the org's append-only history into a
//! deterministic, offline-verifiable evidence pack.
//!
//! Each row answers "who signed this artifact, and were they authorized **at
//! release time**?" — using [`classify_authority_at_signing`], ordered by KEL
//! position, never wall-clock. The pack embeds the honest witness-diversity
//! verdict ([`auths_transparency::HonestyCeiling`] via
//! [`ceiling_for_policy_load`]) rather than a bare non-equivocation flag, so
//! it can never over-claim third-party non-equivocation while only self-run
//! witnesses exist.
//!
//! The pack's wire types and the **verification** half
//! ([`verify_evidence_pack_offline`]) live in
//! [`auths_verifier::evidence_pack`] — the leaf crate every surface (native,
//! FFI, browser WASM) shares — and are re-exported here. This module keeps
//! the **build** half: classifying releases against the live registry and
//! embedding the org's KEL material as an [`AirGappedOrgBundle`] so each row
//! verifies with **zero network**. The org DSSE signature over the in-toto
//! statement lives in [`crate::domains::compliance::dsse`].

use std::path::Path;

use auths_id::keri::types::Prefix;
use auths_transparency::{WitnessPolicy, WitnessPolicyError, ceiling_for_policy_load};
use auths_verifier::IdentityDID;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub use auths_verifier::evidence_pack::{
    ComplianceFramework, EVIDENCE_PACK_SCHEMA_VERSION, EvidencePack, EvidencePackError,
    EvidenceRow, RowVerdict, TransparencyInclusion, verify_evidence_pack_offline,
    verify_transparency_inclusion,
};

use crate::context::AuthsContext;
use crate::domains::org::audit::classify_authority_at_signing;
use crate::domains::org::bundle::build_org_bundle;
use crate::domains::org::error::OrgError;

/// A typed failure building or verifying a compliance evidence pack.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ComplianceQueryError {
    /// Authority classification against the org KEL failed.
    #[error("authority classification failed: {0}")]
    Authority(#[from] OrgError),
    /// Canonical serialization (`json-canon`) failed.
    #[error("canonicalization failed: {0}")]
    Canonicalize(String),
    /// Org DSSE signing failed.
    #[error("org signing failed: {0}")]
    Signing(String),
    /// A base64/hex decode failed while reading a signed/wrapped pack.
    #[error("decode failed: {0}")]
    Decode(String),
    /// A DSSE signature did not verify against the org key.
    #[error("verification failed: {0}")]
    Verification(String),
    /// Offline pack verification failed (tampered KEL, unpinned root, or a
    /// transparency proof that did not check out).
    #[error("offline verification failed: {0}")]
    OfflineVerification(String),
    /// Anchoring a release attestation in the org KEL failed.
    #[error("release anchoring failed: {0}")]
    Anchor(#[from] auths_id::keri::AnchorError),
    /// A registry read/write failed while attesting or discovering releases.
    #[error("registry access failed: {0}")]
    Registry(String),
    /// A malformed artifact digest or release-attestation blob.
    #[error("invalid release attestation: {0}")]
    InvalidRelease(String),
    /// An anchored release blob does not hash back to its KEL seal digest.
    #[error("anchored release attestation {0} does not match its KEL seal digest")]
    TamperedRelease(String),
}

impl From<EvidencePackError> for ComplianceQueryError {
    fn from(e: EvidencePackError) -> Self {
        match e {
            EvidencePackError::Canonicalize(m) => Self::Canonicalize(m),
            EvidencePackError::Decode(m) => Self::Decode(m),
            EvidencePackError::OfflineVerification(m) => Self::OfflineVerification(m),
            other => Self::OfflineVerification(other.to_string()),
        }
    }
}

/// A release to classify: an artifact digest, the member that signed it, and its
/// in-band signing KEL position (`None` when the artifact carries no position —
/// which the classifier conservatively rejects).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReleaseRecord {
    /// The artifact content digest (e.g. `sha256:<hex>`).
    pub artifact_digest: String,
    /// The signing member's KEL prefix.
    pub signer_prefix: Prefix,
    /// The artifact's in-band signing position (`Auths-Anchor-Seq`), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_at: Option<u128>,
    /// Optional transparency-log inclusion evidence so the row verifies offline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transparency: Option<TransparencyInclusion>,
}

/// Load the pinned witness-diversity policy, **failing closed**.
///
/// Mirrors the monitor/cosigner: with no pinned policy path (the reality until an
/// independent commons is admitted) this returns `Err`, which
/// [`ceiling_for_policy_load`] renders as the honest "single-operator — not yet
/// independent" verdict. A surface NEVER falls back to an unconstrained policy that
/// would let it imply independence.
///
/// Args:
/// * `path`: The pinned `witness_policy.json` path, or `None` when unset.
///
/// Usage:
/// ```ignore
/// let policy = load_witness_policy(path.as_deref());
/// let pack = build_evidence_pack(&ctx, org, &p, "2026-Q3", fw, &rel, &policy, now)?;
/// ```
pub fn load_witness_policy(path: Option<&Path>) -> Result<WitnessPolicy, WitnessPolicyError> {
    match path {
        Some(p) => WitnessPolicy::load(p),
        None => Err(WitnessPolicyError::NotFound {
            path: "<AUTHS_WITNESS_POLICY_PATH unset>".into(),
        }),
    }
}

/// Classify each release into an [`EvidenceRow`], by KEL order.
fn classify_rows(
    ctx: &AuthsContext,
    org_prefix: &Prefix,
    releases: &[ReleaseRecord],
) -> Result<Vec<EvidenceRow>, ComplianceQueryError> {
    let mut rows = Vec::with_capacity(releases.len());
    for r in releases {
        let authority_at_release =
            classify_authority_at_signing(ctx, org_prefix, &r.signer_prefix, r.signed_at)?;
        let signer = IdentityDID::try_from(&r.signer_prefix)
            .map_err(|e| ComplianceQueryError::InvalidRelease(e.to_string()))?;
        rows.push(EvidenceRow {
            artifact_digest: r.artifact_digest.clone(),
            signer,
            authority_at_release,
            signed_at: r.signed_at,
            transparency: r.transparency.clone(),
        });
    }
    Ok(rows)
}

/// Build a compliance evidence pack by classifying each release against the org
/// KEL.
///
/// The releases are the query input — the caller (CLI / a higher layer) supplies
/// the artifacts released in the period; this engine classifies each signer's
/// authority at the release position and embeds the honest witness verdict. It
/// performs no I/O beyond the registry reads `classify_authority_at_signing`
/// already does, and embeds no offline bundle (use [`build_offline_evidence_pack`]
/// for a URL-free pack).
///
/// Args:
/// * `ctx`: Auths context (registry).
/// * `org`: The org's self-certifying identity (for the pack header).
/// * `org_prefix`: The org's KEL prefix (the delegator).
/// * `period`: The reporting period label.
/// * `framework`: The target compliance framework.
/// * `releases`: The artifacts released in the period.
/// * `witness_policy`: The witness-policy load result (drives the honest verdict).
/// * `generated_at`: Injected generation timestamp.
///
/// Usage:
/// ```ignore
/// let pack = build_evidence_pack(&ctx, org, &org_prefix, "2026-Q3",
///     ComplianceFramework::Slsa, &releases, &policy_result, now)?;
/// let canonical = pack.canonicalize()?;
/// ```
#[allow(clippy::too_many_arguments)]
pub fn build_evidence_pack(
    ctx: &AuthsContext,
    org: IdentityDID,
    org_prefix: &Prefix,
    period: impl Into<String>,
    framework: ComplianceFramework,
    releases: &[ReleaseRecord],
    witness_policy: &Result<WitnessPolicy, WitnessPolicyError>,
    generated_at: DateTime<Utc>,
) -> Result<EvidencePack, ComplianceQueryError> {
    let rows = classify_rows(ctx, org_prefix, releases)?;
    Ok(EvidencePack {
        schema_version: EVIDENCE_PACK_SCHEMA_VERSION,
        org,
        period: period.into(),
        framework,
        equivocation_visibility: ceiling_for_policy_load(witness_policy),
        generated_at,
        rows,
        org_bundle: None,
    })
}

/// Build an **offline-verifiable** compliance evidence pack.
///
/// Identical to [`build_evidence_pack`] but embeds the org's KEL material as an
/// [`AirGappedOrgBundle`](crate::domains::org::bundle::AirGappedOrgBundle)
/// (org KEL + every member KEL + off-boarding records + pinned root), so
/// [`verify_evidence_pack_offline`] can re-derive every row's authority and
/// check each row's transparency proof with **zero network**.
///
/// Args:
/// * `ctx`: Auths context (registry, clock — used to build the embedded bundle).
/// * `org`: The org's self-certifying identity (for the pack header).
/// * `org_prefix`: The org's KEL prefix (the delegator).
/// * `period`: The reporting period label.
/// * `framework`: The target compliance framework.
/// * `releases`: The artifacts released in the period.
/// * `witness_policy`: The witness-policy load result (drives the honest verdict).
/// * `generated_at`: Injected generation timestamp.
///
/// Usage:
/// ```ignore
/// let pack = build_offline_evidence_pack(&ctx, org, &org_prefix, "2026-Q3",
///     ComplianceFramework::Slsa, &releases, &policy_result, now)?;
/// std::fs::write("acme-2026Q3.evidence", pack.canonicalize()?)?;
/// ```
#[allow(clippy::too_many_arguments)]
pub fn build_offline_evidence_pack(
    ctx: &AuthsContext,
    org: IdentityDID,
    org_prefix: &Prefix,
    period: impl Into<String>,
    framework: ComplianceFramework,
    releases: &[ReleaseRecord],
    witness_policy: &Result<WitnessPolicy, WitnessPolicyError>,
    generated_at: DateTime<Utc>,
) -> Result<EvidencePack, ComplianceQueryError> {
    let mut pack = build_evidence_pack(
        ctx,
        org,
        org_prefix,
        period,
        framework,
        releases,
        witness_policy,
        generated_at,
    )?;
    pack.org_bundle = Some(build_org_bundle(ctx, org_prefix)?);
    Ok(pack)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use auths_transparency::HonestyCeiling;
    use auths_verifier::org_bundle::AuthorityAtSigning;

    fn fixed_now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-06-08T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn single_operator_ceiling() -> HonestyCeiling {
        // The reality today: no independent commons → not policy_met.
        ceiling_for_policy_load(&Err(WitnessPolicyError::NotFound {
            path: "<unset>".into(),
        }))
    }

    fn sample_pack() -> EvidencePack {
        EvidencePack {
            schema_version: EVIDENCE_PACK_SCHEMA_VERSION,
            org: IdentityDID::parse("did:keri:EOrg").unwrap(),
            period: "2026-Q3".into(),
            framework: ComplianceFramework::Slsa,
            equivocation_visibility: single_operator_ceiling(),
            generated_at: fixed_now(),
            rows: vec![EvidenceRow {
                artifact_digest: "sha256:aa".into(),
                signer: IdentityDID::parse("did:keri:EAlice").unwrap(),
                authority_at_release: AuthorityAtSigning::AuthorizedBeforeRevocation,
                signed_at: Some(7),
                transparency: None,
            }],
            org_bundle: None,
        }
    }

    #[test]
    fn pack_embeds_single_operator_ceiling_not_a_bare_flag() {
        let pack = sample_pack();
        assert!(!pack.equivocation_visibility.policy_met);
        let json = pack.canonicalize().unwrap();
        // Honest: renders the ceiling, never a `non_equivocation: true`.
        assert!(!json.contains("non_equivocation"));
        assert!(json.contains("not yet independent"));
    }
}
