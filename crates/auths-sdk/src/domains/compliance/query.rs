//! Compliance-as-a-query: turn the org's append-only history into a
//! deterministic, offline-verifiable evidence pack.
//!
//! Each row answers "who signed this artifact, and were they authorized **at
//! release time**?" — using [`classify_authority_at_signing`], ordered by KEL
//! position, never wall-clock. The pack embeds the honest witness-diversity
//! verdict ([`HonestyCeiling`] via [`ceiling_for_policy_load`]) rather than a
//! bare non-equivocation flag, so it can never over-claim third-party
//! non-equivocation while only self-run witnesses exist.
//!
//! The pack is canonicalized with `json-canon` so two runs over the same inputs
//! produce byte-identical output (an auditor can re-derive it), and it is
//! URL-free so each row verifies offline. The in-toto/DSSE wrapper
//! ([`EvidencePack::to_intoto_statement`]) rides the same canonical bytes; the
//! org DSSE signature and SLSA/SBOM/CRA predicate rendering land in fn-157.9.

use auths_id::keri::types::Prefix;
use auths_transparency::{
    HonestyCeiling, WitnessPolicy, WitnessPolicyError, ceiling_for_policy_load,
};
use auths_verifier::IdentityDID;
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::context::AuthsContext;
use crate::domains::org::audit::{AuthorityAtSigning, classify_authority_at_signing};
use crate::domains::org::error::OrgError;

/// The current evidence-pack schema version.
pub const EVIDENCE_PACK_SCHEMA_VERSION: u32 = 1;

/// A typed failure building a compliance evidence pack.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ComplianceQueryError {
    /// Authority classification against the org KEL failed.
    #[error("authority classification failed: {0}")]
    Authority(#[from] OrgError),
    /// Canonical serialization (`json-canon`) failed.
    #[error("canonicalization failed: {0}")]
    Canonicalize(String),
}

/// The compliance framework a report targets. Predicate rendering (SLSA
/// provenance / SPDX SBOM / CRA mapping) lands in fn-157.9; here it only tags
/// the pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ComplianceFramework {
    /// SLSA provenance.
    Slsa,
    /// SPDX software bill of materials.
    Sbom,
    /// EU Cyber Resilience Act obligation mapping.
    Cra,
}

/// A release to classify: an artifact digest, the member that signed it, and its
/// in-band signing KEL position (`None` when the artifact carries no position —
/// which the classifier conservatively rejects).
#[derive(Debug, Clone)]
pub struct ReleaseRecord {
    /// The artifact content digest (e.g. `sha256:<hex>`).
    pub artifact_digest: String,
    /// The signing member's KEL prefix.
    pub signer_prefix: Prefix,
    /// The artifact's in-band signing position (`Auths-Anchor-Seq`), if any.
    pub signed_at: Option<u128>,
}

/// One row of compliance evidence: the signer's authority **at release**.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvidenceRow {
    /// The artifact content digest.
    pub artifact_digest: String,
    /// The signing member's self-certifying identity.
    pub signer: IdentityDID,
    /// The signer's authority at the signing position, by KEL order.
    pub authority_at_release: AuthorityAtSigning,
    /// The artifact's in-band signing position, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_at: Option<u128>,
}

/// A deterministic, offline-verifiable compliance evidence pack.
#[derive(Debug, Clone, Serialize)]
pub struct EvidencePack {
    /// Schema version.
    pub schema_version: u32,
    /// The org whose history this pack covers.
    pub org: IdentityDID,
    /// The reporting period (free-form, e.g. `2026-Q3`).
    pub period: String,
    /// The framework this pack targets.
    pub framework: ComplianceFramework,
    /// The honest witness-diversity verdict — NEVER a bare `non_equivocation`
    /// flag. With only self-run/placeholder witnesses this is `policy_met ==
    /// false` ("single-operator — not yet independent").
    pub equivocation_visibility: HonestyCeiling,
    /// When the pack was generated (injected clock; never `Utc::now()` in domain
    /// code). Two runs with the same inputs and timestamp are byte-identical.
    pub generated_at: DateTime<Utc>,
    /// One row per classified release.
    pub rows: Vec<EvidenceRow>,
}

impl EvidencePack {
    /// Canonicalize with `json-canon` — the byte-exact, reproducible form an
    /// auditor re-derives and the org signs.
    pub fn canonicalize(&self) -> Result<String, ComplianceQueryError> {
        json_canon::to_string(self).map_err(|e| ComplianceQueryError::Canonicalize(e.to_string()))
    }

    /// Render as a canonical in-toto Statement: `subject` = the artifact digests,
    /// `predicate` = this pack. The org DSSE signature over these bytes (and the
    /// SLSA/SBOM/CRA predicate variants) land in fn-157.9.
    pub fn to_intoto_statement(&self) -> Result<String, ComplianceQueryError> {
        let subject: Vec<serde_json::Value> = self
            .rows
            .iter()
            .map(|r| {
                let digest = r
                    .artifact_digest
                    .strip_prefix("sha256:")
                    .unwrap_or(&r.artifact_digest);
                serde_json::json!({
                    "name": r.artifact_digest,
                    "digest": { "sha256": digest },
                })
            })
            .collect();

        let statement = serde_json::json!({
            "_type": "https://in-toto.io/Statement/v1",
            "subject": subject,
            "predicateType": "https://auths.dev/compliance/evidence/v1",
            "predicate": self,
        });

        json_canon::to_string(&statement)
            .map_err(|e| ComplianceQueryError::Canonicalize(e.to_string()))
    }
}

/// Build a compliance evidence pack by classifying each release against the org
/// KEL.
///
/// The releases are the query input — the caller (CLI / a higher layer) supplies
/// the artifacts released in the period; this engine classifies each signer's
/// authority at the release position and embeds the honest witness verdict. It
/// performs no I/O beyond the registry reads `classify_authority_at_signing`
/// already does.
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
    let mut rows = Vec::with_capacity(releases.len());
    for r in releases {
        let authority_at_release =
            classify_authority_at_signing(ctx, org_prefix, &r.signer_prefix, r.signed_at)?;
        let signer = IdentityDID::new_unchecked(format!("did:keri:{}", r.signer_prefix.as_str()));
        rows.push(EvidenceRow {
            artifact_digest: r.artifact_digest.clone(),
            signer,
            authority_at_release,
            signed_at: r.signed_at,
        });
    }

    Ok(EvidencePack {
        schema_version: EVIDENCE_PACK_SCHEMA_VERSION,
        org,
        period: period.into(),
        framework,
        equivocation_visibility: ceiling_for_policy_load(witness_policy),
        generated_at,
        rows,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

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
            org: IdentityDID::new_unchecked("did:keri:EOrg"),
            period: "2026-Q3".into(),
            framework: ComplianceFramework::Slsa,
            equivocation_visibility: single_operator_ceiling(),
            generated_at: fixed_now(),
            rows: vec![
                EvidenceRow {
                    artifact_digest: "sha256:aa".into(),
                    signer: IdentityDID::new_unchecked("did:keri:EAlice"),
                    authority_at_release: AuthorityAtSigning::AuthorizedBeforeRevocation,
                    signed_at: Some(7),
                },
                EvidenceRow {
                    artifact_digest: "sha256:bb".into(),
                    signer: IdentityDID::new_unchecked("did:keri:EBob"),
                    authority_at_release: AuthorityAtSigning::RejectedRevokedPositionUnknown {
                        revoked_at: 12,
                    },
                    signed_at: None,
                },
            ],
        }
    }

    #[test]
    fn canonicalize_is_deterministic() {
        let a = sample_pack().canonicalize().unwrap();
        let b = sample_pack().canonicalize().unwrap();
        assert_eq!(
            a, b,
            "same inputs must produce byte-identical canonical bytes"
        );
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

    #[test]
    fn position_unknown_is_represented_honestly_not_authorized() {
        let json = sample_pack().canonicalize().unwrap();
        assert!(json.contains("rejected_revoked_position_unknown"));
        // The unclassifiable row must NOT be silently rendered as authorized.
        let bob_authorized = json.matches("authorized_before_revocation").count();
        assert_eq!(
            bob_authorized, 1,
            "only Alice is authorized-before-revocation"
        );
    }

    #[test]
    fn intoto_statement_carries_subjects_and_predicate_type() {
        let stmt = sample_pack().to_intoto_statement().unwrap();
        assert!(stmt.contains("https://in-toto.io/Statement/v1"));
        assert!(stmt.contains("https://auths.dev/compliance/evidence/v1"));
        assert!(stmt.contains("\"sha256\":\"aa\""));
        // The predicate carries the authority verdicts.
        assert!(stmt.contains("authority_at_signing"));
    }
}
