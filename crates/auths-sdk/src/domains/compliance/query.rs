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
//! produce byte-identical output (an auditor can re-derive it). An **offline**
//! pack ([`build_offline_evidence_pack`]) additionally embeds the org's KEL
//! material as an [`AirGappedOrgBundle`] plus, per row, the transparency-log
//! inclusion (and consistency) proof, so each row verifies with **zero network**
//! via [`verify_evidence_pack_offline`]. The org DSSE signature over the in-toto
//! statement lives in [`crate::domains::compliance::dsse`].

use std::path::Path;

use auths_id::keri::types::Prefix;
use auths_transparency::{
    ConsistencyProof, HonestyCeiling, InclusionProof, MerkleHash, SignedCheckpoint, WitnessPolicy,
    WitnessPolicyError, ceiling_for_policy_load,
};
use auths_verifier::IdentityDID;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::context::AuthsContext;
use crate::domains::org::audit::{AuthorityAtSigning, classify_authority_at_signing};
use crate::domains::org::bundle::{AirGappedOrgBundle, build_org_bundle};
use crate::domains::org::error::OrgError;
use crate::domains::org::offline_verify::{classify_authority_in_bundle, verify_org_bundle};

/// The current evidence-pack schema version.
pub const EVIDENCE_PACK_SCHEMA_VERSION: u32 = 1;

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

/// The compliance framework a report targets. Each variant selects the
/// predicate [`crate::domains::compliance::frameworks::build_framework_report`]
/// renders (SLSA provenance + VSA / SPDX SBOM / CRA→SSDF / SOC 2 TSC / ISO
/// 27001 Annex-A); here it only tags the pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ComplianceFramework {
    /// SLSA provenance.
    Slsa,
    /// SPDX software bill of materials.
    Sbom,
    /// EU Cyber Resilience Act obligation mapping.
    Cra,
    /// SOC 2 Trust Services Criteria (TSC) control mapping.
    Soc2,
    /// ISO/IEC 27001:2022 Annex-A control mapping.
    Iso27001,
}

/// The transparency-log evidence that proves an artifact's entry is in the log,
/// bundled so a row verifies offline.
///
/// `inclusion_proof` proves the `leaf_hash` is in the tree at size N (root
/// `inclusion_proof.root`). When the inclusion was taken at a tree size **older**
/// than the embedded `signed_checkpoint`, a `consistency_proof` (N→M) proves the
/// older root is a prefix of the checkpoint root. With no consistency proof the
/// inclusion must be **against** the checkpoint (same root and size).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransparencyInclusion {
    /// The artifact's transparency-log leaf hash (the value `inclusion_proof` proves).
    pub leaf_hash: MerkleHash,
    /// Inclusion proof for `leaf_hash` at tree size `inclusion_proof.size`.
    pub inclusion_proof: InclusionProof,
    /// The signed checkpoint the inclusion is anchored to (directly, or via the
    /// consistency proof). Its signature trust requires a **pinned log key**
    /// ([`auths_transparency::verify_checkpoint_signature`]) — a separate axis from
    /// this offline Merkle check.
    pub signed_checkpoint: SignedCheckpoint,
    /// Consistency proof from the inclusion's tree size to the checkpoint's, present
    /// only when the inclusion was taken at an earlier size than the checkpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consistency_proof: Option<ConsistencyProof>,
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

/// One row of compliance evidence: the signer's authority **at release**.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceRow {
    /// The artifact content digest.
    pub artifact_digest: String,
    /// The signing member's self-certifying identity.
    pub signer: IdentityDID,
    /// The signer's authority at the signing position, by KEL order.
    pub authority_at_release: AuthorityAtSigning,
    /// The artifact's in-band signing position, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_at: Option<u128>,
    /// Transparency-log inclusion evidence, when supplied — lets the row prove the
    /// artifact's log membership offline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transparency: Option<TransparencyInclusion>,
}

/// A deterministic, offline-verifiable compliance evidence pack.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// The embedded, URL-free KEL material (org + member KELs + off-boarding
    /// records + pinned root) that makes authority re-derivable offline. `None`
    /// for a non-offline pack ([`build_evidence_pack`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_bundle: Option<AirGappedOrgBundle>,
}

impl EvidencePack {
    /// Canonicalize with `json-canon` — the byte-exact, reproducible form an
    /// auditor re-derives and the org signs.
    pub fn canonicalize(&self) -> Result<String, ComplianceQueryError> {
        json_canon::to_string(self).map_err(|e| ComplianceQueryError::Canonicalize(e.to_string()))
    }

    /// Parse a pack back from its canonical JSON form. Typed identifiers fail
    /// closed on malformed input.
    pub fn from_json(json: &str) -> Result<Self, ComplianceQueryError> {
        serde_json::from_str(json).map_err(|e| ComplianceQueryError::Decode(e.to_string()))
    }

    /// Render as a canonical in-toto Statement: `subject` = the artifact digests,
    /// `predicate` = this pack. The org DSSE signature over these bytes lives in
    /// [`crate::domains::compliance::dsse::sign_evidence_pack`]; the SLSA/SBOM/CRA
    /// predicate variants land in fn-157.9.
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
        let signer = IdentityDID::new_unchecked(format!("did:keri:{}", r.signer_prefix.as_str()));
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
/// [`AirGappedOrgBundle`] (org KEL + every member KEL + off-boarding records +
/// pinned root), so [`verify_evidence_pack_offline`] can re-derive every row's
/// authority and check each row's transparency proof with **zero network**.
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

/// The offline-verification verdict for one evidence row.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RowVerdict {
    /// The artifact this row covers.
    pub artifact_digest: String,
    /// The row's signer.
    pub signer: IdentityDID,
    /// The authority recorded in the row.
    pub authority_at_release: AuthorityAtSigning,
    /// Whether re-deriving authority from the embedded KEL matches the row's
    /// recorded verdict (a tampered row flips this to `false`).
    pub authority_consistent: bool,
    /// Whether the row's transparency inclusion/consistency proof verified, or
    /// `None` when the row carries no transparency evidence.
    pub transparency_verified: Option<bool>,
}

/// Verify the transparency inclusion (and consistency) of one row, offline.
fn verify_transparency_inclusion(t: &TransparencyInclusion) -> Result<(), ComplianceQueryError> {
    t.inclusion_proof.verify(&t.leaf_hash).map_err(|e| {
        ComplianceQueryError::OfflineVerification(format!("inclusion proof did not verify: {e}"))
    })?;

    let checkpoint_root = t.signed_checkpoint.checkpoint.root;
    let checkpoint_size = t.signed_checkpoint.checkpoint.size;

    match &t.consistency_proof {
        Some(c) => {
            if c.old_root != t.inclusion_proof.root || c.old_size != t.inclusion_proof.size {
                return Err(ComplianceQueryError::OfflineVerification(
                    "consistency proof old root/size does not match the inclusion proof".into(),
                ));
            }
            if c.new_root != checkpoint_root || c.new_size != checkpoint_size {
                return Err(ComplianceQueryError::OfflineVerification(
                    "consistency proof new root/size does not match the signed checkpoint".into(),
                ));
            }
            c.verify().map_err(|e| {
                ComplianceQueryError::OfflineVerification(format!(
                    "consistency proof did not verify: {e}"
                ))
            })?;
        }
        None => {
            if t.inclusion_proof.root != checkpoint_root
                || t.inclusion_proof.size != checkpoint_size
            {
                return Err(ComplianceQueryError::OfflineVerification(
                    "inclusion proof is not against the signed checkpoint and no consistency proof was provided".into(),
                ));
            }
        }
    }
    Ok(())
}

/// Verify an offline evidence pack with **zero network**.
///
/// Checks the embedded [`AirGappedOrgBundle`] integrity (every event self-addresses),
/// confirms the org is a pinned root, flags KEL duplicity, then for each row
/// re-derives authority-at-release from the embedded KEL (tamper check) and verifies
/// any transparency inclusion/consistency proof. The checkpoint **signature** trust
/// (that the log operator signed the root) is a separate axis requiring a pinned log
/// key ([`auths_transparency::verify_checkpoint_signature`]); this function proves
/// the Merkle membership, not the log operator's identity.
///
/// Args:
/// * `pack`: The pack to verify (must have been built by [`build_offline_evidence_pack`]).
/// * `pinned_roots`: The verifier's pinned trust roots.
///
/// Usage:
/// ```ignore
/// let verdicts = verify_evidence_pack_offline(&pack, &roots)?;
/// assert!(verdicts.iter().all(|v| v.authority_consistent));
/// ```
pub fn verify_evidence_pack_offline(
    pack: &EvidencePack,
    pinned_roots: &[IdentityDID],
) -> Result<Vec<RowVerdict>, ComplianceQueryError> {
    let bundle = pack.org_bundle.as_ref().ok_or_else(|| {
        ComplianceQueryError::OfflineVerification(
            "pack carries no embedded org bundle — not an offline-verifiable pack".into(),
        )
    })?;

    let report = verify_org_bundle(bundle, pinned_roots, None)
        .map_err(|e| ComplianceQueryError::OfflineVerification(e.to_string()))?;
    if !report.root_pinned {
        return Err(ComplianceQueryError::OfflineVerification(format!(
            "org {} is not in the pinned trust roots",
            bundle.org_did.as_str()
        )));
    }
    if report.duplicity_detected {
        return Err(ComplianceQueryError::OfflineVerification(
            "org KEL shows duplicity (same-seq divergent SAIDs)".into(),
        ));
    }

    let mut verdicts = Vec::with_capacity(pack.rows.len());
    for row in &pack.rows {
        let signer_prefix = Prefix::new_unchecked(
            row.signer
                .as_str()
                .strip_prefix("did:keri:")
                .unwrap_or(row.signer.as_str())
                .to_string(),
        );
        let rederived = classify_authority_in_bundle(bundle, &signer_prefix, row.signed_at);
        let authority_consistent = rederived == row.authority_at_release;

        let transparency_verified = row
            .transparency
            .as_ref()
            .map(|t| verify_transparency_inclusion(t).is_ok());

        verdicts.push(RowVerdict {
            artifact_digest: row.artifact_digest.clone(),
            signer: row.signer.clone(),
            authority_at_release: row.authority_at_release.clone(),
            authority_consistent,
            transparency_verified,
        });
    }
    Ok(verdicts)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use auths_transparency::types::LogOrigin;

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
                    transparency: None,
                },
                EvidenceRow {
                    artifact_digest: "sha256:bb".into(),
                    signer: IdentityDID::new_unchecked("did:keri:EBob"),
                    authority_at_release: AuthorityAtSigning::RejectedRevokedPositionUnknown {
                        revoked_at: 12,
                    },
                    signed_at: None,
                    transparency: None,
                },
            ],
            org_bundle: None,
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
    fn pack_round_trips_through_json() {
        let pack = sample_pack();
        let json = pack.canonicalize().unwrap();
        let back = EvidencePack::from_json(&json).unwrap();
        assert_eq!(
            json,
            back.canonicalize().unwrap(),
            "canonical JSON must round-trip byte-identically"
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

    fn signed_checkpoint_at(size: u64, root: MerkleHash) -> SignedCheckpoint {
        use auths_transparency::checkpoint::Checkpoint;
        use auths_verifier::{Ed25519PublicKey, Ed25519Signature};
        SignedCheckpoint {
            checkpoint: Checkpoint {
                origin: LogOrigin::new("auths.dev/log").unwrap(),
                size,
                root,
                timestamp: fixed_now(),
            },
            log_signature: Ed25519Signature::from_bytes([0u8; 64]),
            log_public_key: Ed25519PublicKey::from_bytes([0u8; 32]),
            witnesses: vec![],
            ecdsa_checkpoint_signature: None,
            ecdsa_checkpoint_key: None,
        }
    }

    #[test]
    fn transparency_inclusion_against_checkpoint_verifies() {
        use auths_transparency::merkle::{hash_children, hash_leaf};
        let a = hash_leaf(b"artifact-a");
        let b = hash_leaf(b"artifact-b");
        let root = hash_children(&a, &b);

        let t = TransparencyInclusion {
            leaf_hash: a,
            inclusion_proof: InclusionProof {
                index: 0,
                size: 2,
                root,
                hashes: vec![b],
            },
            signed_checkpoint: signed_checkpoint_at(2, root),
            consistency_proof: None,
        };
        verify_transparency_inclusion(&t).expect("inclusion against the checkpoint verifies");
    }

    #[test]
    fn transparency_inclusion_mismatched_checkpoint_fails() {
        use auths_transparency::merkle::{hash_children, hash_leaf};
        let a = hash_leaf(b"artifact-a");
        let b = hash_leaf(b"artifact-b");
        let root = hash_children(&a, &b);

        let t = TransparencyInclusion {
            leaf_hash: a,
            inclusion_proof: InclusionProof {
                index: 0,
                size: 2,
                root,
                hashes: vec![b],
            },
            // A checkpoint over a DIFFERENT root with no consistency proof must fail.
            signed_checkpoint: signed_checkpoint_at(2, MerkleHash::from_bytes([0x99; 32])),
            consistency_proof: None,
        };
        assert!(
            verify_transparency_inclusion(&t).is_err(),
            "inclusion not anchored to the checkpoint must fail closed"
        );
    }
}
