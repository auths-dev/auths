//! Framework predicates over a compliance evidence pack.
//!
//! Renders an [`EvidencePack`] into the predicates auditors ask for — SLSA
//! Provenance v1 + a per-release SLSA VSA, an SPDX SBOM (pinned version, exact
//! bytes hashed), or a CRA obligation mapping (with NIST SSDF practice IDs) — each
//! as a single in-toto Statement that rides the **same** DSSE envelope, so one
//! verification path validates any of them.
//!
//! Two invariants travel through unchanged: point-in-time authority (each row's
//! [`AuthorityAtSigning`] is read from the already-classified pack, never
//! re-resolved against HEAD), and the honest witness ceiling
//! (`HonestyCeiling`) — a single-operator pack renders no third-party
//! non-equivocation claim, only the carried ceiling.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::query::{ComplianceFramework, ComplianceQueryError, EvidencePack, EvidenceRow};
use crate::domains::org::audit::AuthorityAtSigning;

/// in-toto Statement type URI.
pub const INTOTO_STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
/// SLSA Provenance v1 predicate type.
pub const SLSA_PROVENANCE_PREDICATE_TYPE: &str = "https://slsa.dev/provenance/v1";
/// SLSA Verification Summary Attestation predicate type.
pub const SLSA_VSA_PREDICATE_TYPE: &str = "https://slsa.dev/verification_summary/v1";
/// The pinned SPDX specification version emitted by the SBOM serializer.
pub const SPDX_VERSION: &str = "SPDX-2.3";
/// The Auths builder id recorded in SLSA provenance `runDetails`.
pub const AUTHS_BUILDER_ID: &str = "https://auths.dev/builder/compliance-query";
/// Aggregate SLSA report predicate type (carries per-artifact provenance + VSAs).
pub const SLSA_REPORT_PREDICATE_TYPE: &str = "https://auths.dev/compliance/slsa/v1";
/// SPDX SBOM report predicate type.
pub const SBOM_REPORT_PREDICATE_TYPE: &str = "https://auths.dev/compliance/sbom/v1";
/// CRA obligation-mapping report predicate type.
pub const CRA_REPORT_PREDICATE_TYPE: &str = "https://auths.dev/compliance/cra/v1";

/// Whether a fact is immutable build-level evidence or a point-in-time status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RowTimeliness {
    /// Build-level provenance — the artifact digest and who produced it never change.
    Timeless,
    /// A verification snapshot (signer not revoked at release) — valid as of the
    /// verification time, not a permanent claim.
    TimeSensitive,
}

/// A `(signer, verifier)` allow-list for the VSA root of trust.
///
/// Mirrors SLSA's pairing rule ("GitHub may sign for GitHub Actions, not for GCP
/// Deploy"). An **unconfigured** list permits any pairing; once a signer has
/// explicit verifiers, only those verifiers may vouch for it, and an unknown signer
/// fails closed.
#[derive(Debug, Clone, Default)]
pub struct SignerVerifierAllowList {
    pairs: BTreeMap<String, BTreeSet<String>>,
}

impl SignerVerifierAllowList {
    /// An empty (unconfigured) allow-list.
    pub fn new() -> Self {
        Self::default()
    }

    /// Permit `verifier` to vouch for `signer`.
    pub fn allow(mut self, signer: impl Into<String>, verifier: impl Into<String>) -> Self {
        self.pairs
            .entry(signer.into())
            .or_default()
            .insert(verifier.into());
        self
    }

    /// Whether `verifier` may vouch for `signer` under this list.
    ///
    /// Args:
    /// * `signer`: The signer DID.
    /// * `verifier`: The verifier id.
    ///
    /// Usage:
    /// ```ignore
    /// assert!(allow_list.is_allowed("did:keri:E…", "auths-compliance"));
    /// ```
    pub fn is_allowed(&self, signer: &str, verifier: &str) -> bool {
        match self.pairs.get(signer) {
            Some(verifiers) => verifiers.contains(verifier),
            None => self.pairs.is_empty(),
        }
    }
}

/// Parameters for the SLSA Verification Summary Attestation.
#[derive(Debug, Clone)]
pub struct VsaParams {
    /// The verifier id recorded in each VSA.
    pub verifier_id: String,
    /// The verification timestamp (injected, never `Utc::now()`).
    pub time_verified: DateTime<Utc>,
    /// The `(signer, verifier)` allow-list enforced in the VSA root of trust.
    pub allow_list: SignerVerifierAllowList,
}

/// A rendered framework report — a single in-toto Statement (the DSSE payload).
#[derive(Debug, Clone)]
pub struct FrameworkReport {
    /// The framework this report targets.
    pub framework: ComplianceFramework,
    /// The report's in-toto predicate type.
    pub predicate_type: String,
    /// The full in-toto Statement (`_type`/`subject`/`predicateType`/`predicate`).
    pub statement: serde_json::Value,
    /// For SBOM reports, the SHA-256 of the exact canonical SPDX document bytes.
    pub sbom_sha256: Option<String>,
}

impl FrameworkReport {
    /// Canonicalize the in-toto Statement (`json-canon`) — the exact DSSE payload.
    pub fn to_intoto_statement(&self) -> Result<String, ComplianceQueryError> {
        json_canon::to_string(&self.statement)
            .map_err(|e| ComplianceQueryError::Canonicalize(e.to_string()))
    }
}

/// Render the framework predicate selected by `pack.framework`.
///
/// Point-in-time authority is preserved (each row's [`AuthorityAtSigning`] is read
/// from the pack, never re-resolved). The honest [`HonestyCeiling`] is carried, so a
/// single-operator pack emits no third-party non-equivocation claim.
///
/// Args:
/// * `pack`: The classified evidence pack.
/// * `vsa`: VSA verifier id, injected timestamp, and the signer/verifier allow-list.
///
/// Usage:
/// ```ignore
/// let report = build_framework_report(&pack, &vsa_params)?;
/// let envelope = sign_framework_report(&ctx, org_did, &alias, curve, &report)?;
/// ```
pub fn build_framework_report(
    pack: &EvidencePack,
    vsa: &VsaParams,
) -> Result<FrameworkReport, ComplianceQueryError> {
    match pack.framework {
        ComplianceFramework::Slsa => Ok(build_slsa(pack, vsa)),
        ComplianceFramework::Sbom => Ok(build_sbom(pack)),
        ComplianceFramework::Cra => Ok(build_cra(pack)),
    }
}

/// Compute the SHA-256 of the canonical bytes of an SPDX document (`sha256:<hex>`).
///
/// Anchoring this exact-bytes hash means a regenerated SBOM that differs by even one
/// byte is detected rather than silently accepted.
pub fn sbom_document_sha256(document: &serde_json::Value) -> Result<String, ComplianceQueryError> {
    let bytes = json_canon::to_vec(document)
        .map_err(|e| ComplianceQueryError::Canonicalize(e.to_string()))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(&bytes))))
}

// ── in-toto subject ──────────────────────────────────────────────────────────

/// in-toto `subject` entries for every row's artifact digest.
fn subjects(rows: &[EvidenceRow]) -> Vec<serde_json::Value> {
    rows.iter()
        .map(|r| {
            let digest = r
                .artifact_digest
                .strip_prefix("sha256:")
                .unwrap_or(&r.artifact_digest);
            serde_json::json!({ "name": r.artifact_digest, "digest": { "sha256": digest } })
        })
        .collect()
}

fn statement(
    rows: &[EvidenceRow],
    predicate_type: &str,
    predicate: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "_type": INTOTO_STATEMENT_TYPE,
        "subject": subjects(rows),
        "predicateType": predicate_type,
        "predicate": predicate,
    })
}

// ── SLSA ─────────────────────────────────────────────────────────────────────

/// Whether an authority verdict authorizes the release (the VSA `PASSED` axis).
fn authority_authorized(authority: &AuthorityAtSigning) -> bool {
    matches!(authority, AuthorityAtSigning::AuthorizedBeforeRevocation)
}

fn slsa_provenance(row: &EvidenceRow) -> serde_json::Value {
    let digest = row
        .artifact_digest
        .strip_prefix("sha256:")
        .unwrap_or(&row.artifact_digest);
    serde_json::json!({
        "predicateType": SLSA_PROVENANCE_PREDICATE_TYPE,
        "subject": [{ "name": row.artifact_digest, "digest": { "sha256": digest } }],
        "timeliness": RowTimeliness::Timeless,
        "predicate": {
            "buildDefinition": {
                "buildType": "https://auths.dev/buildtypes/signed-release/v1",
                "externalParameters": { "artifact": row.artifact_digest },
                "internalParameters": { "signedAtSeq": row.signed_at.map(|s| s.to_string()) },
                "resolvedDependencies": []
            },
            "runDetails": {
                "builder": { "id": AUTHS_BUILDER_ID },
                "metadata": { "invocationId": row.signer.as_str() }
            }
        }
    })
}

fn slsa_vsa(row: &EvidenceRow, vsa: &VsaParams) -> serde_json::Value {
    let allowed = vsa
        .allow_list
        .is_allowed(row.signer.as_str(), &vsa.verifier_id);
    let passed = authority_authorized(&row.authority_at_release) && allowed;
    serde_json::json!({
        "predicateType": SLSA_VSA_PREDICATE_TYPE,
        "verifier": { "id": vsa.verifier_id },
        "timeVerified": vsa.time_verified,
        "resourceUri": row.artifact_digest,
        "signer": row.signer.as_str(),
        "policy": { "uri": "https://auths.dev/compliance/policy/authority-at-release/v1" },
        "verificationResult": if passed { "PASSED" } else { "FAILED" },
        "verifiedLevels": ["AUTHS_AUTHORITY_AT_RELEASE"],
        "signerVerifierAllowed": allowed,
        "authorityAtRelease": row.authority_at_release,
        "timeliness": RowTimeliness::TimeSensitive,
    })
}

fn build_slsa(pack: &EvidencePack, vsa: &VsaParams) -> FrameworkReport {
    let provenance: Vec<serde_json::Value> = pack.rows.iter().map(slsa_provenance).collect();
    let verification_summaries: Vec<serde_json::Value> =
        pack.rows.iter().map(|r| slsa_vsa(r, vsa)).collect();
    let predicate = serde_json::json!({
        "provenance": provenance,
        "verificationSummaries": verification_summaries,
        "equivocationVisibility": pack.equivocation_visibility,
    });
    FrameworkReport {
        framework: ComplianceFramework::Slsa,
        predicate_type: SLSA_REPORT_PREDICATE_TYPE.to_string(),
        statement: statement(&pack.rows, SLSA_REPORT_PREDICATE_TYPE, predicate),
        sbom_sha256: None,
    }
}

// ── SPDX SBOM ────────────────────────────────────────────────────────────────

fn spdx_document(pack: &EvidencePack) -> serde_json::Value {
    let packages: Vec<serde_json::Value> = pack
        .rows
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let digest = r
                .artifact_digest
                .strip_prefix("sha256:")
                .unwrap_or(&r.artifact_digest);
            serde_json::json!({
                "SPDXID": format!("SPDXRef-Package-{i}"),
                "name": r.artifact_digest,
                "downloadLocation": "NOASSERTION",
                "checksums": [{ "algorithm": "SHA256", "checksumValue": digest }],
                "supplier": format!("Organization: {}", r.signer.as_str()),
            })
        })
        .collect();
    serde_json::json!({
        "spdxVersion": SPDX_VERSION,
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": format!("auths-compliance-{}", pack.period),
        "documentNamespace": format!("https://auths.dev/spdx/{}", pack.period),
        "creationInfo": { "creators": [format!("Tool: {AUTHS_BUILDER_ID}")] },
        "packages": packages,
    })
}

fn build_sbom(pack: &EvidencePack) -> FrameworkReport {
    let document = spdx_document(pack);
    // Hash the exact canonical document bytes so a regenerated SBOM is detectable.
    let sha = sbom_document_sha256(&document).ok();
    let predicate = serde_json::json!({
        "spdxVersion": SPDX_VERSION,
        "document": document,
        "documentSha256": sha,
        "equivocationVisibility": pack.equivocation_visibility,
    });
    FrameworkReport {
        framework: ComplianceFramework::Sbom,
        predicate_type: SBOM_REPORT_PREDICATE_TYPE.to_string(),
        statement: statement(&pack.rows, SBOM_REPORT_PREDICATE_TYPE, predicate),
        sbom_sha256: sha,
    }
}

// ── CRA ──────────────────────────────────────────────────────────────────────

/// One CRA obligation mapped to the pack's evidence and NIST SSDF practice IDs.
#[derive(Debug, Clone, Serialize)]
struct CraObligation {
    id: &'static str,
    description: &'static str,
    ssdf_practices: &'static [&'static str],
    satisfied_by: &'static str,
    status: &'static str,
}

/// The CRA obligation map this evidence pack speaks to. Documentation + a typed
/// report shape, not a new trust primitive.
const CRA_OBLIGATIONS: &[CraObligation] = &[
    CraObligation {
        id: "CRA-Annex-I-2(1)",
        description: "Identify and document components (SBOM).",
        ssdf_practices: &["PS.3.2", "PW.4.1"],
        satisfied_by: "sbom",
        status: "covered",
    },
    CraObligation {
        id: "CRA-Annex-I-2(3)",
        description: "Apply security updates / off-board compromised signers.",
        ssdf_practices: &["RV.1.1", "PO.3.2"],
        satisfied_by: "authority_at_release",
        status: "covered",
    },
    CraObligation {
        id: "CRA-Annex-I-1(2)(j)",
        description: "Record and verify the provenance of releases.",
        ssdf_practices: &["PS.3.1", "PS.2.1"],
        satisfied_by: "slsa_provenance",
        status: "covered",
    },
];

fn build_cra(pack: &EvidencePack) -> FrameworkReport {
    let predicate = serde_json::json!({
        "obligations": CRA_OBLIGATIONS,
        "releasesAssessed": pack.rows.len(),
        "equivocationVisibility": pack.equivocation_visibility,
        "note": "Maps the evidence pack to CRA obligations and NIST SSDF practices; \
                 it is a reporting mapping, not a new trust primitive.",
    });
    FrameworkReport {
        framework: ComplianceFramework::Cra,
        predicate_type: CRA_REPORT_PREDICATE_TYPE.to_string(),
        statement: statement(&pack.rows, CRA_REPORT_PREDICATE_TYPE, predicate),
        sbom_sha256: None,
    }
}
