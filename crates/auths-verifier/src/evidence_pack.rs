//! Offline verification of a compliance evidence pack — zero network, pure
//! function of the pack's bytes.
//!
//! An evidence pack is the org's append-only history rendered as a
//! deterministic, offline-verifiable document: one row per release, each
//! answering "who signed this artifact, and were they authorized **at
//! release time**?" by KEL position, never wall-clock. An **offline** pack
//! embeds the org's KEL material as an
//! [`AirGappedOrgBundle`](crate::org_bundle::AirGappedOrgBundle) plus, per
//! row, the transparency-log inclusion (and consistency) proof.
//!
//! This module owns the pack's wire types and [`verify_evidence_pack_offline`]
//! — the verification half. The *build* half (which classifies releases
//! against a live registry) lives in `auths-sdk` and re-exports these types,
//! so a CI gate, audit tool, or **browser** (via the WASM exports) replays
//! the same verdict from the pack file alone.

use auths_keri::Prefix;
use auths_keri::witness::independence::HonestyCeiling;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::org_bundle::{
    AirGappedOrgBundle, AuthorityAtSigning, classify_authority_in_bundle, verify_org_bundle,
};
use crate::tlog::{ConsistencyProof, InclusionProof, MerkleHash, SignedCheckpoint, hash_leaf};
use crate::types::IdentityDID;

/// The current evidence-pack schema version.
pub const EVIDENCE_PACK_SCHEMA_VERSION: u32 = 1;

/// Maximum accepted JSON input for the JSON/WASM surface (16 MiB) — a pack
/// embeds whole KELs and Merkle proofs, so the ceiling matches the org-bundle
/// contract's.
pub const MAX_PACK_JSON_BYTES: usize = 16 * 1024 * 1024;

/// A typed failure parsing or verifying a compliance evidence pack.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EvidencePackError {
    /// Canonical serialization (`json-canon`) failed.
    #[error("canonicalization failed: {0}")]
    Canonicalize(String),
    /// The pack (or a JSON input) could not be decoded.
    #[error("decode failed: {0}")]
    Decode(String),
    /// Offline pack verification failed (tampered KEL, unpinned root, or a
    /// transparency proof that did not check out).
    #[error("offline verification failed: {0}")]
    OfflineVerification(String),
}

impl auths_crypto::AuthsErrorInfo for EvidencePackError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::Canonicalize(_) => "AUTHS-E2301",
            Self::Decode(_) => "AUTHS-E2302",
            Self::OfflineVerification(_) => "AUTHS-E2303",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::Canonicalize(_) | Self::Decode(_) => Some(
                "The file is not a valid evidence pack; re-export it with `auths compliance report`",
            ),
            Self::OfflineVerification(_) => Some(
                "The pack failed offline verification; obtain a fresh, untampered pack from the org",
            ),
        }
    }
}

/// The compliance framework a report targets. Each variant selects the
/// predicate the report builder renders (SLSA provenance + VSA / SPDX SBOM /
/// CRA→SSDF / SOC 2 TSC / ISO 27001 Annex-A); here it only tags the pack.
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
    /// The artifact's transparency-log leaf hash (the value `inclusion_proof`
    /// proves). For a release row the leaf data is the canonical artifact
    /// digest string (`sha256:<hex>`), so `leaf_hash =
    /// hash_leaf(artifact_digest)` — row verification re-derives and compares
    /// it, binding the proof to *this* artifact rather than to whatever leaf
    /// the prover chose to embed.
    pub leaf_hash: MerkleHash,
    /// Inclusion proof for `leaf_hash` at tree size `inclusion_proof.size`.
    pub inclusion_proof: InclusionProof,
    /// The signed checkpoint the inclusion is anchored to (directly, or via the
    /// consistency proof). Its signature trust requires a **pinned log key** —
    /// a separate axis from this offline Merkle check.
    pub signed_checkpoint: SignedCheckpoint,
    /// Consistency proof from the inclusion's tree size to the checkpoint's, present
    /// only when the inclusion was taken at an earlier size than the checkpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consistency_proof: Option<ConsistencyProof>,
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
    /// for a non-offline pack.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_bundle: Option<AirGappedOrgBundle>,
}

impl EvidencePack {
    /// Canonicalize with `json-canon` — the byte-exact, reproducible form an
    /// auditor re-derives and the org signs.
    pub fn canonicalize(&self) -> Result<String, EvidencePackError> {
        json_canon::to_string(self).map_err(|e| EvidencePackError::Canonicalize(e.to_string()))
    }

    /// Parse a pack back from its canonical JSON form. Typed identifiers fail
    /// closed on malformed input.
    pub fn from_json(json: &str) -> Result<Self, EvidencePackError> {
        serde_json::from_str(json).map_err(|e| EvidencePackError::Decode(e.to_string()))
    }

    /// Render as a canonical in-toto Statement: `subject` = the artifact digests,
    /// `predicate` = this pack. The org DSSE signature over these bytes lives in
    /// the SDK's compliance DSSE module.
    pub fn to_intoto_statement(&self) -> Result<String, EvidencePackError> {
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
            .map_err(|e| EvidencePackError::Canonicalize(e.to_string()))
    }
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
    /// Whether the row's transparency evidence verified: the leaf hash
    /// re-derives from the row's artifact digest AND the inclusion/consistency
    /// proof checks out. `None` when the row carries no transparency evidence.
    pub transparency_verified: Option<bool>,
}

/// Verify the transparency inclusion (and consistency) of one row, offline.
pub fn verify_transparency_inclusion(t: &TransparencyInclusion) -> Result<(), EvidencePackError> {
    t.inclusion_proof.verify(&t.leaf_hash).map_err(|e| {
        EvidencePackError::OfflineVerification(format!("inclusion proof did not verify: {e}"))
    })?;

    let checkpoint_root = t.signed_checkpoint.checkpoint.root;
    let checkpoint_size = t.signed_checkpoint.checkpoint.size;

    match &t.consistency_proof {
        Some(c) => {
            if c.old_root != t.inclusion_proof.root || c.old_size != t.inclusion_proof.size {
                return Err(EvidencePackError::OfflineVerification(
                    "consistency proof old root/size does not match the inclusion proof".into(),
                ));
            }
            if c.new_root != checkpoint_root || c.new_size != checkpoint_size {
                return Err(EvidencePackError::OfflineVerification(
                    "consistency proof new root/size does not match the signed checkpoint".into(),
                ));
            }
            c.verify().map_err(|e| {
                EvidencePackError::OfflineVerification(format!(
                    "consistency proof did not verify: {e}"
                ))
            })?;
        }
        None => {
            if t.inclusion_proof.root != checkpoint_root
                || t.inclusion_proof.size != checkpoint_size
            {
                return Err(EvidencePackError::OfflineVerification(
                    "inclusion proof is not against the signed checkpoint and no consistency proof was provided".into(),
                ));
            }
        }
    }
    Ok(())
}

/// Verify an offline evidence pack with **zero network**.
///
/// Checks the embedded [`AirGappedOrgBundle`] integrity (every event
/// self-addresses AND is signed by the controlling key-state), confirms the org
/// is a pinned root, flags KEL duplicity, then for each row re-derives
/// authority-at-release from the embedded KEL (tamper check) and verifies any
/// transparency inclusion/consistency proof. The checkpoint **signature** trust
/// (that the log operator signed the root) is a separate axis requiring a
/// pinned log key; this function proves the Merkle membership, not the log
/// operator's identity.
///
/// Args:
/// * `pack`: The pack to verify (must embed an org bundle).
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
) -> Result<Vec<RowVerdict>, EvidencePackError> {
    let bundle = pack.org_bundle.as_ref().ok_or_else(|| {
        EvidencePackError::OfflineVerification(
            "pack carries no embedded org bundle — not an offline-verifiable pack".into(),
        )
    })?;

    let report = verify_org_bundle(bundle, pinned_roots, None)
        .map_err(|e| EvidencePackError::OfflineVerification(e.to_string()))?;
    if !report.root_pinned {
        return Err(EvidencePackError::OfflineVerification(format!(
            "org {} is not in the pinned trust roots",
            bundle.org_did.as_str()
        )));
    }
    if report.duplicity_detected {
        return Err(EvidencePackError::OfflineVerification(
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

        // The proof must be FOR this row's artifact: the leaf is the canonical
        // digest string, so a valid proof over some other leaf is a mismatch,
        // not evidence.
        let transparency_verified = row.transparency.as_ref().map(|t| {
            t.leaf_hash == hash_leaf(row.artifact_digest.as_bytes())
                && verify_transparency_inclusion(t).is_ok()
        });

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

// ── JSON contract (the WASM/FFI-facing form) ───────────────────────────────

/// The tagged verdict envelope for [`verify_evidence_pack_offline_json`].
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
enum PackVerdictJson {
    /// Verification ran to completion; one verdict per evidence row.
    #[serde(rename = "verdicts")]
    Verdicts {
        /// Per-row offline verdicts, in pack order.
        rows: Vec<RowVerdict>,
    },
    /// Verification failed closed (tampered pack, unpinned root, bad input).
    #[serde(rename = "error")]
    Error {
        /// The stable `AUTHS-Exxxx` code.
        code: String,
        /// Human-readable detail.
        message: String,
    },
}

/// A last-resort verdict used only if envelope serialization itself fails.
const SERIALIZE_FALLBACK: &str =
    r#"{"kind":"error","code":"AUTHS-E2301","message":"verdict serialization failed"}"#;

/// Verify an offline evidence pack from its JSON wire forms — the
/// string-in/string-out contract the WASM surface exposes.
///
/// Panic-free and synchronous: malformed or oversize input returns a tagged
/// `error` envelope, never an exception. The verdict is a discriminated union
/// (`kind`: `"verdicts"` | `"error"`), never a bare bool.
///
/// Args:
/// * `pack_json`: The [`EvidencePack`] JSON (the `.evidence` file).
/// * `pinned_roots_json`: JSON array of the verifier's pinned `did:keri:` roots.
///
/// Usage:
/// ```ignore
/// let verdict = verify_evidence_pack_offline_json(&pack, r#"["did:keri:EOrg"]"#);
/// ```
pub fn verify_evidence_pack_offline_json(pack_json: &str, pinned_roots_json: &str) -> String {
    use auths_crypto::AuthsErrorInfo;
    let envelope = match verify_pack_json_inner(pack_json, pinned_roots_json) {
        Ok(rows) => PackVerdictJson::Verdicts { rows },
        Err(e) => PackVerdictJson::Error {
            code: e.error_code().to_string(),
            message: e.to_string(),
        },
    };
    serde_json::to_string(&envelope).unwrap_or_else(|_| SERIALIZE_FALLBACK.to_string())
}

fn verify_pack_json_inner(
    pack_json: &str,
    pinned_roots_json: &str,
) -> Result<Vec<RowVerdict>, EvidencePackError> {
    if pack_json.len() > MAX_PACK_JSON_BYTES {
        return Err(EvidencePackError::Decode(format!(
            "pack JSON too large: {} bytes, max {}",
            pack_json.len(),
            MAX_PACK_JSON_BYTES
        )));
    }
    let pack = EvidencePack::from_json(pack_json)?;
    let pinned_roots: Vec<IdentityDID> = serde_json::from_str(pinned_roots_json)
        .map_err(|e| EvidencePackError::Decode(format!("pinned roots: {e}")))?;
    verify_evidence_pack_offline(&pack, &pinned_roots)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::core::{Ed25519PublicKey, Ed25519Signature};
    use crate::tlog::merkle::{hash_children, hash_leaf};
    use crate::tlog::{Checkpoint, LogOrigin};
    use auths_keri::witness::independence::EquivocationDetection;

    fn fixed_now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-06-08T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn single_operator_ceiling() -> HonestyCeiling {
        // The reality today: no independent commons → not policy_met.
        HonestyCeiling {
            distinct_operators: 1,
            distinct_organizations: 1,
            distinct_jurisdictions: 1,
            distinct_infra_zones: 1,
            policy_met: false,
            equivocation: EquivocationDetection::Sampled,
            shortfalls: vec!["no independent witness commons".into()],
            label: "single-operator — not yet independent".into(),
        }
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

    #[test]
    fn pack_without_bundle_fails_offline_verification_closed() {
        let pack = sample_pack();
        let roots = vec![IdentityDID::new_unchecked("did:keri:EOrg")];
        let err = verify_evidence_pack_offline(&pack, &roots).unwrap_err();
        assert!(err.to_string().contains("no embedded org bundle"));
    }

    #[test]
    fn pack_json_contract_reports_errors_as_tagged_envelopes() {
        let verdict = verify_evidence_pack_offline_json("not json", "[]");
        let v: serde_json::Value = serde_json::from_str(&verdict).unwrap();
        assert_eq!(v["kind"], "error");
        assert_eq!(v["code"], "AUTHS-E2302");
    }

    fn signed_checkpoint_at(size: u64, root: MerkleHash) -> SignedCheckpoint {
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
