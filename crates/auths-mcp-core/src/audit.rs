//! The independent spend-audit data model (M2 — "the moat").
//!
//! The contract an offline `auths verify-spend` reads to re-derive an agent's true spend
//! WITHOUT trusting the operator: an append-only **spend log** of per-call records the gateway
//! persists, plus the typed [`AuditVerdict`] the audit returns.
//!
//! This module is the pure DATA layer — no I/O, no crypto, no gateway dependency — so the
//! gateway (which writes the log) and the offline auditor (which reads + verifies it) share one
//! definition. Verification itself replays each record's signed proof(s) through the SAME
//! `auths_verifier::verify_commit_against_kel_scoped` the live gate uses, and sums the
//! AGENT-SIGNED settled costs (B1) — never the operator's counter (M2 decision: A + B1).
//!
//! NOTE (overnight recon finding): the LIVE wrap path does not yet sign a per-call proof — it
//! does a boolean scope check + budget enforcement (`proxy.rs::call_tool`). PRODUCING these
//! records on the live wire is a separate MUST-REVIEW change (wiring `chain.rs` signing into the
//! live path); the audit is first built over the hermetic gate, which already signs + verifies
//! a real commit per call. This data model is path-agnostic.

use crate::receipt::Receipt;
use serde::{Deserialize, Serialize};
use std::fmt;

/// One append-only record in the spend log — everything an offline audit needs to re-verify
/// ONE brokered call without the operator's cooperation. Persisted as one JSON object per line
/// (JSONL) under `<repo>/spend-log/<delegation>.jsonl`.
///
/// `call_commit` / `settlement_commit` are the RAW signed git-commit bytes (not just the SHA),
/// so the auditor replays them through `verify_commit_against_kel_scoped` offline rather than
/// trusting the receipt's `proof_ref`. `rail_response` is the rail's raw response, so the audit
/// re-extracts the cost via `rail::extract` and cross-checks it against the SIGNED cost.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendLogRecord {
    /// Raw bytes of the agent's signed `tools/call` proof commit (A) — retained so the audit
    /// re-verifies it offline rather than trusting the receipt's `proof_ref` SHA.
    pub call_commit: Vec<u8>,
    /// The per-call receipt — the operator's CLAIM. An untrusted hint, cross-checked against the
    /// signed material; never an input to the audited total.
    pub receipt: Receipt,
    /// The payment rail this call settled on (`None` for a non-metered call).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rail: Option<String>,
    /// The rail's RAW response bytes, retained so the audit re-extracts the cost via
    /// `rail::extract` and cross-checks it against the signed settlement (`None` if non-metered).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rail_response: Option<Vec<u8>>,
    /// (B1) Raw bytes of the agent's signed SETTLEMENT commit anchoring the actual cost
    /// `{call proof_ref, rail, actual_cents, rail_ref, cumulative}`. `None` for a non-metered
    /// call. The audit sums the cost SIGNED here, never the receipt's claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement_commit: Option<Vec<u8>>,
}

/// The typed result of an offline spend audit. Every failure mode is a NAMED case the caller
/// must handle — never a bool. Only [`AuditVerdict::Consistent`] passes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "kebab-case")]
pub enum AuditVerdict {
    /// Every proof verified, every signed cost matched its rail response, and the re-derived
    /// cross-rail total equals the claimed cumulative.
    Consistent {
        /// Number of brokered calls audited.
        calls: usize,
        /// The true cross-rail total, re-derived by summing the SIGNED settled costs.
        settled_cents: u64,
    },
    /// A call or settlement proof failed `verify_commit_against_kel_scoped` (forged, altered, or
    /// signed-after-revocation). `proof_ref` is the offending commit.
    TamperedProof {
        /// The proof reference (commit SHA) that failed verification.
        proof_ref: String,
    },
    /// (B1) A settlement commit's SIGNED cost disagrees with the cost re-extracted from the
    /// recorded rail response — the operator signed one number but logged another response.
    CostMismatch {
        /// The cost the agent SIGNED in the settlement commit.
        signed_cents: u64,
        /// The cost re-extracted from the recorded rail response.
        recomputed_cents: u64,
        /// The settlement commit at fault.
        proof_ref: String,
    },
    /// The re-derived cross-rail total (summed from the SIGNED costs) disagrees with the
    /// operator's claimed cumulative.
    BudgetMismatch {
        /// The true total re-derived from the signed costs.
        recomputed_cents: u64,
        /// The cumulative the operator's counter/receipt claimed.
        claimed_cents: u64,
    },
    /// The signed proof chain has a gap at record index `at` — a call was dropped or reordered.
    DroppedCall {
        /// The record index where continuity broke.
        at: usize,
    },
    /// The agent's delegation was revoked as of record index `at`; calls at/after it are
    /// unauthorized.
    Revoked {
        /// The record index at/after which the delegation was revoked.
        at: usize,
    },
}

impl AuditVerdict {
    /// True ONLY for [`AuditVerdict::Consistent`] — the audit passed.
    pub fn is_consistent(&self) -> bool {
        matches!(self, AuditVerdict::Consistent { .. })
    }

    /// A stable kebab-case code (for logs, the CLI, and exit-code mapping).
    pub fn code(&self) -> &'static str {
        match self {
            AuditVerdict::Consistent { .. } => "consistent",
            AuditVerdict::TamperedProof { .. } => "tampered-proof",
            AuditVerdict::CostMismatch { .. } => "cost-mismatch",
            AuditVerdict::BudgetMismatch { .. } => "budget-mismatch",
            AuditVerdict::DroppedCall { .. } => "dropped-call",
            AuditVerdict::Revoked { .. } => "revoked",
        }
    }
}

impl fmt::Display for AuditVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuditVerdict::Consistent {
                calls,
                settled_cents,
            } => write!(
                f,
                "consistent — {calls} call(s), ${}.{:02} re-derived from signed costs",
                settled_cents / 100,
                settled_cents % 100
            ),
            AuditVerdict::TamperedProof { proof_ref } => {
                write!(f, "tampered-proof — {proof_ref} failed verification")
            }
            AuditVerdict::CostMismatch {
                signed_cents,
                recomputed_cents,
                proof_ref,
            } => write!(
                f,
                "cost-mismatch — {proof_ref} signed {signed_cents}c but the rail response is {recomputed_cents}c"
            ),
            AuditVerdict::BudgetMismatch {
                recomputed_cents,
                claimed_cents,
            } => write!(
                f,
                "budget-mismatch — re-derived {recomputed_cents}c, operator claimed {claimed_cents}c"
            ),
            AuditVerdict::DroppedCall { at } => write!(f, "dropped-call — chain gap at record {at}"),
            AuditVerdict::Revoked { at } => {
                write!(f, "revoked — delegation revoked as of record {at}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate::{ToolCall, Verdict};
    use chrono::DateTime;

    fn sample_receipt() -> Receipt {
        let call = ToolCall {
            tool: "read_file".to_string(),
            args: serde_json::json!({ "path": "src/lib.rs" }),
            cost_cents: 0,
        };
        Receipt::for_call(
            "did:keri:Eagent",
            "did:keri:Eroot",
            &call,
            "abc123commitsha",
            Verdict::Allowed,
            Some("x402"),
            Some("0xtx"),
            0,
            150,
            DateTime::from_timestamp(0, 0).unwrap(),
        )
    }

    #[test]
    fn audit_verdict_code_and_is_consistent() {
        let ok = AuditVerdict::Consistent {
            calls: 3,
            settled_cents: 450,
        };
        assert!(ok.is_consistent());
        assert_eq!(ok.code(), "consistent");

        let bad = AuditVerdict::TamperedProof {
            proof_ref: "deadbeef".into(),
        };
        assert!(!bad.is_consistent());
        assert_eq!(bad.code(), "tampered-proof");
        assert_eq!(
            AuditVerdict::CostMismatch {
                signed_cents: 10,
                recomputed_cents: 5,
                proof_ref: "s".into()
            }
            .code(),
            "cost-mismatch"
        );
        assert_eq!(AuditVerdict::DroppedCall { at: 2 }.code(), "dropped-call");
        assert_eq!(AuditVerdict::Revoked { at: 4 }.code(), "revoked");
    }

    #[test]
    fn audit_verdict_serde_roundtrips_tagged_kebab() {
        let v = AuditVerdict::CostMismatch {
            signed_cents: 60,
            recomputed_cents: 50,
            proof_ref: "p".into(),
        };
        let json = serde_json::to_string(&v).unwrap();
        assert!(
            json.contains("\"verdict\":\"cost-mismatch\""),
            "tagged kebab-case: {json}"
        );
        assert_eq!(serde_json::from_str::<AuditVerdict>(&json).unwrap(), v);
    }

    #[test]
    fn spend_log_record_roundtrips_as_one_jsonl_line() {
        let rec = SpendLogRecord {
            call_commit: b"signed call commit bytes".to_vec(),
            receipt: sample_receipt(),
            rail: Some("x402".to_string()),
            rail_response: Some(b"{\"requirements\":{}}".to_vec()),
            settlement_commit: Some(b"signed settlement commit bytes".to_vec()),
        };
        let line = serde_json::to_string(&rec).unwrap();
        assert!(
            !line.contains('\n'),
            "a record must serialize to a single JSONL line"
        );
        // Round-trips stably (Receipt isn't PartialEq, so compare the canonical serialization).
        let back: SpendLogRecord = serde_json::from_str(&line).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), line);
    }

    #[test]
    fn non_metered_record_omits_rail_fields() {
        let rec = SpendLogRecord {
            call_commit: b"c".to_vec(),
            receipt: sample_receipt(),
            rail: None,
            rail_response: None,
            settlement_commit: None,
        };
        let json = serde_json::to_string(&rec).unwrap();
        assert!(
            !json.contains("rail_response") && !json.contains("settlement_commit"),
            "None rail/settlement fields are skipped: {json}"
        );
        let back: SpendLogRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), json);
    }
}
