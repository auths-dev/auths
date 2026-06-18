//! The independent spend-audit data model.
//!
//! The contract an offline `auths verify-spend` reads to re-derive an agent's true spend
//! WITHOUT trusting the operator: an append-only **spend log** of per-call records the gateway
//! persists, plus the typed [`AuditVerdict`] the audit returns.
//!
//! This module is the pure DATA layer — no I/O, no crypto, no gateway dependency — so the
//! gateway (which writes the log) and the offline auditor (which reads + verifies it) share one
//! definition. Verification itself replays each record's signed proof(s) through the SAME
//! `auths_verifier::verify_commit_against_kel_scoped` the live gate uses, and sums the
//! AGENT-SIGNED settled costs — never the operator's counter.
//!
//! NOTE: the LIVE wrap path does not yet sign a per-call proof — it does a boolean scope check +
//! budget enforcement (`proxy.rs::call_tool`). Producing these records on the live wire is a
//! separate change (wiring `chain.rs` signing into the live path); the audit is first built over
//! the hermetic replay gate, which already signs + verifies a real commit per call. This data
//! model is path-agnostic.

use crate::receipt::Receipt;
use auths_id::keri::Event;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};

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
    /// Raw bytes of the agent's signed `tools/call` proof commit — retained so the audit
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
    ///
    /// ⚠️ LIVE-WIRING CAVEAT (must-review when the live path populates this): capture the response
    /// **body only** — NEVER request/response auth headers. An `Authorization: Bearer …` or the
    /// gateway's custodied downstream credential must never land in the spend log. (Hermetic today:
    /// this is a recorded fixture body, which holds no secret.)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rail_response: Option<Vec<u8>>,
    /// Raw bytes of the agent's signed SETTLEMENT commit anchoring the actual cost
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
    /// A settlement commit's SIGNED cost disagrees with the cost re-extracted from the
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

/// The spend-log file for one agent delegation under `repo` (the verifier-held registry path):
/// `<repo>/spend-log/<delegation>.jsonl`. Shared by the gateway (which appends records) and the
/// offline auditor (which reads them) so there is ONE definition of where the log lives.
pub fn spend_log_path(repo: &Path, delegation: &str) -> PathBuf {
    repo.join("spend-log")
        .join(format!("{}.jsonl", safe_key(delegation)))
}

/// Read every [`SpendLogRecord`] from a delegation's spend log, in order (for the offline
/// auditor). A blank trailing line is ignored; a non-blank line that fails to parse is
/// `InvalidData` — a corrupted or edited log fails closed rather than silently dropping a call.
pub fn read_spend_log(path: &Path) -> std::io::Result<Vec<SpendLogRecord>> {
    let raw = std::fs::read_to_string(path)?;
    raw.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            serde_json::from_str::<SpendLogRecord>(l)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })
        .collect()
}

/// A filesystem-safe single component from a delegation id: strip the `did:keri:` scheme and map
/// anything that is not `[A-Za-z0-9_-]` to `_` (defensive — a `did:keri:E…` tail is base64url and
/// already safe; this only guards a malformed key from escaping the directory).
fn safe_key(delegation: &str) -> String {
    let tail = delegation.strip_prefix("did:keri:").unwrap_or(delegation);
    if tail.is_empty() || tail == "." || tail == ".." {
        return "_".to_string();
    }
    tail.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Independently re-verify an agent's spend log. The PROOF leg is operator-proof: replay each
/// record's signed `call_commit` through the SAME `verify_commit_against_kel_scoped` the live gate
/// uses — a forged/tampered proof → [`AuditVerdict::TamperedProof`], a revoked-key proof →
/// [`AuditVerdict::Revoked`] — so a hostile operator cannot forge or alter a proof undetected. The
/// SPEND leg sums each settled call's cost, re-extracted from its recorded `rail_response` via
/// [`crate::rail::extract`], and cross-checks it against the operator's claimed cumulative (catching
/// internal inconsistency). Once a call carries a `settlement_commit`, the cost is taken from the
/// agent's signature instead — un-forgeable even by a colluding operator.
///
/// `now` is unix-epoch seconds (the auditor's injected clock — the verifier holds none). The
/// agent/delegator KELs + `pinned_roots` are resolved the SAME way `PerCallGate::resolve` does (from
/// the issuer's registry), so the audit is the gate's own check, re-run by anyone, offline.
///
/// A legitimately refused call (out-of-scope / over-cap) carries an AUTHENTIC proof and is NOT a
/// tamper.
pub async fn audit_spend_log(
    records: &[SpendLogRecord],
    agent_kel: &[Event],
    delegator_kel: &[Event],
    pinned_roots: &[String],
    now: i64,
) -> AuditVerdict {
    let provider = auths_crypto::default_provider();
    let mut settled: u64 = 0;
    for (i, rec) in records.iter().enumerate() {
        // Re-verify the SIGNED proof bytes — the gate's own authenticity check, re-run offline.
        let commit_verdict = auths_verifier::verify_commit_against_kel_scoped(
            &rec.call_commit,
            agent_kel,
            delegator_kel,
            pinned_roots,
            provider,
            now,
        )
        .await;
        // Reuse the EXACT CommitVerdict→Verdict mapping the gate uses (DRY — one source of truth).
        // The RE-DERIVED verdict is the authority for everything below; the receipt's CLAIMED
        // verdict is operator-controlled and is NEVER an input here.
        let verdict = crate::gate::Verdict::from_commit_verdict(&commit_verdict);
        match &verdict {
            crate::gate::Verdict::ProofUnauthentic { .. } => {
                return AuditVerdict::TamperedProof {
                    proof_ref: rec.receipt.proof_ref.clone(),
                };
            }
            crate::gate::Verdict::Revoked => return AuditVerdict::Revoked { at: i },
            // Allowed / OutsideAgentScope / AgentExpired are AUTHENTIC proofs — a legit refusal is
            // not a tamper; only forgery and revocation are audit failures of the proof itself.
            _ => {}
        }
        // Sum the rail-attested settled cost for a call that (a) carries an AUTHENTIC, IN-SCOPE proof
        // — `Allowed`/`AgentExpired`, both PROOF-DETERMINED, so the operator cannot relabel a settled
        // call as refused without breaking its signature (`OutsideAgentScope` never settled) — AND
        // (b) recorded a rail response (set only for calls that forwarded; see replay.rs).
        // The amount is re-extracted from the recorded rail response; once a `settlement_commit` is
        // present it is read from the agent's signature instead, so a colluding operator cannot lower
        // it without the key.
        if matches!(
            verdict,
            crate::gate::Verdict::Allowed | crate::gate::Verdict::AgentExpired
        ) && let (Some(rail), Some(resp)) = (rec.rail.as_deref(), rec.rail_response.as_deref())
        {
            match crate::rail::extract(rail, resp) {
                Ok(c) => settled = settled.saturating_add(c.amount_cents),
                Err(_) => {
                    // A settled call whose recorded response no longer extracts is a tampered response.
                    return AuditVerdict::CostMismatch {
                        signed_cents: 0,
                        recomputed_cents: 0,
                        proof_ref: rec.receipt.proof_ref.clone(),
                    };
                }
            }
        }
    }
    // The operator's claimed cross-rail total is the last record's cumulative — an UNTRUSTED hint we
    // compare against the cost we re-derived from the rail responses.
    let claimed = records
        .last()
        .map(|r| r.receipt.cumulative_cents)
        .unwrap_or(0);
    if settled != claimed {
        return AuditVerdict::BudgetMismatch {
            recomputed_cents: settled,
            claimed_cents: claimed,
        };
    }
    AuditVerdict::Consistent {
        calls: records.len(),
        settled_cents: settled,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate::{ToolCall, Verdict};
    use chrono::DateTime;
    use std::path::Path;

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

    #[test]
    fn spend_log_path_strips_scheme_and_stays_in_one_component() {
        let p = spend_log_path(Path::new("/repo"), "did:keri:EabC-_9");
        assert!(p.ends_with("spend-log/EabC-_9.jsonl"), "{p:?}");
        // a malformed delegation cannot escape the spend-log dir
        let evil = spend_log_path(Path::new("/repo"), "../../etc/passwd");
        assert!(!evil.to_string_lossy().contains(".."), "{evil:?}");
    }

    #[test]
    fn read_spend_log_parses_in_order_and_fails_closed_on_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.jsonl");
        let line = serde_json::to_string(&SpendLogRecord {
            call_commit: b"a".to_vec(),
            receipt: sample_receipt(),
            rail: None,
            rail_response: None,
            settlement_commit: None,
        })
        .unwrap();
        // two records + a blank line (ignored)
        std::fs::write(&path, format!("{line}\n\n{line}\n")).unwrap();
        assert_eq!(read_spend_log(&path).unwrap().len(), 2);
        // a corrupted/edited line fails closed, never silently drops a record
        std::fs::write(&path, format!("{line}\nnot json\n")).unwrap();
        assert!(read_spend_log(&path).is_err());
    }
}
