//! Append-only WRITE side of the per-call spend log.
//!
//! The gateway appends one [`SpendLogRecord`] per brokered call to
//! `<repo>/spend-log/<delegation>.jsonl`, so an offline `auths verify-spend` can re-verify every
//! SIGNED proof and re-derive the true spend **without the operator** — re-running each record's
//! `call_commit` (and, when present, `settlement_commit`) through the SAME
//! `verify_commit_against_kel_scoped` the live gate uses. One JSON object per line; the writer
//! only ever APPENDS — it never rewrites a prior record. EDITING a record is caught (it breaks the
//! record's SSH signature → tampered-proof), and DROPPING or reordering a record is caught too: each
//! record carries a signed `Auths-Prev` trailer linking it to the prior record's hash (a genesis
//! sentinel for the first), so the audit verifies the log is a continuous chain — a gap or a
//! relinked-out-of-order record → dropped-call.
//!
//! Residual: truncating the TAIL (dropping the most-recent records) is not yet caught here — the
//! back-link proves each record points at a real predecessor, not that the chain is the WHOLE log.
//! Catching tail-truncation needs a signed running HEAD/count anchor (or, for metered spend,
//! cross-checking the re-derived total against the durable cross-rail counter) — a follow-on.
//!
//! The path layout and the READ side (`spend_log_path` / `read_spend_log`) live in
//! `auths_mcp_core` so the gateway (writer) and the `auths-cli` auditor (reader) share ONE
//! definition; this module is only the gateway-side append.

use auths_mcp_core::{SpendLogRecord, spend_log_path};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

/// Append one record as a single JSONL line. Append-only: prior records are never rewritten.
pub fn append(repo: &Path, delegation: &str, record: &SpendLogRecord) -> anyhow::Result<()> {
    let path = spend_log_path(repo, delegation);
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let mut line = serde_json::to_string(record)?;
    debug_assert!(
        !line.contains('\n'),
        "a SpendLogRecord must serialize to one JSONL line"
    );
    line.push('\n');
    let mut f = OpenOptions::new().create(true).append(true).open(&path)?;
    f.write_all(line.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_mcp_core::Cents;
    use auths_mcp_core::gate::{ToolCall, Verdict};
    use auths_mcp_core::receipt::Receipt;
    use auths_mcp_core::read_spend_log;
    use chrono::DateTime;

    fn record(cumulative: u64) -> SpendLogRecord {
        let call = ToolCall {
            tool: "paid_call".to_string(),
            args: serde_json::json!({ "q": "x" }),
            cost_cents: Cents::ZERO,
        };
        let receipt = Receipt::for_call(
            "did:keri:Eagent",
            "did:keri:Eroot",
            &call,
            "shaXYZ",
            Verdict::Allowed,
            Some("x402"),
            Some("0xtx"),
            Cents::ZERO,
            Cents::new(cumulative),
            DateTime::from_timestamp(0, 0).unwrap(),
        );
        SpendLogRecord {
            call_commit: b"signed call commit".to_vec(),
            receipt,
            rail: Some("x402".to_string()),
            rail_response: Some(b"{\"requirements\":{}}".to_vec()),
            settlement_commit: None,
        }
    }

    #[test]
    fn append_is_append_only_and_reads_back_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        let dlg = "did:keri:EagentDelegationABC";

        append(repo, dlg, &record(100)).unwrap();
        append(repo, dlg, &record(250)).unwrap();

        let path = spend_log_path(repo, dlg);
        let back = read_spend_log(&path).unwrap();
        assert_eq!(back.len(), 2, "the second append must NOT clobber the first");
        assert_eq!(back[0].receipt.cumulative_cents, Cents::new(100));
        assert_eq!(back[1].receipt.cumulative_cents, Cents::new(250));
    }
}
