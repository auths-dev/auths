//! Evidence-layer bindings: the `auths-evidence` trust core re-exported verbatim
//! into the `auths` wheel. Each function returns the versioned JSON contract
//! (`audit/v1`, `receipts/v1`, `activity/v1`) — never a second implementation.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use crate::runtime::runtime;

/// Re-derive an agent's spend from its signed log (the `audit/v1` report, JSON).
///
/// Args:
/// * `log_path`: the spend log (JSONL file or rotated directory).
/// * `registry_path`: the issuer's registry.
/// * `agent` / `root`: the delegation to audit.
///
/// Usage:
/// ```ignore
/// report = json.loads(auths.evidence.verify_spend(log, registry, agent, root))
/// ```
#[pyfunction]
pub fn verify_spend(
    log_path: String,
    registry_path: String,
    agent: String,
    root: String,
) -> PyResult<String> {
    let spend = runtime()
        .block_on(auths_evidence::verify_spend(
            auths_evidence::VerifyOpts::new(
                std::path::Path::new(&log_path),
                std::path::Path::new(&registry_path),
                &agent,
                &root,
            ),
            chrono::Utc::now(),
        ))
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    serde_json::to_string(&spend.report).map_err(|e| PyValueError::new_err(e.to_string()))
}

/// Fully-offline verification of a `receipts/v1` EvidenceBundle (JSON in → the
/// OfflineVerdict JSON out). The CALLER must assert the echoed subject/tx/
/// callIndex match its own payment ref (security S4).
#[pyfunction]
pub fn verify_offline(bundle_json: String) -> PyResult<String> {
    let bundle: auths_evidence::EvidenceBundle =
        serde_json::from_str(&bundle_json).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let verdict = runtime().block_on(auths_evidence::verify_offline(&bundle));
    serde_json::to_string(&verdict).map_err(|e| PyValueError::new_err(e.to_string()))
}

/// Verify a published `activity/v1` attestation against a fetched registry copy
/// (identity resolution only). Returns `{ok, reason?, …}` JSON.
#[pyfunction]
pub fn verify_activity(attestation_json: String, registry_path: String) -> PyResult<String> {
    let doc: auths_evidence::ActivityV1 = match serde_json::from_str(&attestation_json) {
        Ok(doc) => doc,
        Err(e) => {
            return serde_json::to_string(&serde_json::json!({
                "ok": false, "reason": format!("not activity/v1-shaped: {e}"),
            }))
            .map_err(|e| PyValueError::new_err(e.to_string()));
        }
    };
    let body = match auths_evidence::verify_activity_against_registry(
        &doc,
        std::path::Path::new(&registry_path),
    ) {
        Ok(()) => serde_json::json!({
            "ok": true,
            "head": doc.head,
            "count": doc.count,
            "cumulative_cents": doc.cumulative_cents,
            "as_of_ts": doc.as_of.ts.to_rfc3339(),
            "subject_root": doc.subject.root,
            "subject_agent": doc.subject.agent,
        }),
        Err(e) => serde_json::json!({ "ok": false, "reason": e.to_string() }),
    };
    serde_json::to_string(&body).map_err(|e| PyValueError::new_err(e.to_string()))
}

/// The embedded `receipts/v1` JSON schema.
#[pyfunction]
pub fn receipts_v1_schema() -> String {
    auths_evidence::RECEIPTS_V1_SCHEMA.to_string()
}

/// The embedded `audit/v1` JSON schema.
#[pyfunction]
pub fn audit_v1_schema() -> String {
    auths_evidence::AUDIT_V1_SCHEMA.to_string()
}
