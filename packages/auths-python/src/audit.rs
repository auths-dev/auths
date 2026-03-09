use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use std::path::PathBuf;

use auths_infra_git::audit::Git2LogProvider;
use auths_sdk::ports::git::SignatureStatus;
use auths_sdk::workflows::audit::AuditWorkflow;

fn resolve_repo(repo_path: &str) -> PathBuf {
    PathBuf::from(shellexpand::tilde(repo_path).as_ref())
}

#[pyfunction]
#[pyo3(signature = (target_repo_path, auths_repo_path, since=None, until=None, author=None, limit=500))]
pub fn generate_audit_report(
    py: Python<'_>,
    target_repo_path: &str,
    auths_repo_path: &str,
    since: Option<String>,
    until: Option<String>,
    author: Option<String>,
    limit: usize,
) -> PyResult<String> {
    let target = resolve_repo(target_repo_path);
    let _auths = resolve_repo(auths_repo_path);
    let since = since;
    let until = until;
    let author = author;

    py.allow_threads(move || {
        let provider = Git2LogProvider::open(&target)
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_AUDIT_ERROR] {e}")))?;

        let workflow = AuditWorkflow::new(&provider);
        let report = workflow
            .generate_report(None, Some(limit))
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_AUDIT_ERROR] {e}")))?;

        let since_filter = since.and_then(|s| {
            chrono::NaiveDate::parse_from_str(&s, "%Y-%m-%d")
                .ok()
                .map(|d| d.and_hms_opt(0, 0, 0).unwrap())
        });
        let until_filter = until.and_then(|u| {
            chrono::NaiveDate::parse_from_str(&u, "%Y-%m-%d")
                .ok()
                .map(|d| d.and_hms_opt(23, 59, 59).unwrap())
        });

        let commits: Vec<serde_json::Value> = report
            .commits
            .iter()
            .filter(|c| {
                if let Some(ref a) = author {
                    if c.author_email != *a {
                        return false;
                    }
                }
                if let Some(since_dt) = since_filter {
                    if let Ok(ct) =
                        chrono::NaiveDateTime::parse_from_str(&c.timestamp[..19], "%Y-%m-%dT%H:%M:%S")
                    {
                        if ct < since_dt {
                            return false;
                        }
                    }
                }
                if let Some(until_dt) = until_filter {
                    if let Ok(ct) =
                        chrono::NaiveDateTime::parse_from_str(&c.timestamp[..19], "%Y-%m-%dT%H:%M:%S")
                    {
                        if ct > until_dt {
                            return false;
                        }
                    }
                }
                true
            })
            .map(|c| {
                let (sig_type, signer_did, verified) = match &c.signature_status {
                    SignatureStatus::AuthsSigned { signer_did } => {
                        (Some("auths"), Some(signer_did.as_str()), Some(true))
                    }
                    SignatureStatus::SshSigned => (Some("ssh"), None, None),
                    SignatureStatus::GpgSigned { verified } => {
                        (Some("gpg"), None, Some(*verified))
                    }
                    SignatureStatus::InvalidSignature { .. } => {
                        (Some("invalid"), None, Some(false))
                    }
                    SignatureStatus::Unsigned => (None, None, None),
                };
                serde_json::json!({
                    "oid": c.hash,
                    "author_name": c.author_name,
                    "author_email": c.author_email,
                    "date": c.timestamp,
                    "message": c.message,
                    "signature_type": sig_type,
                    "signer_did": signer_did,
                    "verified": verified,
                })
            })
            .collect();

        let filtered_summary = {
            let total = commits.len();
            let signed = commits
                .iter()
                .filter(|c| c["signature_type"] != serde_json::Value::Null)
                .count();
            let unsigned = total - signed;
            let auths_signed = commits
                .iter()
                .filter(|c| c["signature_type"] == "auths")
                .count();
            let gpg_signed = commits
                .iter()
                .filter(|c| c["signature_type"] == "gpg")
                .count();
            let ssh_signed = commits
                .iter()
                .filter(|c| c["signature_type"] == "ssh")
                .count();
            let verification_passed = commits
                .iter()
                .filter(|c| c["verified"] == true)
                .count();
            let verification_failed = signed - verification_passed;

            serde_json::json!({
                "total_commits": total,
                "signed_commits": signed,
                "unsigned_commits": unsigned,
                "auths_signed": auths_signed,
                "gpg_signed": gpg_signed,
                "ssh_signed": ssh_signed,
                "verification_passed": verification_passed,
                "verification_failed": verification_failed,
            })
        };

        let result = serde_json::json!({
            "commits": commits,
            "summary": filtered_summary,
        });

        serde_json::to_string(&result)
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_AUDIT_ERROR] {e}")))
    })
}
