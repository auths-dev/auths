use std::path::PathBuf;

use auths_infra_git::audit::Git2LogProvider;
use auths_sdk::ports::git::SignatureStatus;
use auths_sdk::workflows::audit::AuditWorkflow;
use napi_derive::napi;

use crate::error::format_error;

fn resolve_repo(repo_path: &str) -> PathBuf {
    PathBuf::from(shellexpand::tilde(repo_path).as_ref())
}

fn parse_timestamp(ts: &str) -> Option<chrono::NaiveDateTime> {
    chrono::NaiveDateTime::parse_from_str(&ts[..19], "%Y-%m-%dT%H:%M:%S").ok()
}

#[napi]
pub fn generate_audit_report(
    target_repo_path: String,
    auths_repo_path: String,
    since: Option<String>,
    until: Option<String>,
    author: Option<String>,
    limit: Option<u32>,
) -> napi::Result<String> {
    let target = resolve_repo(&target_repo_path);
    let _auths = resolve_repo(&auths_repo_path);
    let limit = limit.unwrap_or(500) as usize;

    let provider =
        Git2LogProvider::open(&target).map_err(|e| format_error("AUTHS_AUDIT_ERROR", e))?;

    let workflow = AuditWorkflow::new(&provider);
    let report = workflow
        .generate_report(None, Some(limit))
        .map_err(|e| format_error("AUTHS_AUDIT_ERROR", e))?;

    let since_filter = since.and_then(|s| {
        chrono::NaiveDate::parse_from_str(&s, "%Y-%m-%d")
            .ok()
            .and_then(|d| d.and_hms_opt(0, 0, 0))
    });
    let until_filter = until.and_then(|u| {
        chrono::NaiveDate::parse_from_str(&u, "%Y-%m-%d")
            .ok()
            .and_then(|d| d.and_hms_opt(23, 59, 59))
    });

    let commits: Vec<serde_json::Value> = report
        .commits
        .iter()
        .filter(|c| {
            if author.as_ref().is_some_and(|a| c.author_email != *a) {
                return false;
            }
            if since_filter.is_some_and(|since_dt| {
                parse_timestamp(&c.timestamp).is_some_and(|ct| ct < since_dt)
            }) {
                return false;
            }
            if until_filter.is_some_and(|until_dt| {
                parse_timestamp(&c.timestamp).is_some_and(|ct| ct > until_dt)
            }) {
                return false;
            }
            true
        })
        .map(|c| {
            let (sig_type, signer_did, verified) = match &c.signature_status {
                SignatureStatus::AuthsSigned { signer_did } => {
                    (Some("auths"), Some(signer_did.as_str()), Some(true))
                }
                SignatureStatus::SshSigned => (Some("ssh"), None, None),
                SignatureStatus::GpgSigned { verified } => (Some("gpg"), None, Some(*verified)),
                SignatureStatus::InvalidSignature { .. } => (Some("invalid"), None, Some(false)),
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
    let verification_passed = commits.iter().filter(|c| c["verified"] == true).count();
    let verification_failed = signed - verification_passed;

    let result = serde_json::json!({
        "commits": commits,
        "summary": {
            "total_commits": total,
            "signed_commits": signed,
            "unsigned_commits": unsigned,
            "auths_signed": auths_signed,
            "gpg_signed": gpg_signed,
            "ssh_signed": ssh_signed,
            "verification_passed": verification_passed,
            "verification_failed": verification_failed,
        },
    });

    serde_json::to_string(&result).map_err(|e| format_error("AUTHS_AUDIT_ERROR", e))
}
