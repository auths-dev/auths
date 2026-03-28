use std::process::Command;

use auths_sdk::ports::diagnostics::{
    CheckCategory, CheckResult, CryptoDiagnosticProvider, DiagnosticError, GitDiagnosticProvider,
};
use auths_sdk::workflows::diagnostics::DiagnosticsWorkflow;
use napi_derive::napi;

use crate::error::format_error;

struct FfiDiagnosticAdapter;

impl GitDiagnosticProvider for FfiDiagnosticAdapter {
    fn check_git_version(&self) -> Result<CheckResult, DiagnosticError> {
        let output = Command::new("git").arg("--version").output();
        let (passed, message) = match output {
            Ok(out) if out.status.success() => {
                let version = String::from_utf8_lossy(&out.stdout).trim().to_string();
                (true, Some(version))
            }
            _ => (false, Some("git command not found on PATH".to_string())),
        };
        Ok(CheckResult {
            name: "Git installed".to_string(),
            passed,
            message,
            config_issues: vec![],
            category: CheckCategory::Advisory,
        })
    }

    fn get_git_config(&self, key: &str) -> Result<Option<String>, DiagnosticError> {
        let output = Command::new("git")
            .args(["config", "--global", "--get", key])
            .output()
            .map_err(|e| DiagnosticError::ExecutionFailed(e.to_string()))?;

        if output.status.success() {
            Ok(String::from_utf8(output.stdout)
                .ok()
                .map(|s| s.trim().to_string()))
        } else {
            Ok(None)
        }
    }
}

impl CryptoDiagnosticProvider for FfiDiagnosticAdapter {
    fn check_ssh_keygen_available(&self) -> Result<CheckResult, DiagnosticError> {
        let output = Command::new("ssh-keygen").arg("-V").output();
        let (passed, message) = match output {
            Ok(out) if out.status.success() => (true, Some("ssh-keygen found on PATH".to_string())),
            _ => (
                false,
                Some("ssh-keygen command not found on PATH".to_string()),
            ),
        };
        Ok(CheckResult {
            name: "ssh-keygen installed".to_string(),
            passed,
            message,
            config_issues: vec![],
            category: CheckCategory::Advisory,
        })
    }
}

#[napi]
pub fn run_diagnostics(repo_path: String, passphrase: Option<String>) -> napi::Result<String> {
    let _repo = repo_path;
    let _passphrase = passphrase;

    let adapter = FfiDiagnosticAdapter;
    let workflow = DiagnosticsWorkflow::new(&adapter, &adapter);
    let report = workflow
        .run()
        .map_err(|e| format_error("AUTHS_DIAGNOSTIC_ERROR", e))?;

    let all_passed = report.checks.iter().all(|c| c.passed);

    let checks: Vec<serde_json::Value> = report
        .checks
        .iter()
        .map(|c| {
            let fix_hint = if !c.passed {
                Some("Run: auths init --profile developer")
            } else {
                None
            };
            serde_json::json!({
                "name": c.name,
                "passed": c.passed,
                "message": c.message,
                "fix_hint": fix_hint,
            })
        })
        .collect();

    let result = serde_json::json!({
        "checks": checks,
        "all_passed": all_passed,
        "version": env!("CARGO_PKG_VERSION"),
    });

    serde_json::to_string(&result).map_err(|e| format_error("AUTHS_DIAGNOSTIC_ERROR", e))
}
