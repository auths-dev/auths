//! POSIX-based diagnostic adapter — subprocess calls live here, nowhere else.

use auths_sdk::ports::diagnostics::{
    CheckResult, CryptoDiagnosticProvider, DiagnosticError, GitDiagnosticProvider,
};
use std::process::Command;

/// Production adapter that shells out to system binaries.
pub struct PosixDiagnosticAdapter;

impl GitDiagnosticProvider for PosixDiagnosticAdapter {
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

impl CryptoDiagnosticProvider for PosixDiagnosticAdapter {
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
        })
    }
}
