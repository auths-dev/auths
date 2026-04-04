//! POSIX-based diagnostic adapter — subprocess calls live here, nowhere else.

use auths_sdk::ports::diagnostics::{
    CheckCategory, CheckResult, CryptoDiagnosticProvider, DiagnosticError, GitDiagnosticProvider,
};
use std::process::Command;

/// Production adapter that shells out to system binaries.
pub struct PosixDiagnosticAdapter;

impl GitDiagnosticProvider for PosixDiagnosticAdapter {
    fn check_git_version(&self) -> Result<CheckResult, DiagnosticError> {
        let output = crate::subprocess::git_command(&["--version"]).output();
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
        let output = crate::subprocess::git_command(&["config", "--global", "--get", key])
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
        // Use `which` crate logic: check if ssh-keygen exists on PATH
        let output = Command::new("ssh-keygen")
            .arg("-?")
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .output();
        let (passed, message) = match output {
            Ok(out) if !out.stderr.is_empty() || !out.stdout.is_empty() => {
                (true, Some("ssh-keygen found on PATH".to_string()))
            }
            Ok(_) => (true, Some("ssh-keygen found on PATH".to_string())),
            Err(_) => {
                let hint = ssh_install_hint();
                (false, Some(format!("ssh-keygen not found on PATH. {hint}")))
            }
        };
        Ok(CheckResult {
            name: "ssh-keygen installed".to_string(),
            passed,
            message,
            config_issues: vec![],
            category: CheckCategory::Advisory,
        })
    }

    fn check_ssh_version(&self) -> Result<String, DiagnosticError> {
        // `ssh -V` writes to stderr, not stdout
        let output = Command::new("ssh")
            .arg("-V")
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .output()
            .map_err(|e| DiagnosticError::ExecutionFailed(format!("ssh -V failed: {e}")))?;

        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if !stderr.is_empty() {
            return Ok(stderr);
        }
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !stdout.is_empty() {
            return Ok(stdout);
        }
        Ok("unknown".to_string())
    }
}

/// Platform-specific install hint for ssh-keygen / OpenSSH.
fn ssh_install_hint() -> &'static str {
    if cfg!(target_os = "macos") {
        "ssh-keygen is normally pre-installed on macOS. Check your PATH."
    } else if cfg!(target_os = "windows") {
        "Install OpenSSH via Settings > Apps > Optional features, or `winget install Microsoft.OpenSSH.Client`."
    } else {
        "Install OpenSSH: `sudo apt install openssh-client` (Debian/Ubuntu) or `sudo dnf install openssh-clients` (Fedora/RHEL)."
    }
}
