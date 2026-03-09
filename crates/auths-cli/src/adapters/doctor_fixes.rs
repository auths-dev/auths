//! Fix implementations for CLI-only diagnostic checks.

use std::path::PathBuf;
use std::process::Command;

use auths_sdk::ports::diagnostics::{CheckResult, DiagnosticError, DiagnosticFix};
use auths_sdk::workflows::allowed_signers::AllowedSigners;
use auths_storage::git::RegistryAttestationStorage;

/// Regenerates the allowed_signers file from attestation storage.
///
/// Safe fix — runs without user confirmation since it only writes
/// a derived file and doesn't overwrite user-authored configuration.
pub struct AllowedSignersFix {
    repo_path: PathBuf,
}

impl AllowedSignersFix {
    pub fn new(repo_path: PathBuf) -> Self {
        Self { repo_path }
    }
}

impl DiagnosticFix for AllowedSignersFix {
    fn name(&self) -> &str {
        "Regenerate allowed_signers"
    }

    fn is_safe(&self) -> bool {
        true
    }

    fn can_fix(&self, check: &CheckResult) -> bool {
        check.name == "Allowed signers file" && !check.passed
    }

    fn apply(&self) -> Result<String, DiagnosticError> {
        let home = dirs::home_dir()
            .ok_or_else(|| DiagnosticError::ExecutionFailed("no home directory".into()))?;
        let ssh_dir = home.join(".ssh");
        std::fs::create_dir_all(&ssh_dir)
            .map_err(|e| DiagnosticError::ExecutionFailed(format!("create .ssh dir: {e}")))?;
        let signers_path = ssh_dir.join("allowed_signers");

        let storage = RegistryAttestationStorage::new(&self.repo_path);
        let mut signers = AllowedSigners::load(&signers_path)
            .unwrap_or_else(|_| AllowedSigners::new(&signers_path));
        let report = signers
            .sync(&storage)
            .map_err(|e| DiagnosticError::ExecutionFailed(format!("sync signers: {e}")))?;
        signers
            .save()
            .map_err(|e| DiagnosticError::ExecutionFailed(format!("save signers: {e}")))?;

        let signers_str = signers_path
            .to_str()
            .ok_or_else(|| DiagnosticError::ExecutionFailed("path not UTF-8".into()))?;
        set_git_config_value("gpg.ssh.allowedSignersFile", signers_str)?;

        Ok(format!(
            "Wrote {} signer(s) to {}, set gpg.ssh.allowedSignersFile",
            report.added,
            signers_path.display()
        ))
    }
}

/// Sets the 5 git signing config keys for auths.
///
/// Unsafe fix — may overwrite existing non-auths git signing config,
/// so it requires user confirmation in interactive mode.
pub struct GitSigningConfigFix {
    sign_binary_path: PathBuf,
    key_alias: String,
}

impl GitSigningConfigFix {
    pub fn new(sign_binary_path: PathBuf, key_alias: String) -> Self {
        Self {
            sign_binary_path,
            key_alias,
        }
    }
}

impl DiagnosticFix for GitSigningConfigFix {
    fn name(&self) -> &str {
        "Configure git signing"
    }

    fn is_safe(&self) -> bool {
        false
    }

    fn can_fix(&self, check: &CheckResult) -> bool {
        check.name == "Git signing config" && !check.passed
    }

    fn apply(&self) -> Result<String, DiagnosticError> {
        let auths_sign_str = self
            .sign_binary_path
            .to_str()
            .ok_or_else(|| DiagnosticError::ExecutionFailed("auths-sign path not UTF-8".into()))?;
        let signing_key = format!("auths:{}", self.key_alias);

        let configs: &[(&str, &str)] = &[
            ("gpg.format", "ssh"),
            ("gpg.ssh.program", auths_sign_str),
            ("user.signingkey", &signing_key),
            ("commit.gpgsign", "true"),
            ("tag.gpgsign", "true"),
        ];

        for (key, val) in configs {
            set_git_config_value(key, val)?;
        }

        Ok("Set 5 git signing config keys (gpg.format, gpg.ssh.program, user.signingkey, commit.gpgsign, tag.gpgsign)".to_string())
    }
}

fn set_git_config_value(key: &str, value: &str) -> Result<(), DiagnosticError> {
    let status = Command::new("git")
        .args(["config", "--global", key, value])
        .status()
        .map_err(|e| DiagnosticError::ExecutionFailed(format!("git config: {e}")))?;
    if !status.success() {
        return Err(DiagnosticError::ExecutionFailed(format!(
            "git config --global {key} {value} failed"
        )));
    }
    Ok(())
}
