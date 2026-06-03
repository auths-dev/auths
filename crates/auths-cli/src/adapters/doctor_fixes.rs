//! Fix implementations for CLI-only diagnostic checks.

use std::path::PathBuf;

use auths_sdk::ports::diagnostics::{CheckResult, DiagnosticError, DiagnosticFix};
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
    let status = crate::subprocess::git_command(&["config", "--global", key, value])
        .status()
        .map_err(|e| DiagnosticError::ExecutionFailed(format!("git config: {e}")))?;
    if !status.success() {
        return Err(DiagnosticError::ExecutionFailed(format!(
            "git config --global {key} {value} failed"
        )));
    }
    Ok(())
}
