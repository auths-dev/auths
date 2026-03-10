//! Diagnostics workflow — orchestrates system health checks via injected providers.

use crate::ports::diagnostics::{
    CheckResult, ConfigIssue, CryptoDiagnosticProvider, DiagnosticError, DiagnosticReport,
    GitDiagnosticProvider,
};

/// Orchestrates diagnostic checks without subprocess calls.
///
/// Args:
/// * `G`: A [`GitDiagnosticProvider`] implementation.
/// * `C`: A [`CryptoDiagnosticProvider`] implementation.
///
/// Usage:
/// ```ignore
/// let workflow = DiagnosticsWorkflow::new(posix_adapter.clone(), posix_adapter);
/// let report = workflow.run()?;
/// ```
pub struct DiagnosticsWorkflow<G: GitDiagnosticProvider, C: CryptoDiagnosticProvider> {
    git: G,
    crypto: C,
}

impl<G: GitDiagnosticProvider, C: CryptoDiagnosticProvider> DiagnosticsWorkflow<G, C> {
    /// Create a new diagnostics workflow with the given providers.
    pub fn new(git: G, crypto: C) -> Self {
        Self { git, crypto }
    }

    /// Names of all available checks.
    pub fn available_checks() -> &'static [&'static str] {
        &["git_version", "ssh_keygen", "git_signing_config"]
    }

    /// Run a single diagnostic check by name.
    ///
    /// Returns `Err(DiagnosticError::CheckNotFound)` if the name is unknown.
    pub fn run_single(&self, name: &str) -> Result<CheckResult, DiagnosticError> {
        match name {
            "git_version" => self.git.check_git_version(),
            "ssh_keygen" => self.crypto.check_ssh_keygen_available(),
            "git_signing_config" => {
                let mut checks = Vec::new();
                self.check_git_signing_config(&mut checks)?;
                checks
                    .into_iter()
                    .next()
                    .ok_or_else(|| DiagnosticError::CheckNotFound(name.to_string()))
            }
            _ => Err(DiagnosticError::CheckNotFound(name.to_string())),
        }
    }

    /// Run all diagnostic checks and return the aggregated report.
    ///
    /// Usage:
    /// ```ignore
    /// let report = workflow.run()?;
    /// assert!(report.checks.iter().all(|c| c.passed));
    /// ```
    pub fn run(&self) -> Result<DiagnosticReport, DiagnosticError> {
        let mut checks = Vec::new();

        checks.push(self.git.check_git_version()?);
        checks.push(self.crypto.check_ssh_keygen_available()?);

        self.check_git_signing_config(&mut checks)?;

        Ok(DiagnosticReport { checks })
    }

    fn check_git_signing_config(
        &self,
        checks: &mut Vec<CheckResult>,
    ) -> Result<(), DiagnosticError> {
        let required = [
            ("gpg.format", "ssh"),
            ("commit.gpgsign", "true"),
            ("tag.gpgsign", "true"),
        ];
        let presence_only = ["user.signingkey", "gpg.ssh.program"];

        let mut issues: Vec<ConfigIssue> = Vec::new();

        for (key, expected) in &required {
            match self.git.get_git_config(key)? {
                Some(val) if val == *expected => {}
                Some(actual) => {
                    issues.push(ConfigIssue::Mismatch {
                        key: key.to_string(),
                        expected: expected.to_string(),
                        actual,
                    });
                }
                None => {
                    issues.push(ConfigIssue::Absent(key.to_string()));
                }
            }
        }

        for key in &presence_only {
            if self.git.get_git_config(key)?.is_none() {
                issues.push(ConfigIssue::Absent(key.to_string()));
            }
        }

        let passed = issues.is_empty();

        checks.push(CheckResult {
            name: "Git signing config".to_string(),
            passed,
            message: None,
            config_issues: issues,
        });

        Ok(())
    }
}
