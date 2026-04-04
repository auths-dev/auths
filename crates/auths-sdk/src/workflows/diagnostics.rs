//! Diagnostics workflow — orchestrates system health checks via injected providers.

use crate::ports::diagnostics::{
    CheckCategory, CheckResult, ConfigIssue, CryptoDiagnosticProvider, DiagnosticError,
    DiagnosticReport, GitDiagnosticProvider,
};

/// Minimum Git version required for SSH signing support.
pub const MIN_GIT_VERSION: (u32, u32, u32) = (2, 34, 0);

/// Minimum OpenSSH version required (`-Y find-principals` was added in 8.2).
pub const MIN_SSH_VERSION: (u32, u32, u32) = (8, 2, 0);

/// Parses a Git version string into a `(major, minor, patch)` tuple.
///
/// Args:
/// * `version_str`: Raw output from `git --version`, e.g. `"git version 2.39.0"`.
///
/// Usage:
/// ```ignore
/// let v = parse_git_version("git version 2.39.0");
/// assert_eq!(v, Some((2, 39, 0)));
/// ```
pub fn parse_git_version(version_str: &str) -> Option<(u32, u32, u32)> {
    let version_part = version_str
        .split_whitespace()
        .find(|s| s.chars().next().is_some_and(|c| c.is_ascii_digit()))?;

    let numbers: Vec<u32> = version_part
        .split('.')
        .take(3)
        .filter_map(|s| {
            s.chars()
                .take_while(|c| c.is_ascii_digit())
                .collect::<String>()
                .parse()
                .ok()
        })
        .collect();

    match numbers.as_slice() {
        [major, minor, patch, ..] => Some((*major, *minor, *patch)),
        [major, minor] => Some((*major, *minor, 0)),
        [major] => Some((*major, 0, 0)),
        _ => None,
    }
}

/// Parses an OpenSSH version string into a `(major, minor, patch)` tuple.
///
/// Handles formats from `ssh -V` (written to stderr):
/// - `OpenSSH_9.6p1, LibreSSL 3.3.6` (macOS/Linux)
/// - `OpenSSH_for_Windows_8.6p1, LibreSSL 3.4.3` (Windows)
///
/// Args:
/// * `version_str`: Raw stderr output from `ssh -V`.
///
/// Usage:
/// ```ignore
/// let v = parse_ssh_version("OpenSSH_9.6p1, LibreSSL 3.3.6");
/// assert_eq!(v, Some((9, 6, 1)));
/// ```
pub fn parse_ssh_version(version_str: &str) -> Option<(u32, u32, u32)> {
    // Find the "OpenSSH_X.Yp1" or "OpenSSH_for_Windows_X.Yp1" portion
    let ssh_part = version_str.split(',').next()?.trim();

    // Extract the version after the last underscore
    let version_segment = ssh_part.rsplit('_').next()?;

    // Split on '.' to get major, then minor+patch
    let mut parts = version_segment.split('.');
    let major: u32 = parts.next()?.parse().ok()?;

    let minor_patch = parts.next().unwrap_or("0");
    // minor_patch is like "6p1" or "6" — split on 'p' for patch
    let mut mp = minor_patch.splitn(2, 'p');
    let minor: u32 = mp.next()?.parse().ok()?;
    let patch: u32 = mp
        .next()
        .and_then(|p| {
            p.chars()
                .take_while(|c| c.is_ascii_digit())
                .collect::<String>()
                .parse()
                .ok()
        })
        .unwrap_or(0);

    Some((major, minor, patch))
}

/// Check whether the given SSH version meets the minimum requirement.
///
/// Args:
/// * `version`: Parsed `(major, minor, patch)` tuple.
///
/// Usage:
/// ```ignore
/// assert!(check_ssh_version_minimum((9, 6, 1)));
/// assert!(!check_ssh_version_minimum((7, 9, 0)));
/// ```
pub fn check_ssh_version_minimum(version: (u32, u32, u32)) -> bool {
    version >= MIN_SSH_VERSION
}

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
        &[
            "git_version",
            "git_version_minimum",
            "ssh_keygen",
            "ssh_version",
            "git_signing_config",
            "git_user_config",
        ]
    }

    /// Run a single diagnostic check by name.
    ///
    /// Returns `Err(DiagnosticError::CheckNotFound)` if the name is unknown.
    pub fn run_single(&self, name: &str) -> Result<CheckResult, DiagnosticError> {
        match name {
            "git_version" => self.git.check_git_version(),
            "git_version_minimum" => {
                let git_check = self.git.check_git_version()?;
                let mut checks = Vec::new();
                self.check_git_version_minimum(&git_check, &mut checks);
                checks
                    .into_iter()
                    .next()
                    .ok_or_else(|| DiagnosticError::CheckNotFound(name.to_string()))
            }
            "ssh_keygen" => self.crypto.check_ssh_keygen_available(),
            "ssh_version" => {
                let mut checks = Vec::new();
                self.check_ssh_version_minimum(&mut checks);
                checks
                    .into_iter()
                    .next()
                    .ok_or_else(|| DiagnosticError::CheckNotFound(name.to_string()))
            }
            "git_signing_config" => {
                let mut checks = Vec::new();
                self.check_git_signing_config(&mut checks)?;
                checks
                    .into_iter()
                    .next()
                    .ok_or_else(|| DiagnosticError::CheckNotFound(name.to_string()))
            }
            "git_user_config" => {
                let mut checks = Vec::new();
                self.check_git_user_config(&mut checks)?;
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

        let git_check = self.git.check_git_version()?;
        self.check_git_version_minimum(&git_check, &mut checks);
        checks.push(git_check);

        checks.push(self.crypto.check_ssh_keygen_available()?);
        self.check_ssh_version_minimum(&mut checks);

        self.check_git_user_config(&mut checks)?;
        self.check_git_signing_config(&mut checks)?;

        Ok(DiagnosticReport { checks })
    }

    fn check_git_version_minimum(&self, git_check: &CheckResult, checks: &mut Vec<CheckResult>) {
        let version_str = git_check.message.as_deref().unwrap_or("");
        match parse_git_version(version_str) {
            Some(version) if version >= MIN_GIT_VERSION => {
                checks.push(CheckResult {
                    name: "Git version".to_string(),
                    passed: true,
                    message: Some(format!(
                        "{}.{}.{} (>= {}.{}.{})",
                        version.0,
                        version.1,
                        version.2,
                        MIN_GIT_VERSION.0,
                        MIN_GIT_VERSION.1,
                        MIN_GIT_VERSION.2,
                    )),
                    config_issues: vec![],
                    category: CheckCategory::Critical,
                });
            }
            Some(version) => {
                checks.push(CheckResult {
                    name: "Git version".to_string(),
                    passed: false,
                    message: Some(format!(
                        "{}.{}.{} found, need >= {}.{}.{} for SSH signing",
                        version.0,
                        version.1,
                        version.2,
                        MIN_GIT_VERSION.0,
                        MIN_GIT_VERSION.1,
                        MIN_GIT_VERSION.2,
                    )),
                    config_issues: vec![],
                    category: CheckCategory::Critical,
                });
            }
            None => {
                if !git_check.passed {
                    return;
                }
                checks.push(CheckResult {
                    name: "Git version".to_string(),
                    passed: false,
                    message: Some(format!("Could not parse version from: {version_str}")),
                    config_issues: vec![],
                    category: CheckCategory::Advisory,
                });
            }
        }
    }

    fn check_ssh_version_minimum(&self, checks: &mut Vec<CheckResult>) {
        let version_str = match self.crypto.check_ssh_version() {
            Ok(v) => v,
            Err(_) => return,
        };

        if version_str == "unknown" {
            return;
        }

        match parse_ssh_version(&version_str) {
            Some(version) if check_ssh_version_minimum(version) => {
                checks.push(CheckResult {
                    name: "SSH version".to_string(),
                    passed: true,
                    message: Some(format!(
                        "{}.{}.{} (>= {}.{}.{})",
                        version.0,
                        version.1,
                        version.2,
                        MIN_SSH_VERSION.0,
                        MIN_SSH_VERSION.1,
                        MIN_SSH_VERSION.2,
                    )),
                    config_issues: vec![],
                    category: CheckCategory::Advisory,
                });
            }
            Some(version) => {
                checks.push(CheckResult {
                    name: "SSH version".to_string(),
                    passed: false,
                    message: Some(format!(
                        "{}.{}.{} found, need >= {}.{}.{} for -Y find-principals",
                        version.0,
                        version.1,
                        version.2,
                        MIN_SSH_VERSION.0,
                        MIN_SSH_VERSION.1,
                        MIN_SSH_VERSION.2,
                    )),
                    config_issues: vec![],
                    category: CheckCategory::Advisory,
                });
            }
            None => {
                checks.push(CheckResult {
                    name: "SSH version".to_string(),
                    passed: false,
                    message: Some(format!("Could not parse version from: {version_str}")),
                    config_issues: vec![],
                    category: CheckCategory::Advisory,
                });
            }
        }
    }

    fn check_git_user_config(&self, checks: &mut Vec<CheckResult>) -> Result<(), DiagnosticError> {
        let name = self.git.get_git_config("user.name")?;
        let email = self.git.get_git_config("user.email")?;

        let mut issues: Vec<ConfigIssue> = Vec::new();
        if name.is_none() {
            issues.push(ConfigIssue::Absent("user.name".to_string()));
        }
        if email.is_none() {
            issues.push(ConfigIssue::Absent("user.email".to_string()));
        }

        let passed = issues.is_empty();
        let message = if passed {
            Some(format!(
                "{} <{}>",
                name.unwrap_or_default(),
                email.unwrap_or_default()
            ))
        } else {
            None
        };

        checks.push(CheckResult {
            name: "Git user identity".to_string(),
            passed,
            message,
            config_issues: issues,
            category: CheckCategory::Advisory,
        });

        Ok(())
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
            category: CheckCategory::Critical,
        });

        Ok(())
    }
}
