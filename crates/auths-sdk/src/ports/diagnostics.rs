//! Diagnostic provider ports for system health checks.
//!
//! Follows Interface Segregation: one trait per tool category so tests
//! only mock what they need.

use serde::{Deserialize, Serialize};

/// A structured issue found during git signing configuration checks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ConfigIssue {
    /// A key exists but has the wrong value.
    Mismatch {
        /// The git config key name.
        key: String,
        /// The expected value.
        expected: String,
        /// The actual value found.
        actual: String,
    },
    /// A required key is not set.
    Absent(String),
}

/// Result of a single diagnostic check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    /// Human-readable name of the diagnostic check.
    pub name: String,
    /// Whether the check passed.
    pub passed: bool,
    /// Free-form informational text (e.g. version strings).
    pub message: Option<String>,
    /// Structured config issues — populated only by config checks.
    #[serde(default)]
    pub config_issues: Vec<ConfigIssue>,
}

/// Aggregated diagnostic report.
#[derive(Debug, Serialize, Deserialize)]
pub struct DiagnosticReport {
    /// All individual check results in the report.
    pub checks: Vec<CheckResult>,
}

/// Errors from diagnostic check execution.
#[derive(Debug, thiserror::Error)]
pub enum DiagnosticError {
    /// A diagnostic check failed to execute.
    #[error("check failed to execute: {0}")]
    ExecutionFailed(String),
}

/// Port for Git-related diagnostic checks.
///
/// Usage:
/// ```ignore
/// let result = provider.check_git_version()?;
/// let config_val = provider.get_git_config("user.email")?;
/// ```
pub trait GitDiagnosticProvider: Send + Sync {
    /// Check that git is installed and return version info.
    fn check_git_version(&self) -> Result<CheckResult, DiagnosticError>;

    /// Read a global git config value, returning `None` if unset.
    fn get_git_config(&self, key: &str) -> Result<Option<String>, DiagnosticError>;
}

/// Port for cryptographic tool diagnostic checks.
///
/// Usage:
/// ```ignore
/// let result = provider.check_ssh_keygen_available()?;
/// ```
pub trait CryptoDiagnosticProvider: Send + Sync {
    /// Check that ssh-keygen is available on the system.
    fn check_ssh_keygen_available(&self) -> Result<CheckResult, DiagnosticError>;
}

impl<T: GitDiagnosticProvider> GitDiagnosticProvider for &T {
    fn check_git_version(&self) -> Result<CheckResult, DiagnosticError> {
        (**self).check_git_version()
    }
    fn get_git_config(&self, key: &str) -> Result<Option<String>, DiagnosticError> {
        (**self).get_git_config(key)
    }
}

impl<T: CryptoDiagnosticProvider> CryptoDiagnosticProvider for &T {
    fn check_ssh_keygen_available(&self) -> Result<CheckResult, DiagnosticError> {
        (**self).check_ssh_keygen_available()
    }
}
