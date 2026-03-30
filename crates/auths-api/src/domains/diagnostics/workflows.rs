use auths_sdk::ports::diagnostics::{
    CheckCategory, CheckResult, ConfigIssue, CryptoDiagnosticProvider, DiagnosticError,
    DiagnosticReport, GitDiagnosticProvider,
};
use auths_sdk::ports::git::{CommitRecord, GitLogProvider, GitProviderError, SignatureStatus};
use auths_sdk::result::{
    AgentStatus, DeviceReadiness, DeviceStatus, IdentityStatus, NextStep, StatusReport,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;

// ── Diagnostics Workflow ──────────────────────────────────────────────────────

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
            category: CheckCategory::Critical,
        });

        Ok(())
    }
}

// ── Status Workflow ───────────────────────────────────────────────────────────

/// Status workflow for reporting Auths state.
///
/// This workflow aggregates information from identity storage, device attestations,
/// and agent status to produce a unified StatusReport suitable for CLI display.
///
/// Usage:
/// ```ignore
/// let report = StatusWorkflow::query(&ctx, Utc::now())?;
/// println!("Identity: {}", report.identity.controller_did);
/// ```
pub struct StatusWorkflow;

impl StatusWorkflow {
    /// Query the current status of the Auths system.
    ///
    /// Args:
    /// * `repo_path` - Path to the Auths repository.
    /// * `now` - Current time for expiry calculations.
    ///
    /// Returns a StatusReport with identity, device, and agent state.
    ///
    /// This is a placeholder implementation; the real version will integrate
    /// with IdentityStorage, AttestationSource, and agent discovery ports.
    pub fn query(repo_path: &Path, _now: DateTime<Utc>) -> Result<StatusReport, String> {
        let _ = repo_path; // Placeholder to avoid unused warning
        // TODO: In full implementation, load identity from IdentityStorage
        let identity = None; // Placeholder

        // TODO: In full implementation, load attestations from AttestationSource
        // and aggregate by device with expiry checking
        let devices = Vec::new(); // Placeholder

        // TODO: In full implementation, check agent socket and PID
        let agent = AgentStatus {
            running: false,
            pid: None,
            socket_path: None,
        };

        // Compute next steps based on current state
        let next_steps = Self::compute_next_steps(&identity, &devices, &agent);

        Ok(StatusReport {
            identity,
            devices,
            agent,
            next_steps,
        })
    }

    /// Compute suggested next steps based on current state.
    fn compute_next_steps(
        identity: &Option<IdentityStatus>,
        devices: &[DeviceStatus],
        agent: &AgentStatus,
    ) -> Vec<NextStep> {
        let mut steps = Vec::new();

        // No identity initialized
        if identity.is_none() {
            steps.push(NextStep {
                summary: "Initialize your identity".to_string(),
                command: "auths init --profile developer".to_string(),
            });
            return steps;
        }

        // No devices linked
        if devices.is_empty() {
            steps.push(NextStep {
                summary: "Link this device to your identity".to_string(),
                command: "auths pair".to_string(),
            });
        }

        // Device expiring soon
        let expiring_soon = devices
            .iter()
            .filter(|d| d.readiness == DeviceReadiness::ExpiringSoon)
            .count();
        if expiring_soon > 0 {
            steps.push(NextStep {
                summary: format!("{} device(s) expiring soon", expiring_soon),
                command: "auths device extend".to_string(),
            });
        }

        // Agent not running
        if !agent.running {
            steps.push(NextStep {
                summary: "Start the authentication agent for signing".to_string(),
                command: "auths agent start".to_string(),
            });
        }

        // Always suggest viewing help for deeper features
        if steps.is_empty() {
            steps.push(NextStep {
                summary: "Explore advanced features".to_string(),
                command: "auths --help-all".to_string(),
            });
        }

        steps
    }

    /// Determine device readiness given expiration timestamps.
    pub fn compute_readiness(
        expires_at: Option<DateTime<Utc>>,
        revoked_at: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) -> DeviceReadiness {
        if revoked_at.is_some() {
            return DeviceReadiness::Revoked;
        }

        match expires_at {
            Some(exp) if exp < now => DeviceReadiness::Expired,
            Some(exp) if exp - now < Duration::days(7) => DeviceReadiness::ExpiringSoon,
            Some(_) => DeviceReadiness::Ok,
            None => DeviceReadiness::Ok, // No expiry set
        }
    }
}

// ── Audit Workflow ────────────────────────────────────────────────────────────

/// Errors from audit workflow execution.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    /// A git provider error occurred while reading commit history.
    #[error("git provider error: {0}")]
    Provider(#[from] GitProviderError),
}

/// Structured audit report with commit entries and summary statistics.
///
/// Usage:
/// ```ignore
/// let report = workflow.generate_report(None, Some(100))?;
/// println!("Total: {}, Signed: {}", report.summary.total_commits, report.summary.signed_commits);
/// ```
#[derive(Debug)]
pub struct AuditReport {
    /// All commit records in the audited range.
    pub commits: Vec<CommitRecord>,
    /// Aggregate statistics for the commit set.
    pub summary: AuditSummary,
}

/// Summary statistics for an audit report.
///
/// `verification_failed` counts commits that carry a signing attempt (including
/// `InvalidSignature`) but did not pass verification. This matches the CLI
/// definition: `signed_commits - verification_passed`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSummary {
    /// Total number of commits in the audited range.
    pub total_commits: usize,
    /// Commits with any signing attempt (including invalid signatures).
    pub signed_commits: usize,
    /// Commits with no signing attempt.
    pub unsigned_commits: usize,
    /// Commits signed with the auths workflow.
    pub auths_signed: usize,
    /// Commits signed with GPG.
    pub gpg_signed: usize,
    /// Commits signed with SSH.
    pub ssh_signed: usize,
    /// Signed commits whose signature verified successfully.
    pub verification_passed: usize,
    /// Signed commits whose signature did not verify.
    pub verification_failed: usize,
}

/// Workflow that generates audit compliance reports from commit history.
///
/// Args:
/// * `provider`: A `GitLogProvider` implementation for reading commits.
///
/// Usage:
/// ```ignore
/// let workflow = AuditWorkflow::new(&my_provider);
/// let report = workflow.generate_report(None, Some(100))?;
/// ```
pub struct AuditWorkflow<'a, G: GitLogProvider> {
    provider: &'a G,
}

impl<'a, G: GitLogProvider> AuditWorkflow<'a, G> {
    /// Create a new `AuditWorkflow` backed by the given provider.
    pub fn new(provider: &'a G) -> Self {
        Self { provider }
    }

    /// Generate an audit report from the repository's commit history.
    ///
    /// Args:
    /// * `range`: Optional git revision range spec.
    /// * `limit`: Optional maximum number of commits.
    pub fn generate_report(
        &self,
        range: Option<&str>,
        limit: Option<usize>,
    ) -> Result<AuditReport, AuditError> {
        let commits = self.provider.walk_commits(range, limit)?;
        let summary = summarize_commits(&commits);
        Ok(AuditReport { commits, summary })
    }
}

/// Compute an `AuditSummary` from a slice of commit records.
///
/// Args:
/// * `commits`: The commit records to summarize.
///
/// Usage:
/// ```ignore
/// let summary = summarize_commits(&filtered_commits);
/// ```
pub fn summarize_commits(commits: &[CommitRecord]) -> AuditSummary {
    let total_commits = commits.len();
    let mut signed_commits = 0usize;
    let mut auths_signed = 0usize;
    let mut gpg_signed = 0usize;
    let mut ssh_signed = 0usize;
    let mut verification_passed = 0usize;

    for c in commits {
        match &c.signature_status {
            SignatureStatus::AuthsSigned { .. } => {
                signed_commits += 1;
                auths_signed += 1;
                verification_passed += 1;
            }
            SignatureStatus::SshSigned => {
                signed_commits += 1;
                ssh_signed += 1;
            }
            SignatureStatus::GpgSigned { verified } => {
                signed_commits += 1;
                gpg_signed += 1;
                if *verified {
                    verification_passed += 1;
                }
            }
            SignatureStatus::InvalidSignature { .. } => {
                signed_commits += 1;
            }
            SignatureStatus::Unsigned => {}
        }
    }

    AuditSummary {
        total_commits,
        unsigned_commits: total_commits - signed_commits,
        verification_failed: signed_commits - verification_passed,
        signed_commits,
        auths_signed,
        gpg_signed,
        ssh_signed,
        verification_passed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::disallowed_methods)]
    fn test_compute_readiness_revoked() {
        let now = Utc::now();
        let readiness =
            StatusWorkflow::compute_readiness(None, Some(now - Duration::hours(1)), now);
        assert_eq!(readiness, DeviceReadiness::Revoked);
    }

    #[test]
    #[allow(clippy::disallowed_methods)]
    fn test_compute_readiness_expired() {
        let now = Utc::now();
        let exp = now - Duration::days(1);
        let readiness = StatusWorkflow::compute_readiness(Some(exp), None, now);
        assert_eq!(readiness, DeviceReadiness::Expired);
    }

    #[test]
    #[allow(clippy::disallowed_methods)]
    fn test_compute_readiness_expiring_soon() {
        let now = Utc::now();
        let exp = now + Duration::days(3);
        let readiness = StatusWorkflow::compute_readiness(Some(exp), None, now);
        assert_eq!(readiness, DeviceReadiness::ExpiringSoon);
    }

    #[test]
    #[allow(clippy::disallowed_methods)]
    fn test_compute_readiness_ok() {
        let now = Utc::now();
        let exp = now + Duration::days(30);
        let readiness = StatusWorkflow::compute_readiness(Some(exp), None, now);
        assert_eq!(readiness, DeviceReadiness::Ok);
    }

    #[test]
    fn test_next_steps_no_identity() {
        let steps = StatusWorkflow::compute_next_steps(
            &None,
            &[],
            &AgentStatus {
                running: false,
                pid: None,
                socket_path: None,
            },
        );
        assert!(!steps.is_empty());
        assert!(steps[0].command.contains("init"));
    }
}
