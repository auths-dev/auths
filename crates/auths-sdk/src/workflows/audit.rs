//! Audit workflow for commit signing compliance analysis.
//!
//! Produces structured audit reports from git commit history.
//! All I/O is abstracted behind the `GitLogProvider` port.

use crate::ports::git::{CommitRecord, GitLogProvider, GitProviderError, SignatureStatus};
use serde::{Deserialize, Serialize};

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
