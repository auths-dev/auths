//! Audit and compliance reporting commands.
//!
//! Thin CLI wrapper that wires `Git2LogProvider` into `AuditWorkflow`
//! and formats the output.

use crate::ux::format::Output;
use anyhow::{Context, Result, anyhow};
use auths_infra_git::audit::Git2LogProvider;
use auths_sdk::ports::git::{CommitRecord, SignatureStatus};
use auths_sdk::presentation::html::render_audit_html;
use auths_sdk::workflows::audit::{AuditSummary, AuditWorkflow, summarize_commits};
use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Audit and compliance reporting.
#[derive(Parser, Debug, Clone)]
#[command(
    name = "audit",
    about = "Generate signing audit reports for compliance"
)]
pub struct AuditCommand {
    /// Path to the Git repository to audit (defaults to current directory).
    #[arg(long, default_value = ".")]
    pub repo: PathBuf,

    /// Start date for audit period (YYYY-MM-DD or YYYY-QN for quarter).
    #[arg(long)]
    pub since: Option<String>,

    /// End date for audit period (YYYY-MM-DD).
    #[arg(long)]
    pub until: Option<String>,

    /// Output format.
    #[arg(long, value_enum, default_value = "table")]
    pub format: OutputFormat,

    /// Require all commits to be signed (for CI exit codes).
    #[arg(long)]
    pub require_all_signed: bool,

    /// Return exit code 1 if any unsigned commits found.
    #[arg(long)]
    pub exit_code: bool,

    /// Filter by author email.
    #[arg(long)]
    pub author: Option<String>,

    /// Filter by signing identity/device DID.
    #[arg(long)]
    pub signer: Option<String>,

    /// Maximum number of commits to include.
    #[arg(long, short = 'n', default_value = "100")]
    pub count: usize,

    /// Output file path (defaults to stdout).
    #[arg(long, short = 'o')]
    pub output_file: Option<PathBuf>,
}

/// Output format for audit reports.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum OutputFormat {
    /// ASCII table format.
    #[default]
    Table,
    /// CSV format.
    Csv,
    /// JSON format.
    Json,
    /// HTML report.
    Html,
}

/// A single commit audit entry (CLI presentation type).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitAuditEntry {
    pub hash: String,
    pub timestamp: String,
    pub author_name: String,
    pub author_email: String,
    pub message: String,
    pub signing_method: String,
    pub signer: Option<String>,
    pub verified: bool,
}

/// Full audit report (CLI presentation type).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub generated_at: String,
    pub repository: String,
    pub period_start: Option<String>,
    pub period_end: Option<String>,
    pub summary: AuditSummary,
    pub commits: Vec<CommitAuditEntry>,
}

/// Handle the audit command.
#[allow(clippy::disallowed_methods)]
pub fn handle_audit(cmd: AuditCommand) -> Result<()> {
    let now = chrono::Utc::now();
    let out = Output::new();

    let since = cmd.since.as_ref().map(|s| parse_date_arg(s)).transpose()?;
    let until = cmd.until.clone();

    let provider = Git2LogProvider::open(&cmd.repo)
        .with_context(|| format!("Failed to open repository at {:?}", cmd.repo))?;
    let workflow = AuditWorkflow::new(&provider);
    let sdk_report = workflow
        .generate_report(None, Some(cmd.count))
        .context("Failed to generate audit report")?;

    let mut commits: Vec<CommitRecord> = sdk_report.commits;

    if let Some(author_filter) = &cmd.author {
        commits.retain(|c| c.author_email.contains(author_filter.as_str()));
    }
    if let Some(signer_filter) = &cmd.signer {
        commits.retain(|c| {
            matches!(&c.signature_status, SignatureStatus::AuthsSigned { signer_did } if signer_did.contains(signer_filter.as_str()))
        });
    }

    let summary = summarize_commits(&commits);
    let unsigned_commits = summary.unsigned_commits;
    let generated_at = now.to_rfc3339();
    let repository = cmd.repo.display().to_string();

    let output = match cmd.format {
        OutputFormat::Html => render_audit_html(&generated_at, &repository, &summary, &commits),
        _ => {
            let entries: Vec<CommitAuditEntry> =
                commits.iter().map(commit_record_to_entry).collect();
            let report = AuditReport {
                generated_at,
                repository,
                period_start: since,
                period_end: until,
                summary,
                commits: entries,
            };
            match cmd.format {
                OutputFormat::Table => format_as_table(&report),
                OutputFormat::Csv => format_as_csv(&report),
                OutputFormat::Json => serde_json::to_string_pretty(&report)?,
                OutputFormat::Html => unreachable!(),
            }
        }
    };

    if let Some(output_path) = &cmd.output_file {
        std::fs::write(output_path, &output)
            .with_context(|| format!("Failed to write report to {:?}", output_path))?;
        out.print_success(&format!("Report saved to {}", output_path.display()));
    } else {
        println!("{}", output);
    }

    if (cmd.exit_code || cmd.require_all_signed) && unsigned_commits > 0 {
        if cmd.require_all_signed {
            out.print_error(&format!("{} unsigned commits found", unsigned_commits));
        }
        std::process::exit(1);
    }

    Ok(())
}

/// Parse date argument, handling quarter format (YYYY-QN).
fn parse_date_arg(arg: &str) -> Result<String> {
    if let Some(caps) = arg
        .strip_suffix("-Q1")
        .or_else(|| arg.strip_suffix("-Q2"))
        .or_else(|| arg.strip_suffix("-Q3"))
        .or_else(|| arg.strip_suffix("-Q4"))
    {
        let year = caps;
        let quarter = &arg[arg.len() - 2..];
        let month = match quarter {
            "Q1" => "01-01",
            "Q2" => "04-01",
            "Q3" => "07-01",
            "Q4" => "10-01",
            _ => return Err(anyhow!("Invalid quarter format")),
        };
        return Ok(format!("{}-{}", year, month));
    }

    Ok(arg.to_string())
}

fn commit_record_to_entry(c: &CommitRecord) -> CommitAuditEntry {
    let (signing_method, verified, signer) = match &c.signature_status {
        SignatureStatus::AuthsSigned { signer_did } => {
            ("auths".to_string(), true, Some(signer_did.clone()))
        }
        SignatureStatus::SshSigned => ("ssh".to_string(), false, None),
        SignatureStatus::GpgSigned { verified } => ("gpg".to_string(), *verified, None),
        SignatureStatus::Unsigned => ("none".to_string(), false, None),
        SignatureStatus::InvalidSignature { reason } => {
            ("invalid".to_string(), false, Some(reason.clone()))
        }
    };
    CommitAuditEntry {
        hash: c.hash.clone(),
        timestamp: c.timestamp.clone(),
        author_name: c.author_name.clone(),
        author_email: c.author_email.clone(),
        message: c.message.clone(),
        signing_method,
        signer,
        verified,
    }
}

/// Format report as ASCII table.
fn format_as_table(report: &AuditReport) -> String {
    let mut output = String::new();

    output.push_str("Audit Report\n");
    output.push_str(&format!("Generated: {}\n", report.generated_at));
    output.push_str(&format!("Repository: {}\n", report.repository));
    if let Some(start) = &report.period_start {
        output.push_str(&format!(
            "Period: {} to {}\n",
            start,
            report.period_end.as_deref().unwrap_or("now")
        ));
    }
    output.push('\n');

    output.push_str("Summary\n");
    output.push_str("-------\n");
    output.push_str(&format!(
        "Total commits:      {:>5}\n",
        report.summary.total_commits
    ));
    output.push_str(&format!(
        "Signed commits:     {:>5} ({:.0}%)\n",
        report.summary.signed_commits,
        if report.summary.total_commits > 0 {
            (report.summary.signed_commits as f64 / report.summary.total_commits as f64) * 100.0
        } else {
            0.0
        }
    ));
    output.push_str(&format!(
        "Unsigned commits:   {:>5} ({:.0}%)\n",
        report.summary.unsigned_commits,
        if report.summary.total_commits > 0 {
            (report.summary.unsigned_commits as f64 / report.summary.total_commits as f64) * 100.0
        } else {
            0.0
        }
    ));
    output.push_str(&format!(
        "  - GPG signed:     {:>5}\n",
        report.summary.gpg_signed
    ));
    output.push_str(&format!(
        "  - SSH signed:     {:>5}\n",
        report.summary.ssh_signed
    ));
    output.push_str(&format!(
        "  - Auths signed:   {:>5}\n",
        report.summary.auths_signed
    ));
    output.push_str(&format!(
        "Verification passed:{:>5}\n",
        report.summary.verification_passed
    ));
    output.push('\n');

    output.push_str("Commits\n");
    output.push_str("-------\n");
    output.push_str(&format!(
        "{:<10} {:<20} {:<25} {:<8} {:<8}\n",
        "Hash", "Date", "Author", "Method", "Verified"
    ));
    output.push_str(&"-".repeat(80));
    output.push('\n');

    for commit in &report.commits {
        let date = if commit.timestamp.len() >= 10 {
            &commit.timestamp[..10]
        } else {
            &commit.timestamp
        };
        let author = if commit.author_name.len() > 23 {
            format!("{}...", &commit.author_name[..20])
        } else {
            commit.author_name.clone()
        };
        let verified = if commit.signing_method == "none" {
            "-"
        } else if commit.verified {
            "yes"
        } else {
            "no"
        };

        output.push_str(&format!(
            "{:<10} {:<20} {:<25} {:<8} {:<8}\n",
            commit.hash, date, author, commit.signing_method, verified
        ));
    }

    output
}

/// Format report as CSV.
fn format_as_csv(report: &AuditReport) -> String {
    let mut output = String::new();

    output.push_str(
        "hash,timestamp,author_name,author_email,message,signing_method,signer,verified\n",
    );

    for commit in &report.commits {
        output.push_str(&format!(
            "{},{},\"{}\",{},\"{}\",{},{},{}\n",
            commit.hash,
            commit.timestamp,
            commit.author_name.replace('"', "\"\""),
            commit.author_email,
            commit.message.replace('"', "\"\""),
            commit.signing_method,
            commit.signer.as_deref().unwrap_or(""),
            commit.verified
        ));
    }

    output
}

use crate::commands::executable::ExecutableCommand;
use crate::config::CliConfig;

impl ExecutableCommand for AuditCommand {
    fn execute(&self, _ctx: &CliConfig) -> Result<()> {
        handle_audit(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_date_arg_quarter() {
        assert_eq!(parse_date_arg("2024-Q1").unwrap(), "2024-01-01");
        assert_eq!(parse_date_arg("2024-Q2").unwrap(), "2024-04-01");
        assert_eq!(parse_date_arg("2024-Q3").unwrap(), "2024-07-01");
        assert_eq!(parse_date_arg("2024-Q4").unwrap(), "2024-10-01");
    }

    #[test]
    fn test_parse_date_arg_date() {
        assert_eq!(parse_date_arg("2024-01-15").unwrap(), "2024-01-15");
    }

    #[test]
    fn test_summarize_commits() {
        use auths_sdk::ports::git::{CommitRecord, SignatureStatus};
        let commits = vec![
            CommitRecord {
                hash: "abc123".to_string(),
                timestamp: "2024-01-15T10:00:00Z".to_string(),
                author_name: "Test".to_string(),
                author_email: "test@example.com".to_string(),
                message: "test".to_string(),
                signature_status: SignatureStatus::GpgSigned { verified: true },
            },
            CommitRecord {
                hash: "def456".to_string(),
                timestamp: "2024-01-16T10:00:00Z".to_string(),
                author_name: "Test".to_string(),
                author_email: "test@example.com".to_string(),
                message: "test".to_string(),
                signature_status: SignatureStatus::Unsigned,
            },
        ];

        let summary = summarize_commits(&commits);
        assert_eq!(summary.total_commits, 2);
        assert_eq!(summary.signed_commits, 1);
        assert_eq!(summary.unsigned_commits, 1);
        assert_eq!(summary.gpg_signed, 1);
        assert_eq!(summary.verification_passed, 1);
    }
}
