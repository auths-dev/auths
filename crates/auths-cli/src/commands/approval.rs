//! CLI command for approval management.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::commands::executable::ExecutableCommand;
use crate::config::CliConfig;

/// Exit code when a command's policy evaluation returns RequiresApproval.
/// Value 75 = EX_TEMPFAIL (sysexits.h) — "temporary failure, try again later."
pub const EXIT_APPROVAL_REQUIRED: i32 = 75;

#[derive(Parser, Debug)]
#[command(
    about = "Manage approval gates",
    after_help = "Examples:
  auths approval list       # Show pending approval requests
  auths approval grant --request <hash> --note 'Reviewed and approved'
                            # Grant approval for a request

Exit Codes:
  75 — Approval required (TEMPFAIL) — operation needs authorization

Related:
  auths policy  — Manage capability policies
  auths status  — Check system status"
)]
pub struct ApprovalCommand {
    #[command(subcommand)]
    pub command: ApprovalSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum ApprovalSubcommand {
    /// List pending approval requests.
    List(ApprovalListCommand),
    /// Grant approval for a pending request.
    Grant(ApprovalGrantCommand),
}

#[derive(Parser, Debug)]
pub struct ApprovalListCommand {}

#[derive(Parser, Debug)]
pub struct ApprovalGrantCommand {
    /// The request hash to approve (hex-encoded).
    #[arg(long)]
    pub request: String,
    /// Optional note for the approval.
    #[arg(long)]
    pub note: Option<String>,
}

impl ExecutableCommand for ApprovalCommand {
    fn execute(&self, _ctx: &CliConfig) -> Result<()> {
        match &self.command {
            ApprovalSubcommand::List(_cmd) => {
                println!("No pending approval requests.");
                Ok(())
            }
            ApprovalSubcommand::Grant(cmd) => {
                println!(
                    "Approval grant for request {} — not yet wired to storage backend.",
                    cmd.request
                );
                Ok(())
            }
        }
    }
}
