use anyhow::Result;
use clap::{Args, Subcommand};

use crate::commands::executable::ExecutableCommand;
use crate::commands::sign::SignCommand;
use crate::commands::verify_commit::VerifyCommitCommand;
use crate::config::CliConfig;

#[derive(Args, Debug, Clone)]
pub struct CommitCmd {
    #[command(subcommand)]
    pub command: CommitSubcommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum CommitSubcommand {
    Sign(SignCommand),
    Verify(VerifyCommitCommand),
}

impl ExecutableCommand for CommitCmd {
    fn execute(&self, ctx: &CliConfig) -> Result<()> {
        match &self.command {
            CommitSubcommand::Sign(cmd) => cmd.execute(ctx),
            CommitSubcommand::Verify(cmd) => cmd.execute(ctx),
        }
    }
}
