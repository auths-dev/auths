use anyhow::Result;
use clap::{Args, Subcommand};

use crate::commands::cache::CacheCommand;
use crate::commands::executable::ExecutableCommand;
use crate::commands::index::IndexCommand;
use crate::commands::utils::UtilCommand;
use crate::config::CliConfig;

#[derive(Args, Debug, Clone)]
#[command(about = "Internal debugging utilities")]
pub struct DebugCmd {
    #[command(subcommand)]
    pub command: DebugSubcommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum DebugSubcommand {
    Cache(CacheCommand),
    Index(IndexCommand),
    Util(UtilCommand),
}

impl ExecutableCommand for DebugCmd {
    fn execute(&self, ctx: &CliConfig) -> Result<()> {
        match &self.command {
            DebugSubcommand::Cache(cmd) => cmd.execute(ctx),
            DebugSubcommand::Index(cmd) => cmd.execute(ctx),
            DebugSubcommand::Util(cmd) => cmd.execute(ctx),
        }
    }
}
