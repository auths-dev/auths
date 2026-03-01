use anyhow::Result;

use crate::config::CliConfig;

pub trait ExecutableCommand {
    fn execute(&self, ctx: &CliConfig) -> Result<()>;
}
