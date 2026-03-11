pub mod claim;
pub mod identity;
pub mod migrate;
pub mod register;

pub use identity::{IdCommand, IdSubcommand, LayoutPreset, handle_id};
pub use migrate::{MigrateCommand, handle_migrate};
pub use register::DEFAULT_REGISTRY_URL;

use crate::commands::executable::ExecutableCommand;
use crate::config::CliConfig;
use anyhow::Result;

impl ExecutableCommand for IdCommand {
    #[allow(clippy::disallowed_methods)]
    fn execute(&self, ctx: &CliConfig) -> Result<()> {
        handle_id(
            self.clone(),
            ctx.repo_path.clone(),
            self.overrides.identity_ref.clone(),
            self.overrides.identity_blob.clone(),
            self.overrides.attestation_prefix.clone(),
            self.overrides.attestation_blob.clone(),
            ctx.passphrase_provider.clone(),
            &ctx.env_config,
            chrono::Utc::now(),
        )
    }
}
