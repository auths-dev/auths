pub mod authorization;
pub mod pair;
pub mod verify_attestation;

pub use authorization::{DeviceCommand, DeviceSubcommand, handle_device};
pub use pair::{PairCommand, handle_pair};
pub use verify_attestation::{VerifyCommand, handle_verify};

use crate::commands::executable::ExecutableCommand;
use crate::config::CliConfig;
use anyhow::{Context, Result};

impl ExecutableCommand for PairCommand {
    fn execute(&self, ctx: &CliConfig) -> Result<()> {
        // Pairing resolves its store from `env_config.auths_home`. When `--repo`
        // is given, fold the resolved registry path into a derived config so the
        // pairing store is scoped to that repo. Absent `--repo`, the unchanged
        // config preserves the AUTHS_HOME / `~/.auths` default.
        let env_config = match &ctx.repo_path {
            Some(_) => {
                let registry = auths_sdk::storage_layout::resolve_repo_path(ctx.repo_path.clone())
                    .context("Failed to resolve the repository path for the pairing store")?;
                let mut scoped = ctx.env_config.clone();
                scoped.auths_home = Some(registry);
                scoped
            }
            None => ctx.env_config.clone(),
        };

        handle_pair(self.clone(), ctx.passphrase_provider.clone(), &env_config)
    }
}

impl ExecutableCommand for DeviceCommand {
    fn execute(&self, ctx: &CliConfig) -> Result<()> {
        handle_device(
            self.clone(),
            ctx.repo_path.clone(),
            self.overrides.identity_ref.clone(),
            self.overrides.identity_blob.clone(),
            self.overrides.attestation_prefix.clone(),
            self.overrides.attestation_blob.clone(),
            ctx.passphrase_provider.clone(),
            &ctx.env_config,
        )
    }
}
