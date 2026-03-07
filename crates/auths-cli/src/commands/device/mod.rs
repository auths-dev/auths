pub mod authorization;
pub mod pair;
pub mod verify_attestation;

pub use authorization::{DeviceCommand, DeviceSubcommand, handle_device};
pub use pair::{PairCommand, handle_pair};
pub use verify_attestation::{VerifyCommand, handle_verify};

use crate::commands::executable::ExecutableCommand;
use crate::config::CliConfig;
use anyhow::Result;

impl ExecutableCommand for PairCommand {
    fn execute(&self, ctx: &CliConfig) -> Result<()> {
        handle_pair(self.clone(), &ctx.env_config)
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
