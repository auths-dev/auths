//! CI/CD integration commands — setup and rotate CI signing secrets.

pub mod forge_backend;
pub mod rotate;
pub mod setup;

/// Key alias used by all CI commands (setup, rotate).
pub(crate) const CI_DEVICE_ALIAS: &str = "ci-release-device";

use anyhow::Result;
use clap::{Args, Subcommand};
use std::sync::Arc;

use auths_sdk::signing::PassphraseProvider;
use auths_sdk::storage_layout::layout;

use crate::commands::executable::ExecutableCommand;
use crate::config::CliConfig;

/// CI/CD integration (setup, rotate secrets).
#[derive(Args, Debug, Clone)]
#[command(
    about = "CI/CD integration — set up and rotate CI signing secrets.",
    after_help = "Examples:
  auths ci setup             # Auto-detect forge, set AUTHS_CI_TOKEN
  auths ci setup --repo owner/repo
                             # Specify target repo
  auths ci rotate            # Refresh token, reuse device key
  auths ci rotate --max-age-secs 7776000
                             # Rotate with 90-day TTL

Related:
  auths device   — Manage device authorizations
  auths key      — Manage cryptographic keys
  auths init     — Set up identity"
)]
pub struct CiCommand {
    #[command(subcommand)]
    pub command: CiSubcommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum CiSubcommand {
    /// Set up CI secrets for release artifact signing and verification.
    Setup {
        /// Target repo. Accepts `owner/repo`, HTTPS URL, or SSH URL.
        /// Defaults to git remote origin.
        #[arg(long)]
        repo: Option<String>,

        /// Max age for the verification bundle in seconds (default: 1 year).
        #[arg(long, default_value = "31536000")]
        max_age_secs: u64,

        /// Disable auto-generated passphrase and prompt interactively instead.
        #[arg(long)]
        manual_passphrase: bool,
    },

    /// Rotate an existing CI token (regenerate bundle, reuse device key).
    Rotate {
        /// Target repo override.
        #[arg(long)]
        repo: Option<String>,

        /// Max age for the verification bundle in seconds (default: 1 year).
        #[arg(long, default_value = "31536000")]
        max_age_secs: u64,

        /// Disable auto-generated passphrase and prompt interactively instead.
        #[arg(long)]
        manual_passphrase: bool,
    },
}

impl ExecutableCommand for CiCommand {
    fn execute(&self, ctx: &CliConfig) -> Result<()> {
        let repo_path = layout::resolve_repo_path(ctx.repo_path.clone())?;
        let pp: Arc<dyn PassphraseProvider + Send + Sync> = Arc::clone(&ctx.passphrase_provider);

        match &self.command {
            CiSubcommand::Setup {
                repo,
                max_age_secs,
                manual_passphrase,
            } => setup::run_setup(
                repo.clone(),
                *max_age_secs,
                !manual_passphrase,
                pp,
                &ctx.env_config,
                &repo_path,
            ),
            CiSubcommand::Rotate {
                repo,
                max_age_secs,
                manual_passphrase,
            } => rotate::run_rotate(
                repo.clone(),
                *max_age_secs,
                !manual_passphrase,
                pp,
                &ctx.env_config,
                &repo_path,
            ),
        }
    }
}
