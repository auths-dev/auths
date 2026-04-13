use anyhow::{Context, Result};
use clap::Parser;

use crate::adapters::git_config::SystemGitConfigProvider;
use crate::commands::executable::ExecutableCommand;
use crate::config::CliConfig;
use crate::ux::format::Output;
use auths_sdk::ports::git_config::GitConfigProvider;

/// Git config keys that `auths init` sets for signing.
const GIT_SIGNING_CONFIG_KEYS: &[&str] = &[
    "gpg.format",
    "gpg.ssh.program",
    "user.signingkey",
    "commit.gpgsign",
    "tag.gpgsign",
    "gpg.ssh.allowedSignersFile",
];

/// Remove Auths identity and git configuration, allowing a clean re-initialization.
///
/// This is a destructive operation that removes your local identity
/// and signing configuration. Your identity can be recovered from
/// a paired device if you have one.
///
/// Usage:
/// ```ignore
/// auths reset
/// auths reset --force  # skip confirmation
/// ```
#[derive(Parser, Debug, Clone)]
#[command(
    name = "reset",
    about = "Remove Auths identity and git signing configuration"
)]
pub struct ResetCommand {
    /// Skip confirmation prompt
    #[arg(long)]
    force: bool,
}

impl ExecutableCommand for ResetCommand {
    fn execute(&self, ctx: &CliConfig) -> Result<()> {
        let out = Output::new();

        if !self.force {
            let confirmed = dialoguer::Confirm::new()
                .with_prompt("This will remove ~/.auths and git signing config. Continue? [y/N]")
                .default(false)
                .interact()
                .context("Failed to read confirmation")?;

            if !confirmed {
                out.println("Aborted.");
                return Ok(());
            }
        }

        out.newline();
        out.print_heading("Resetting Auths...");
        out.newline();

        remove_auths_directory(&out)?;
        clear_keychain_keys(&out, &ctx.env_config);
        unset_git_signing_config(&out)?;

        out.newline();
        out.print_success("Reset complete. Run 'auths init' to set up again.");

        Ok(())
    }
}

fn remove_auths_directory(out: &Output) -> Result<()> {
    let auths_dir = dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("Cannot determine home directory"))?
        .join(".auths");

    if auths_dir.exists() {
        std::fs::remove_dir_all(&auths_dir)
            .with_context(|| format!("Failed to remove {}", auths_dir.display()))?;
        out.print_success(&format!("Removed {}", auths_dir.display()));
    } else {
        out.print_info(&format!("{} does not exist, skipping", auths_dir.display()));
    }

    Ok(())
}

fn unset_git_signing_config(out: &Output) -> Result<()> {
    let provider = SystemGitConfigProvider::global();

    for key in GIT_SIGNING_CONFIG_KEYS {
        match provider.unset(key) {
            Ok(()) => out.print_success(&format!("Unset git config {key}")),
            Err(e) => out.print_warn(&format!("Could not unset {key}: {e}")),
        }
    }

    Ok(())
}

/// Clear all keys from the keychain backend.
fn clear_keychain_keys(out: &Output, env_config: &auths_sdk::core_config::EnvironmentConfig) {
    let keychain = match auths_sdk::keychain::get_platform_keychain_with_config(env_config) {
        Ok(k) => k,
        Err(e) => {
            out.print_warn(&format!("Could not access keychain to clear keys: {e}"));
            return;
        }
    };

    let aliases = match keychain.list_aliases() {
        Ok(a) => a,
        Err(e) => {
            out.print_warn(&format!("Could not list keychain keys: {e}"));
            return;
        }
    };

    if aliases.is_empty() {
        return;
    }

    for alias in &aliases {
        match keychain.delete_key(alias) {
            Ok(()) => {}
            Err(e) => {
                out.print_warn(&format!("Could not delete key '{}': {e}", alias.as_str()));
            }
        }
    }

    out.print_success(&format!(
        "Cleared {} key(s) from {} keychain",
        aliases.len(),
        keychain.backend_name()
    ));
}
