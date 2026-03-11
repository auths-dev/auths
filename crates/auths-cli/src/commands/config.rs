//! `auths config` command — view and modify `~/.auths/config.toml`.

use crate::commands::executable::ExecutableCommand;
use crate::config::CliConfig;
use anyhow::{Result, bail};
use auths_core::config::{AuthsConfig, PassphraseCachePolicy, load_config, save_config};

use crate::adapters::config_store::FileConfigStore;
use clap::{Parser, Subcommand};

/// Manage Auths configuration.
#[derive(Parser, Debug, Clone)]
#[command(name = "config", about = "View and modify Auths configuration")]
pub struct ConfigCommand {
    #[command(subcommand)]
    pub action: ConfigAction,
}

/// Config subcommands.
#[derive(Subcommand, Debug, Clone)]
pub enum ConfigAction {
    /// Set a configuration value (e.g. `auths config set passphrase.cache always`).
    Set {
        /// Dotted key path (e.g. `passphrase.cache`, `passphrase.duration`).
        key: String,
        /// Value to assign.
        value: String,
    },
    /// Get a configuration value (e.g. `auths config get passphrase.cache`).
    Get {
        /// Dotted key path.
        key: String,
    },
    /// Show the full configuration.
    Show,
}

impl ExecutableCommand for ConfigCommand {
    fn execute(&self, _ctx: &CliConfig) -> Result<()> {
        match &self.action {
            ConfigAction::Set { key, value } => execute_set(key, value),
            ConfigAction::Get { key } => execute_get(key),
            ConfigAction::Show => execute_show(),
        }
    }
}

fn execute_set(key: &str, value: &str) -> Result<()> {
    let store = FileConfigStore;
    let mut config = load_config(&store);

    match key {
        "passphrase.cache" => {
            config.passphrase.cache = parse_cache_policy(value)?;
        }
        "passphrase.duration" => {
            auths_core::storage::passphrase_cache::parse_duration_str(value).ok_or_else(|| {
                anyhow::anyhow!(
                    "Invalid duration '{}'. Use formats like '7d', '24h', '30m', '3600s'.",
                    value
                )
            })?;
            config.passphrase.duration = Some(value.to_string());
        }
        "passphrase.biometric" => {
            config.passphrase.biometric = parse_bool(value)?;
        }
        _ => bail!(
            "Unknown config key '{}'. Valid keys: passphrase.cache, passphrase.duration, passphrase.biometric",
            key
        ),
    }

    save_config(&config, &store)?;
    println!("Set {} = {}", key, value);
    Ok(())
}

fn execute_get(key: &str) -> Result<()> {
    let config = load_config(&FileConfigStore);

    match key {
        "passphrase.cache" => {
            let label = policy_label(&config.passphrase.cache);
            println!("{}", label);
        }
        "passphrase.duration" => {
            println!(
                "{}",
                config.passphrase.duration.as_deref().unwrap_or("(not set)")
            );
        }
        "passphrase.biometric" => {
            println!("{}", config.passphrase.biometric);
        }
        _ => bail!(
            "Unknown config key '{}'. Valid keys: passphrase.cache, passphrase.duration, passphrase.biometric",
            key
        ),
    }

    Ok(())
}

fn execute_show() -> Result<()> {
    let config = load_config(&FileConfigStore);
    let toml_str = toml::to_string_pretty(&config)
        .map_err(|e| anyhow::anyhow!("Failed to serialize config: {}", e))?;
    println!("{}", toml_str);
    Ok(())
}

fn parse_cache_policy(s: &str) -> Result<PassphraseCachePolicy> {
    match s.to_lowercase().as_str() {
        "always" => Ok(PassphraseCachePolicy::Always),
        "session" => Ok(PassphraseCachePolicy::Session),
        "duration" => Ok(PassphraseCachePolicy::Duration),
        "never" => Ok(PassphraseCachePolicy::Never),
        _ => bail!(
            "Invalid cache policy '{}'. Valid values: always, session, duration, never",
            s
        ),
    }
}

fn policy_label(policy: &PassphraseCachePolicy) -> &'static str {
    match policy {
        PassphraseCachePolicy::Always => "always",
        PassphraseCachePolicy::Session => "session",
        PassphraseCachePolicy::Duration => "duration",
        PassphraseCachePolicy::Never => "never",
    }
}

fn parse_bool(s: &str) -> Result<bool> {
    match s.to_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => bail!("Invalid boolean '{}'. Use true/false, yes/no, or 1/0", s),
    }
}

fn _ensure_default_config_exists() -> Result<AuthsConfig> {
    let store = FileConfigStore;
    let config = load_config(&store);
    save_config(&config, &store)?;
    Ok(config)
}
