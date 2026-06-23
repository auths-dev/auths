//! `auths config` command — view and modify `~/.auths/config.toml`.

use crate::commands::executable::ExecutableCommand;
use crate::config::CliConfig;
use anyhow::{Context, Result, bail};
use auths_sdk::core_config::{AuthsConfig, PassphraseCachePolicy};
use auths_sdk::ports::ConfigStore;

use crate::adapters::config_store::FileConfigStore;
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

/// Manage Auths configuration.
#[derive(Parser, Debug, Clone)]
#[command(
    name = "config",
    about = "View and modify Auths configuration",
    after_help = "Configuration file: ~/.auths/config.toml

Examples:
  auths config show                               # View all settings
  auths config get passphrase.cache               # Check caching status
  auths config set passphrase.cache always        # Cache passphrases

Valid Keys:
  passphrase.cache       — 'never', 'session', 'always'
  passphrase.duration    — seconds until cache expires
  passphrase.biometric   — 'enabled', 'disabled' (macOS)

Related:
  auths doctor  — Check system configuration"
)]
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
    fn execute(&self, ctx: &CliConfig) -> Result<()> {
        let path = config_path(ctx.repo_path.clone())?;
        match &self.action {
            ConfigAction::Set { key, value } => execute_set(key, value, &path),
            ConfigAction::Get { key } => execute_get(key, &path),
            ConfigAction::Show => execute_show(&path),
        }
    }
}

/// Resolves the `config.toml` path for the active registry, honoring `--repo`.
///
/// Args:
/// * `repo`: The optional `--repo` override; `None` selects the default
///   `~/.auths` registry, matching the path used when `--repo` is absent.
///
/// Usage:
/// ```ignore
/// let path = config_path(ctx.repo_path.clone())?;
/// ```
fn config_path(repo: Option<PathBuf>) -> Result<PathBuf> {
    let dir = match repo {
        Some(_) => auths_sdk::storage_layout::resolve_repo_path(repo)
            .context("Failed to resolve the repository path for the config file")?,
        None => auths_sdk::paths::auths_home()
            .map_err(|e| anyhow::anyhow!("Failed to resolve the Auths home directory: {e}"))?,
    };
    Ok(dir.join("config.toml"))
}

/// Reads the config at `path`, returning defaults when the file is absent.
fn read_config(path: &Path) -> AuthsConfig {
    match FileConfigStore.read(path) {
        Ok(Some(contents)) => toml::from_str(&contents).unwrap_or_default(),
        _ => AuthsConfig::default(),
    }
}

/// Writes the config to `path`, creating parent directories as needed.
fn write_config(config: &AuthsConfig, path: &Path) -> Result<()> {
    let contents = toml::to_string_pretty(config)
        .map_err(|e| anyhow::anyhow!("Failed to serialize config: {e}"))?;
    FileConfigStore
        .write(path, &contents)
        .map_err(|e| anyhow::anyhow!("{e}"))
}

fn execute_set(key: &str, value: &str, path: &Path) -> Result<()> {
    let mut config = read_config(path);

    match key {
        "passphrase.cache" => {
            config.passphrase.cache = parse_cache_policy(value)?;
        }
        "passphrase.duration" => {
            auths_sdk::keychain::parse_duration_str(value).ok_or_else(|| {
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

    write_config(&config, path)?;
    println!("Set {} = {}", key, value);
    Ok(())
}

fn execute_get(key: &str, path: &Path) -> Result<()> {
    let config = read_config(path);

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

fn execute_show(path: &Path) -> Result<()> {
    let config = read_config(path);
    if crate::ux::format::is_json_mode() {
        let json = serde_json::to_string_pretty(&config)
            .map_err(|e| anyhow::anyhow!("Failed to serialize config as JSON: {}", e))?;
        println!("{}", json);
    } else {
        let toml_str = toml::to_string_pretty(&config)
            .map_err(|e| anyhow::anyhow!("Failed to serialize config: {}", e))?;
        println!("{}", toml_str);
    }
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
