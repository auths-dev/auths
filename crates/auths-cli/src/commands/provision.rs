//! Declarative, headless provisioning for enterprise deployments.
//!
//! Reads a TOML configuration file and reconciles the node's identity state
//! to match. Secrets are handled via environment variable overrides layered
//! automatically by the `config` crate, never passed as CLI arguments.

use crate::ux::format::Output;
use anyhow::{Context, Result, anyhow};
use auths_sdk::keychain::get_platform_keychain;
use auths_sdk::ports::IdentityStorage;
use auths_sdk::ports::RegistryBackend;
use auths_sdk::signing::PassphraseProvider;
use auths_sdk::storage::{GitRegistryBackend, RegistryConfig, RegistryIdentityStorage};
use auths_sdk::storage_layout::install_linearity_hook;
use auths_sdk::workflows::provision::{IdentityConfig, NodeConfig, enforce_identity_state};
use clap::Parser;
use config::{Config, Environment, File};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Declarative headless provisioning for enterprise deployments.
///
/// Reads a TOML configuration file and reconciles the node's identity
/// state to match. Environment variables with prefix `AUTHS_` and
/// separator `__` override any TOML values.
///
/// Usage:
/// ```ignore
/// auths provision --config node.toml
/// auths provision --config node.toml --dry-run
/// AUTHS_IDENTITY__KEY_ALIAS=override auths provision --config node.toml
/// ```
#[derive(Parser, Debug, Clone)]
#[command(
    name = "provision",
    about = "Declarative headless provisioning from a TOML config file"
)]
pub struct ProvisionCommand {
    /// Path to the TOML configuration file.
    #[arg(long, value_parser, help = "Path to the TOML config file")]
    pub config: PathBuf,

    /// Validate config and print resolved state without applying changes.
    #[arg(long, help = "Validate and print resolved config without applying")]
    pub dry_run: bool,

    /// Overwrite existing identity if present.
    #[arg(long, help = "Overwrite existing identity")]
    pub force: bool,
}

/// Handle the provision command.
///
/// Args:
/// * `cmd`: The parsed provision command with config path, dry-run, and force flags.
/// * `passphrase_provider`: Provider for key encryption passphrases.
///
/// Usage:
/// ```ignore
/// handle_provision(cmd, Arc::clone(&passphrase_provider))?;
/// ```
pub fn handle_provision(
    cmd: ProvisionCommand,
    passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync>,
) -> Result<()> {
    let out = Output::new();
    let config = load_node_config(&cmd.config)?;

    if cmd.dry_run {
        return display_resolved_state(&config, &out);
    }

    out.print_heading("Auths Provision");
    out.println("================");
    out.newline();

    validate_storage_perimeter(&config.identity, &out)?;
    out.print_info("Initializing identity...");

    let repo_path = Path::new(&config.identity.repo_path);
    let registry: Arc<dyn RegistryBackend + Send + Sync> = Arc::new(
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(repo_path)),
    );
    let identity_storage: Arc<dyn IdentityStorage + Send + Sync> =
        Arc::new(RegistryIdentityStorage::new(repo_path.to_path_buf()));
    let keychain =
        get_platform_keychain().map_err(|e| anyhow!("Failed to access keychain: {}", e))?;

    match enforce_identity_state(
        &config,
        cmd.force,
        passphrase_provider.as_ref(),
        keychain.as_ref(),
        registry,
        identity_storage,
    )
    .map_err(anyhow::Error::from)?
    {
        None => {
            out.print_success("Identity already exists and matches — no changes needed.");
        }
        Some(result) => {
            out.newline();
            out.print_success("Identity provisioned successfully.");
            out.println(&format!(
                "  {}",
                out.key_value("Controller DID", &result.controller_did)
            ));
            out.println(&format!(
                "  {}",
                out.key_value("Key alias", &result.key_alias)
            ));
        }
    }

    install_system_hooks(&config.identity, &out);
    print_provision_summary(&config, &out);

    Ok(())
}

/// Load and merge TOML config file with environment variable overrides.
///
/// Environment variables use prefix `AUTHS_` with double-underscore separator
/// for nested keys. For example:
/// - `AUTHS_IDENTITY__KEY_ALIAS` overrides `identity.key_alias`
/// - `AUTHS_WITNESS__THRESHOLD` overrides `witness.threshold`
///
/// Args:
/// * `path`: Path to the TOML configuration file.
///
/// Usage:
/// ```ignore
/// let config = load_node_config(Path::new("node.toml"))?;
/// ```
fn load_node_config(path: &Path) -> Result<NodeConfig> {
    let path_str = path
        .to_str()
        .ok_or_else(|| anyhow!("Config path is not valid UTF-8"))?;

    let settings = Config::builder()
        .add_source(File::with_name(path_str))
        .add_source(Environment::with_prefix("AUTHS").separator("__"))
        .build()
        .with_context(|| format!("Failed to load config from {:?}", path))?;

    settings
        .try_deserialize::<NodeConfig>()
        .with_context(|| "Failed to deserialize node config")
}

/// Print the resolved configuration for `--dry-run` inspection.
fn display_resolved_state(config: &NodeConfig, out: &Output) -> Result<()> {
    out.print_heading("Resolved Configuration (dry-run)");
    out.println("=================================");
    out.newline();

    out.println(&format!(
        "  {}",
        out.key_value("key_alias", &config.identity.key_alias)
    ));
    out.println(&format!(
        "  {}",
        out.key_value("repo_path", &config.identity.repo_path)
    ));
    out.println(&format!(
        "  {}",
        out.key_value("preset", &config.identity.preset)
    ));

    if !config.identity.metadata.is_empty() {
        out.newline();
        out.println("  Metadata:");
        for (k, v) in &config.identity.metadata {
            out.println(&format!("    {} = {}", k, v));
        }
    }

    if let Some(ref witness) = config.witness {
        out.newline();
        out.println("  Witness:");
        out.println(&format!(
            "    {}",
            out.key_value("urls", &format!("{:?}", witness.urls))
        ));
        out.println(&format!(
            "    {}",
            out.key_value("threshold", &witness.threshold.to_string())
        ));
        out.println(&format!(
            "    {}",
            out.key_value("timeout_ms", &witness.timeout_ms.to_string())
        ));
        out.println(&format!("    {}", out.key_value("policy", &witness.policy)));
    }

    out.newline();
    out.print_success("Config is valid. No changes applied (dry-run).");
    Ok(())
}

/// Ensure the repo directory exists and contains a Git repository.
fn validate_storage_perimeter(identity: &IdentityConfig, out: &Output) -> Result<()> {
    use crate::factories::storage::{ensure_git_repo, open_git_repo};

    let repo_path = Path::new(&identity.repo_path);

    if repo_path.exists() {
        match open_git_repo(repo_path) {
            Ok(_) => {
                out.println(&format!(
                    "  Repository: {} ({})",
                    out.info(&identity.repo_path),
                    out.success("found")
                ));
            }
            Err(_) => {
                out.print_info("Initializing Git repository...");
                ensure_git_repo(repo_path)
                    .with_context(|| format!("Failed to init Git repository at {:?}", repo_path))?;
                out.println(&format!(
                    "  Repository: {} ({})",
                    out.info(&identity.repo_path),
                    out.success("initialized")
                ));
            }
        }
    } else {
        out.print_info("Creating directory and Git repository...");
        ensure_git_repo(repo_path).with_context(|| {
            format!(
                "Failed to create and init Git repository at {:?}",
                repo_path
            )
        })?;
        out.println(&format!(
            "  Repository: {} ({})",
            out.info(&identity.repo_path),
            out.success("created")
        ));
    }

    Ok(())
}

/// Install linearity enforcement hook (best-effort).
fn install_system_hooks(identity: &IdentityConfig, out: &Output) {
    let repo_path = Path::new(&identity.repo_path);
    if let Err(e) = install_linearity_hook(repo_path) {
        out.print_warn(&format!("Could not install linearity hook: {}", e));
    }
}

/// Print a summary of what was provisioned.
fn print_provision_summary(config: &NodeConfig, out: &Output) {
    out.newline();
    out.print_heading("Provision Summary");
    out.println(&format!(
        "  {}",
        out.key_value("Repository", &config.identity.repo_path)
    ));
    out.println(&format!(
        "  {}",
        out.key_value("Key alias", &config.identity.key_alias)
    ));
    out.println(&format!(
        "  {}",
        out.key_value("Preset", &config.identity.preset)
    ));

    if let Some(ref w) = config.witness {
        out.println(&format!(
            "  {}",
            out.key_value("Witnesses", &w.urls.join(", "))
        ));
        out.println(&format!("  {}", out.key_value("Witness policy", &w.policy)));
    }
}

impl crate::commands::executable::ExecutableCommand for ProvisionCommand {
    fn execute(&self, ctx: &crate::config::CliConfig) -> anyhow::Result<()> {
        handle_provision(self.clone(), ctx.passphrase_provider.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_test_toml(content: &str) -> NamedTempFile {
        let mut f = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    #[test]
    fn test_load_minimal_config() {
        let toml = r#"
[identity]
key_alias = "test-key"
repo_path = "/tmp/test-auths"
"#;
        let f = write_test_toml(toml);
        let config = load_node_config(f.path()).unwrap();
        assert_eq!(config.identity.key_alias, "test-key");
        assert_eq!(config.identity.repo_path, "/tmp/test-auths");
        assert_eq!(config.identity.preset, "default");
        assert!(config.witness.is_none());
    }

    #[test]
    fn test_load_full_config() {
        let toml = r#"
[identity]
key_alias = "prod-key"
repo_path = "/data/auths"
preset = "radicle"

[identity.metadata]
name = "prod-node-01"
environment = "production"

[witness]
urls = ["https://witness1.example.com", "https://witness2.example.com"]
threshold = 2
timeout_ms = 10000
policy = "enforce"
"#;
        let f = write_test_toml(toml);
        let config = load_node_config(f.path()).unwrap();
        assert_eq!(config.identity.key_alias, "prod-key");
        assert_eq!(config.identity.preset, "radicle");
        assert_eq!(
            config.identity.metadata.get("name").unwrap(),
            "prod-node-01"
        );
        let w = config.witness.unwrap();
        assert_eq!(w.urls.len(), 2);
        assert_eq!(w.threshold, 2);
        assert_eq!(w.timeout_ms, 10000);
        assert_eq!(w.policy, "enforce");
    }

    #[test]
    fn test_load_config_with_defaults() {
        let toml = r#"
[identity]
"#;
        let f = write_test_toml(toml);
        let config = load_node_config(f.path()).unwrap();
        assert_eq!(config.identity.key_alias, "main");
        assert_eq!(config.identity.preset, "default");
    }

    #[test]
    fn test_load_config_missing_file() {
        let result = load_node_config(Path::new("/nonexistent/config.toml"));
        assert!(result.is_err());
    }

    #[test]
    fn test_provision_command_defaults() {
        let cmd = ProvisionCommand {
            config: PathBuf::from("test.toml"),
            dry_run: false,
            force: false,
        };
        assert!(!cmd.dry_run);
        assert!(!cmd.force);
    }

    #[test]
    fn test_witness_policy_parsing() {
        let toml = r#"
[identity]
key_alias = "test"
repo_path = "/tmp/test"

[witness]
urls = ["https://w1.example.com"]
threshold = 1
policy = "warn"
"#;
        let f = write_test_toml(toml);
        let config = load_node_config(f.path()).unwrap();
        let w = config.witness.unwrap();
        assert_eq!(w.policy, "warn");
    }
}
