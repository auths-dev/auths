//! Witness server and client management commands.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use auths_utils::path::expand_tilde;
use clap::{Parser, Subcommand};

use auths_sdk::ports::IdentityStorage;
use auths_sdk::storage::RegistryIdentityStorage;
use auths_sdk::witness::WitnessConfig;
use auths_sdk::witness::{WitnessServerConfig, WitnessServerState, run_server};

/// Manage identity witness servers.
#[derive(Parser, Debug, Clone)]
pub struct WitnessCommand {
    #[command(subcommand)]
    pub subcommand: WitnessSubcommand,
}

/// Witness subcommands.
#[derive(Subcommand, Debug, Clone)]
pub enum WitnessSubcommand {
    /// Start the witness HTTP server.
    #[command(visible_alias = "serve")]
    Start {
        /// Address to bind to (e.g., "127.0.0.1:3333").
        #[clap(long, default_value = "127.0.0.1:3333")]
        bind: SocketAddr,

        /// Path to the SQLite database for witness storage.
        #[clap(long, default_value = "witness.db")]
        db_path: PathBuf,

        /// Witness server identity (auto-generated if not provided).
        #[clap(long, visible_alias = "witness")]
        witness_did: Option<String>,
    },

    /// Add a witness URL to the identity configuration.
    Add {
        /// Witness server URL (e.g., "http://127.0.0.1:3333").
        #[clap(long)]
        url: String,
    },

    /// Remove a witness URL from the identity configuration.
    Remove {
        /// Witness server URL to remove.
        #[clap(long)]
        url: String,
    },

    /// List configured witnesses for the current identity.
    List,
}

/// Handle witness commands.
pub fn handle_witness(cmd: WitnessCommand, repo_opt: Option<PathBuf>) -> Result<()> {
    match cmd.subcommand {
        WitnessSubcommand::Start {
            bind,
            db_path,
            witness_did,
        } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let state = {
                    // fn-116.1/B1a: curve-aware keypair generation. Default to P-256
                    // at the CLI layer (workspace default); plumb --curve through
                    // the subcommand if explicit selection becomes necessary.
                    let curve = auths_crypto::CurveType::P256;
                    let cfg = WitnessServerConfig::with_generated_keypair(db_path, curve)
                        .map_err(|e| anyhow::anyhow!("Failed to generate witness keypair: {e}"))?;
                    let cfg = if let Some(did_override) = witness_did {
                        WitnessServerConfig {
                            #[allow(clippy::disallowed_methods)]
                            // INVARIANT: caller-supplied witness DID
                            witness_did: auths_verifier::types::DeviceDID::new_unchecked(
                                did_override,
                            ),
                            ..cfg
                        }
                    } else {
                        cfg
                    };
                    WitnessServerState::new(cfg)
                        .map_err(|e| anyhow::anyhow!("Failed to create witness state: {}", e))?
                };

                println!(
                    "Witness server started at {} (identity: {})",
                    bind,
                    state.witness_did()
                );

                run_server(state, bind)
                    .await
                    .map_err(|e| anyhow::anyhow!("Server error: {}", e))?;

                Ok(())
            })
        }

        WitnessSubcommand::Add { url } => {
            let repo_path = resolve_repo_path(repo_opt)?;
            let parsed_url: url::Url = url
                .parse()
                .map_err(|e| anyhow!("Invalid witness URL '{}': {}", url, e))?;
            let mut config = load_witness_config(&repo_path)?;
            if config.witness_urls.contains(&parsed_url) {
                println!("Witness already configured: {}", url);
                return Ok(());
            }
            config.witness_urls.push(parsed_url);
            if config.threshold == 0 {
                config.threshold = 1;
            }
            save_witness_config(&repo_path, &config)?;
            println!("Added witness: {}", url);
            println!(
                "  Witnesses: {}, required: {}",
                config.witness_urls.len(),
                config.threshold
            );
            Ok(())
        }

        WitnessSubcommand::Remove { url } => {
            let repo_path = resolve_repo_path(repo_opt)?;
            let parsed_url: url::Url = url
                .parse()
                .map_err(|e| anyhow!("Invalid witness URL '{}': {}", url, e))?;
            let mut config = load_witness_config(&repo_path)?;
            let before = config.witness_urls.len();
            config.witness_urls.retain(|u| u != &parsed_url);
            if config.witness_urls.len() == before {
                println!("Witness not found: {}", url);
                return Ok(());
            }
            // Adjust threshold if needed
            if config.threshold > config.witness_urls.len() {
                config.threshold = config.witness_urls.len();
            }
            save_witness_config(&repo_path, &config)?;
            println!("Removed witness: {}", url);
            println!(
                "  Remaining witnesses: {}, required: {}",
                config.witness_urls.len(),
                config.threshold
            );
            Ok(())
        }

        WitnessSubcommand::List => {
            let repo_path = resolve_repo_path(repo_opt)?;
            let config = load_witness_config(&repo_path)?;
            if config.witness_urls.is_empty() {
                println!("No witnesses configured.");
                return Ok(());
            }
            println!("Configured witnesses:");
            for (i, url) in config.witness_urls.iter().enumerate() {
                println!("  {}. {}", i + 1, url);
            }
            println!(
                "\nRequired: {}/{} (policy: {:?})",
                config.threshold,
                config.witness_urls.len(),
                config.policy
            );
            Ok(())
        }
    }
}

/// Resolve the identity repo path (defaults to ~/.auths).
///
/// Expands leading `~/` so paths from clap defaults work correctly.
fn resolve_repo_path(repo_opt: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = repo_opt {
        return Ok(expand_tilde(&path)?);
    }
    let home = dirs::home_dir().ok_or_else(|| anyhow!("Could not determine home directory"))?;
    Ok(home.join(".auths"))
}

/// Load witness config from identity metadata.
fn load_witness_config(repo_path: &Path) -> Result<WitnessConfig> {
    let storage = RegistryIdentityStorage::new(repo_path.to_path_buf());
    let identity = storage.load_identity()?;

    if let Some(ref metadata) = identity.metadata
        && let Some(wc) = metadata.get("witness_config")
    {
        let config: WitnessConfig = serde_json::from_value(wc.clone())?;
        return Ok(config);
    }
    Ok(WitnessConfig::default())
}

/// Save witness config into identity metadata.
fn save_witness_config(repo_path: &Path, config: &WitnessConfig) -> Result<()> {
    let storage = RegistryIdentityStorage::new(repo_path.to_path_buf());
    let mut identity = storage.load_identity()?;

    let metadata = identity
        .metadata
        .get_or_insert_with(|| serde_json::json!({}));
    if let Some(obj) = metadata.as_object_mut() {
        obj.insert("witness_config".to_string(), serde_json::to_value(config)?);
    }

    storage.create_identity(identity.controller_did.as_str(), identity.metadata)?;
    Ok(())
}

impl crate::commands::executable::ExecutableCommand for WitnessCommand {
    fn execute(&self, ctx: &crate::config::CliConfig) -> anyhow::Result<()> {
        handle_witness(self.clone(), ctx.repo_path.clone())
    }
}
