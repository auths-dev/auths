//! Witness server and client management commands.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use auths_utils::path::expand_tilde;
use clap::{Parser, Subcommand};

use auths_core::witness::AsyncWitnessProvider;
use auths_infra_http::HttpAsyncWitnessClient;
use auths_sdk::ports::IdentityStorage;
use auths_sdk::storage::RegistryIdentityStorage;
use auths_sdk::witness::{WitnessConfig, WitnessRef};
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
                    // curve-aware keypair generation. Default to P-256
                    // at the CLI layer (workspace default); plumb --curve through
                    // the subcommand if explicit selection becomes necessary.
                    let curve = auths_crypto::CurveType::P256;
                    let cfg = WitnessServerConfig::with_generated_keypair(db_path, curve)
                        .map_err(|e| anyhow::anyhow!("Failed to generate witness keypair: {e}"))?;
                    let cfg = if let Some(did_override) = witness_did {
                        WitnessServerConfig {
                            #[allow(clippy::disallowed_methods)]
                            // INVARIANT: caller-supplied witness DID
                            witness_did: auths_verifier::types::CanonicalDid::new_unchecked(
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
            // A witness is its AID, not its URL: resolve the witness's identity
            // from its `/health` and pin `(url, aid)`. The AID is what gets
            // designated in `b[]` and what receipt signatures are verified
            // against. Refuse to pin a witness we can't identify.
            let rt = tokio::runtime::Runtime::new()?;
            let aid = rt
                .block_on(async {
                    let client = HttpAsyncWitnessClient::new(
                        parsed_url.to_string(),
                        config.threshold.max(1),
                    );
                    client.witness_aid().await
                })
                .map_err(|e| {
                    anyhow!(
                        "Could not resolve witness identity from {}/health: {}",
                        parsed_url,
                        e
                    )
                })?;
            if !config.pin(WitnessRef {
                url: parsed_url.clone(),
                aid: aid.clone(),
            }) {
                println!("Witness already configured (aid {}): {}", aid.as_str(), url);
                return Ok(());
            }
            if config.threshold == 0 {
                config.threshold = 1;
            }
            save_witness_config(&repo_path, &config)?;
            println!("Added witness: {} (aid {})", url, aid.as_str());
            println!(
                "  Witnesses: {}, required: {}",
                config.witnesses.len(),
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
            if !config.remove_url(&parsed_url) {
                println!("Witness not found: {}", url);
                return Ok(());
            }
            // Adjust threshold if needed
            if config.threshold > config.witnesses.len() {
                config.threshold = config.witnesses.len();
            }
            save_witness_config(&repo_path, &config)?;
            println!("Removed witness: {}", url);
            println!(
                "  Remaining witnesses: {}, required: {}",
                config.witnesses.len(),
                config.threshold
            );
            Ok(())
        }

        WitnessSubcommand::List => {
            let repo_path = resolve_repo_path(repo_opt)?;
            let config = load_witness_config(&repo_path)?;
            if config.witnesses.is_empty() {
                println!("No witnesses configured.");
                return Ok(());
            }
            println!("Configured witnesses:");
            for (i, w) in config.witnesses.iter().enumerate() {
                println!("  {}. {}  (aid {})", i + 1, w.url, w.aid.as_str());
            }
            println!(
                "\nRequired: {}/{} (policy: {:?})",
                config.threshold,
                config.witnesses.len(),
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
