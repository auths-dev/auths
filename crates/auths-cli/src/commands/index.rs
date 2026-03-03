use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use std::path::PathBuf;

use auths_id::storage::layout::{self, StorageLayoutConfig};
use auths_index::{AttestationIndex, rebuild_attestations_from_git};

#[derive(Args, Debug, Clone)]
#[command(about = "Manage the device authorization index for fast lookups.")]
pub struct IndexCommand {
    #[command(subcommand)]
    pub command: IndexSubcommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum IndexSubcommand {
    /// Rebuild the index from Git refs.
    Rebuild,

    /// Show index statistics.
    Stats,

    /// Query authorizations by device identity ID.
    #[command(name = "query-device")]
    QueryDevice {
        /// The device identity ID to query.
        #[arg(long)]
        device_did: String,
    },

    /// Query authorizations by issuer identity ID.
    #[command(name = "query-issuer")]
    QueryIssuer {
        /// The issuer identity ID to query.
        #[arg(long)]
        issuer_did: String,
    },
}

/// Handles the `index` subcommand.
pub fn handle_index(
    cmd: IndexCommand,
    repo_opt: Option<PathBuf>,
    attestation_prefix_override: Option<String>,
    attestation_blob_name_override: Option<String>,
) -> Result<()> {
    let repo_path = layout::resolve_repo_path(repo_opt)?;
    let index_path = repo_path.join(".auths-index.db");

    let mut config = StorageLayoutConfig::default();
    if let Some(prefix) = attestation_prefix_override {
        config.device_attestation_prefix = prefix.into();
    }
    if let Some(blob_name) = attestation_blob_name_override {
        config.attestation_blob_name = blob_name.into();
    }

    match cmd.command {
        IndexSubcommand::Rebuild => {
            println!("Rebuilding device authorization index...");
            println!("   Repository: {:?}", repo_path);
            println!("   Index path: {:?}", index_path);
            println!(
                "   Authorization prefix: {}",
                config.device_attestation_prefix
            );

            let index = AttestationIndex::open_or_create(&index_path)
                .context("Failed to open or create index")?;

            let stats = rebuild_attestations_from_git(
                &index,
                &repo_path,
                &config.device_attestation_prefix,
                &config.attestation_blob_name,
            )
            .context("Failed to rebuild index from Git")?;

            println!("\nRebuild complete:");
            println!("   Refs scanned: {}", stats.refs_scanned);
            println!("   Attestations indexed: {}", stats.attestations_indexed);
            if stats.errors > 0 {
                println!("   Errors: {}", stats.errors);
            }

            Ok(())
        }

        IndexSubcommand::Stats => {
            if !index_path.exists() {
                println!("No index found at {:?}", index_path);
                println!("Run 'auths index rebuild' to create one.");
                return Ok(());
            }

            let index =
                AttestationIndex::open_or_create(&index_path).context("Failed to open index")?;

            let stats = index.stats().context("Failed to get index stats")?;

            println!("Attestation Index Statistics");
            println!("   Index path: {:?}", index_path);
            println!();
            println!("   Total attestations:  {}", stats.total_attestations);
            println!("   Active attestations: {}", stats.active_attestations);
            println!("   Revoked attestations: {}", stats.revoked_attestations);
            println!("   With expiry:         {}", stats.with_expiry);
            println!("   Unique devices:      {}", stats.unique_devices);
            println!("   Unique issuers:      {}", stats.unique_issuers);

            Ok(())
        }

        IndexSubcommand::QueryDevice { device_did } => {
            if !index_path.exists() {
                println!("No index found at {:?}", index_path);
                println!("Run 'auths index rebuild' to create one.");
                return Ok(());
            }

            let index =
                AttestationIndex::open_or_create(&index_path).context("Failed to open index")?;

            let results = index
                .query_by_device(&device_did)
                .context("Failed to query by device")?;

            if results.is_empty() {
                println!("No attestations found for device: {}", device_did);
            } else {
                println!(
                    "Found {} attestation(s) for device {}:",
                    results.len(),
                    device_did
                );
                for att in results {
                    println!();
                    println!("   RID: {}", att.rid);
                    println!("   Issuer: {}", att.issuer_did);
                    println!("   Revoked At: {:?}", att.revoked_at);
                    if let Some(expires) = att.expires_at {
                        println!("   Expires: {}", expires);
                    }
                    println!("   Git ref: {}", att.git_ref);
                }
            }

            Ok(())
        }

        IndexSubcommand::QueryIssuer { issuer_did } => {
            if !index_path.exists() {
                println!("No index found at {:?}", index_path);
                println!("Run 'auths index rebuild' to create one.");
                return Ok(());
            }

            let index =
                AttestationIndex::open_or_create(&index_path).context("Failed to open index")?;

            let results = index
                .query_by_issuer(&issuer_did)
                .context("Failed to query by issuer")?;

            if results.is_empty() {
                println!("No attestations found for issuer: {}", issuer_did);
            } else {
                println!(
                    "Found {} attestation(s) for issuer {}:",
                    results.len(),
                    issuer_did
                );
                for att in results {
                    println!();
                    println!("   RID: {}", att.rid);
                    println!("   Device: {}", att.device_did);
                    println!("   Revoked At: {:?}", att.revoked_at);
                    if let Some(expires) = att.expires_at {
                        println!("   Expires: {}", expires);
                    }
                    println!("   Git ref: {}", att.git_ref);
                }
            }

            Ok(())
        }
    }
}

impl crate::commands::executable::ExecutableCommand for IndexCommand {
    fn execute(&self, ctx: &crate::config::CliConfig) -> anyhow::Result<()> {
        handle_index(self.clone(), ctx.repo_path.clone(), None, None)
    }
}
