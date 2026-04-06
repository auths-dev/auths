//! Cache management commands.
//!
//! Provides commands to list, inspect, and clear the local identity history cache.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use auths_sdk::core_config::EnvironmentConfig;
use auths_sdk::keri::cache;

#[derive(Parser, Debug, Clone)]
#[command(about = "Manage cached identity snapshots")]
pub struct CacheCommand {
    #[command(subcommand)]
    command: CacheSubcommand,
}

#[derive(Subcommand, Debug, Clone)]
enum CacheSubcommand {
    /// List all cached identity states
    List,

    /// Inspect a cached identity state for a specific identity ID
    Inspect {
        /// The identity ID to inspect
        did: String,
    },

    /// Clear cached identity states
    Clear {
        /// Optional: only clear cache for this specific identity ID
        did: Option<String>,
    },
}

pub fn handle_cache(cmd: CacheCommand, env_config: &EnvironmentConfig) -> Result<()> {
    let auths_home = auths_sdk::paths::auths_home_with_config(env_config)
        .context("Failed to resolve auths home directory")?;
    match cmd.command {
        CacheSubcommand::List => handle_list(&auths_home),
        CacheSubcommand::Inspect { did } => handle_inspect(&auths_home, &did),
        CacheSubcommand::Clear { did } => handle_clear(&auths_home, did.as_deref()),
    }
}

fn handle_list(auths_home: &std::path::Path) -> Result<()> {
    let entries = cache::list_cached_entries(auths_home)?;

    if entries.is_empty() {
        println!("No cached snapshots found.");
        return Ok(());
    }

    println!("Cached identity snapshots:\n");
    for entry in entries {
        println!("  Identity ID: {}", entry.did);
        println!("  Sequence: {}", entry.sequence);
        println!("  Verified against: {}", entry.validated_against_tip_said);
        println!("  Commit OID: {}", entry.last_commit_oid);
        println!("  Cached at: {}", entry.cached_at);
        println!("  File: {}", entry.path.display());
        println!();
    }

    Ok(())
}

fn handle_inspect(auths_home: &std::path::Path, did: &str) -> Result<()> {
    match cache::inspect_cache(auths_home, did)? {
        Some(cached) => {
            println!("Cache entry for: {}\n", did);
            println!("Version: {}", cached.version);
            println!("Identity ID: {}", cached.did);
            println!("Sequence: {}", cached.sequence);
            println!(
                "Verified against log entry: {}",
                cached.validated_against_tip_said
            );
            println!("Last commit OID: {}", cached.last_commit_oid);
            println!("Cached at: {}", cached.cached_at);
            println!("\nKey State:");
            println!("  Current keys: {:?}", cached.state.current_keys);
            println!(
                "  Pre-committed rotation key: {:?}",
                cached.state.next_commitment
            );
            println!("  Is abandoned: {}", cached.state.is_abandoned);
            println!(
                "\nCache file: {}",
                cache::cache_path_for_did(auths_home, did).display()
            );
        }
        None => {
            println!("No cache entry found for: {}", did);
            println!(
                "Expected path: {}",
                cache::cache_path_for_did(auths_home, did).display()
            );
        }
    }

    Ok(())
}

fn handle_clear(auths_home: &std::path::Path, did: Option<&str>) -> Result<()> {
    match did {
        Some(did) => {
            cache::invalidate_cache(auths_home, did)?;
            println!("Cleared cache for: {}", did);
        }
        None => {
            let count = cache::clear_all_caches(auths_home)?;
            if count == 0 {
                println!("No cache entries to clear.");
            } else {
                println!("Cleared {} cache entries.", count);
            }
        }
    }

    Ok(())
}

impl crate::commands::executable::ExecutableCommand for CacheCommand {
    fn execute(&self, ctx: &crate::config::CliConfig) -> anyhow::Result<()> {
        handle_cache(self.clone(), &ctx.env_config)
    }
}
