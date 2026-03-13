use std::time::Duration;

use anyhow::{Context, Result, bail};
use auths_core::ports::network::RegistryClient;
use auths_infra_http::HttpRegistryClient;
use auths_transparency::SignedCheckpoint;
use clap::{Args, Subcommand};
use serde::Serialize;

use super::executable::ExecutableCommand;
use crate::config::CliConfig;
use crate::ux::format::{JsonResponse, is_json_mode};

#[derive(Args, Debug, Clone)]
#[command(about = "Inspect and verify the transparency log")]
pub struct LogCommand {
    #[command(subcommand)]
    pub command: LogSubcommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum LogSubcommand {
    /// Fetch and display a log entry by sequence number
    Inspect(InspectArgs),
    /// Verify log consistency from the cached checkpoint
    Verify(VerifyArgs),
}

#[derive(Args, Debug, Clone)]
pub struct InspectArgs {
    /// Sequence number of the entry to inspect
    pub sequence: u64,

    /// Registry URL to fetch from
    #[clap(long, default_value = "https://public.auths.dev")]
    pub registry: String,
}

#[derive(Args, Debug, Clone)]
pub struct VerifyArgs {
    /// Registry URL to verify against
    #[clap(long, default_value = "https://public.auths.dev")]
    pub registry: String,
}

#[derive(Serialize)]
struct VerifyResult {
    consistent: bool,
    cached_size: u64,
    latest_size: u64,
    cached_root: String,
    latest_root: String,
}

impl ExecutableCommand for LogCommand {
    fn execute(&self, _ctx: &CliConfig) -> Result<()> {
        let rt = tokio::runtime::Runtime::new().context("Failed to create async runtime")?;
        rt.block_on(async {
            match &self.command {
                LogSubcommand::Inspect(args) => handle_inspect(args).await,
                LogSubcommand::Verify(args) => handle_verify(args).await,
            }
        })
    }
}

async fn handle_inspect(args: &InspectArgs) -> Result<()> {
    let registry_url = args.registry.trim_end_matches('/');
    let client =
        HttpRegistryClient::new_with_timeouts(Duration::from_secs(30), Duration::from_secs(60));

    let path = format!("v1/log/entries/{}", args.sequence);
    let response_bytes = client
        .fetch_registry_data(registry_url, &path)
        .await
        .context("Failed to fetch log entry")?;

    let entry: serde_json::Value =
        serde_json::from_slice(&response_bytes).context("Failed to parse log entry response")?;

    if is_json_mode() {
        println!(
            "{}",
            serde_json::to_string_pretty(&entry).context("Failed to serialize entry")?
        );
    } else {
        let entry_type = entry
            .get("content")
            .and_then(|c| c.get("entry_type"))
            .and_then(|t| t.as_str())
            .unwrap_or("unknown");
        let actor = entry
            .get("content")
            .and_then(|c| c.get("actor_did"))
            .and_then(|a| a.as_str())
            .unwrap_or("unknown");
        let timestamp = entry
            .get("timestamp")
            .and_then(|t| t.as_str())
            .unwrap_or("unknown");
        let sequence = entry
            .get("sequence")
            .and_then(|s| s.as_u64())
            .unwrap_or(args.sequence);

        println!("Log Entry #{sequence}");
        println!("  Type:      {entry_type}");
        println!("  Actor:     {actor}");
        println!("  Timestamp: {timestamp}");

        if let Some(body) = entry.get("content").and_then(|c| c.get("body")) {
            println!(
                "  Body:      {}",
                serde_json::to_string_pretty(body).unwrap_or_default()
            );
        }
    }

    Ok(())
}

#[allow(clippy::disallowed_methods)] // CLI is the presentation boundary
async fn handle_verify(args: &VerifyArgs) -> Result<()> {
    let cache_path = dirs::home_dir()
        .map(|h| h.join(".auths").join("log_checkpoint.json"))
        .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;

    let cached_checkpoint: SignedCheckpoint = match std::fs::read_to_string(&cache_path) {
        Ok(json) => serde_json::from_str(&json).context("Failed to parse cached checkpoint")?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if is_json_mode() {
                let result = VerifyResult {
                    consistent: false,
                    cached_size: 0,
                    latest_size: 0,
                    cached_root: String::new(),
                    latest_root: String::new(),
                };
                JsonResponse::success("log verify", result).print()?;
            } else {
                println!("No cached checkpoint found at {}", cache_path.display());
                println!("Run 'auths artifact verify' with a bundle to establish initial trust.");
            }
            return Ok(());
        }
        Err(e) => return Err(e).context("Failed to read cached checkpoint"),
    };

    let registry_url = args.registry.trim_end_matches('/');
    let client =
        HttpRegistryClient::new_with_timeouts(Duration::from_secs(30), Duration::from_secs(60));

    let response_bytes = client
        .fetch_registry_data(registry_url, "v1/log/checkpoint")
        .await
        .context("Failed to fetch latest checkpoint from registry")?;

    let latest_checkpoint: SignedCheckpoint =
        serde_json::from_slice(&response_bytes).context("Failed to parse latest checkpoint")?;

    let report = auths_sdk::workflows::transparency::try_cache_checkpoint(
        &cache_path,
        &latest_checkpoint,
        None,
    );

    match report {
        Ok(consistency) => {
            if is_json_mode() {
                let result = VerifyResult {
                    consistent: consistency.consistent,
                    cached_size: consistency.old_size,
                    latest_size: consistency.new_size,
                    cached_root: hex::encode(cached_checkpoint.checkpoint.root.as_bytes()),
                    latest_root: hex::encode(latest_checkpoint.checkpoint.root.as_bytes()),
                };
                JsonResponse::success("log verify", result).print()?;
            } else {
                println!("Log Consistency: verified");
                println!(
                    "  Cached:  size={}, root={}",
                    consistency.old_size,
                    hex::encode(cached_checkpoint.checkpoint.root.as_bytes())
                );
                println!(
                    "  Latest:  size={}, root={}",
                    consistency.new_size,
                    hex::encode(latest_checkpoint.checkpoint.root.as_bytes())
                );
                println!("  Checkpoint updated.");
            }
        }
        Err(e) => {
            if is_json_mode() {
                let result = VerifyResult {
                    consistent: false,
                    cached_size: cached_checkpoint.checkpoint.size,
                    latest_size: latest_checkpoint.checkpoint.size,
                    cached_root: hex::encode(cached_checkpoint.checkpoint.root.as_bytes()),
                    latest_root: hex::encode(latest_checkpoint.checkpoint.root.as_bytes()),
                };
                let resp: JsonResponse<VerifyResult> = JsonResponse {
                    success: false,
                    command: "log verify".into(),
                    data: Some(result),
                    error: Some(e.to_string()),
                };
                println!(
                    "{}",
                    serde_json::to_string(&resp).context("Failed to serialize error response")?
                );
            } else {
                eprintln!("Log Consistency: FAILED");
                eprintln!("  Error: {e}");
                eprintln!("  This may indicate a split-view attack.");
            }
            bail!("Log consistency verification failed: {e}");
        }
    }

    Ok(())
}
