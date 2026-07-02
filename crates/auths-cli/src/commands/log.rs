use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use auths_infra_http::HttpRegistryClient;
use auths_sdk::ports::RegistryClient;
use auths_transparency::SignedCheckpoint;
use clap::{Args, Subcommand};
use serde::Serialize;

use super::executable::ExecutableCommand;
use crate::config::CliConfig;
use crate::ux::format::{JsonResponse, is_json_mode};

#[derive(Args, Debug, Clone)]
#[command(about = "Inspect, verify, and operate the transparency log")]
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
    /// Append an artifact digest to a local tile-backed transparency log
    Append(AppendArgs),
    /// Emit offline inclusion evidence for an appended artifact digest
    Prove(ProveArgs),
}

#[derive(Args, Debug, Clone)]
pub struct InspectArgs {
    /// Sequence number of the entry to inspect
    pub sequence: u128,

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

#[derive(Args, Debug, Clone)]
pub struct AppendArgs {
    /// Artifact digest to log (sha256:<64 hex>)
    #[clap(long)]
    pub artifact: String,

    /// Directory holding the local log (tiles, checkpoint, signing key)
    #[clap(long)]
    pub log_dir: PathBuf,

    /// The log's origin line (its identity in every checkpoint)
    #[clap(long, default_value = "auths.local/log")]
    pub origin: String,
}

#[derive(Args, Debug, Clone)]
pub struct ProveArgs {
    /// Artifact digest to prove (sha256:<64 hex>)
    #[clap(long)]
    pub artifact: String,

    /// Directory holding the local log (tiles, checkpoint, signing key)
    #[clap(long)]
    pub log_dir: PathBuf,

    /// The log's origin line (must match the log's checkpoints)
    #[clap(long, default_value = "auths.local/log")]
    pub origin: String,

    /// Write the inclusion-evidence JSON to this file instead of stdout
    #[clap(long)]
    pub out: Option<PathBuf>,
}

#[derive(Serialize)]
struct VerifyResult {
    consistent: bool,
    cached_size: u64,
    latest_size: u64,
    cached_root: String,
    latest_root: String,
}

#[derive(Serialize)]
struct AppendResult {
    artifact_digest: String,
    leaf_hash: String,
    index: u64,
    size: u64,
    root: String,
    origin: String,
}

impl ExecutableCommand for LogCommand {
    fn execute(&self, _ctx: &CliConfig) -> Result<()> {
        let rt = tokio::runtime::Runtime::new().context("Failed to create async runtime")?;
        rt.block_on(async {
            match &self.command {
                LogSubcommand::Inspect(args) => handle_inspect(args).await,
                LogSubcommand::Verify(args) => handle_verify(args).await,
                LogSubcommand::Append(args) => handle_append(args).await,
                LogSubcommand::Prove(args) => handle_prove(args).await,
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
        let sequence: u128 = entry
            .get("sequence")
            .and_then(|s| s.as_u64())
            .map(u128::from)
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
        &crate::adapters::config_store::FileConfigStore,
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

#[allow(clippy::disallowed_methods)] // CLI is the presentation boundary (checkpoint timestamp)
async fn handle_append(args: &AppendArgs) -> Result<()> {
    let appended = auths_sdk::workflows::transparency::append_artifact_digest(
        &args.log_dir,
        &args.origin,
        &args.artifact,
        chrono::Utc::now(),
    )
    .await
    .context("Failed to append artifact to transparency log")?;

    let checkpoint = &appended.signed_checkpoint.checkpoint;
    let result = AppendResult {
        artifact_digest: appended.artifact_digest,
        leaf_hash: hex::encode(appended.leaf_hash.as_bytes()),
        index: appended.index,
        size: checkpoint.size,
        root: hex::encode(checkpoint.root.as_bytes()),
        origin: checkpoint.origin.to_string(),
    };

    if is_json_mode() {
        JsonResponse::success("log append", result).print()?;
    } else {
        println!("Appended to transparency log");
        println!("  Artifact: {}", result.artifact_digest);
        println!("  Leaf:     {}", result.leaf_hash);
        println!("  Index:    {}", result.index);
        println!("  Size:     {}", result.size);
        println!("  Root:     {}", result.root);
        println!("  Origin:   {}", result.origin);
    }
    Ok(())
}

async fn handle_prove(args: &ProveArgs) -> Result<()> {
    let inclusion = auths_sdk::workflows::transparency::prove_artifact_digest(
        &args.log_dir,
        &args.origin,
        &args.artifact,
    )
    .await
    .context("Failed to prove artifact inclusion")?;

    if let Some(out) = &args.out {
        let json = serde_json::to_string_pretty(&inclusion)
            .context("Failed to serialize inclusion evidence")?;
        std::fs::write(out, json).with_context(|| format!("Failed to write {}", out.display()))?;
        if is_json_mode() {
            JsonResponse::success("log prove", &inclusion).print()?;
        } else {
            println!("Inclusion evidence written");
            println!("  Artifact: {}", args.artifact);
            println!("  Index:    {}", inclusion.inclusion_proof.index);
            println!("  Size:     {}", inclusion.inclusion_proof.size);
            println!("  Out:      {}", out.display());
        }
    } else if is_json_mode() {
        JsonResponse::success("log prove", &inclusion).print()?;
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&inclusion)
                .context("Failed to serialize inclusion evidence")?
        );
    }
    Ok(())
}
