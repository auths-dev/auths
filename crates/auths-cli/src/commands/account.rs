use anyhow::Result;
use clap::{Parser, Subcommand};
use serde::Deserialize;

use super::executable::ExecutableCommand;
use crate::config::CliConfig;

/// Manage your registry account and view usage.
#[derive(Parser, Debug, Clone)]
pub struct AccountCommand {
    #[clap(subcommand)]
    pub subcommand: AccountSubcommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum AccountSubcommand {
    /// Show account status and rate limits
    Status {
        /// Registry URL to query
        #[arg(long, default_value = "https://registry.auths.dev")]
        registry_url: String,
    },
    /// Show API usage history
    Usage {
        /// Registry URL to query
        #[arg(long, default_value = "https://registry.auths.dev")]
        registry_url: String,
        /// Number of days to show
        #[arg(long, default_value = "7")]
        days: u32,
    },
}

#[derive(Debug, Deserialize)]
struct AccountStatusResponse {
    did: String,
    tier: String,
    daily_limit: i32,
    daily_used: i32,
    expires_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UsageEntry {
    date: String,
    request_count: i32,
}

fn handle_status(registry_url: &str) -> Result<()> {
    let url = registry_url.trim_end_matches('/');

    println!("Fetching account status...");

    let client = reqwest::blocking::Client::new();
    let resp = client
        .get(format!("{url}/v1/account/status"))
        .send()
        .map_err(|e| anyhow::anyhow!("Failed to fetch account status: {e}"))?;

    if !resp.status().is_success() {
        return Err(anyhow::anyhow!("Registry returned {}", resp.status()));
    }

    let status: AccountStatusResponse = resp
        .json()
        .map_err(|e| anyhow::anyhow!("Failed to parse response: {e}"))?;

    println!("\nAccount Status:");
    println!("  DID:         {}", status.did);
    println!("  Tier:        {}", status.tier);
    println!("  Daily Limit: {}", status.daily_limit);
    println!("  Daily Used:  {}", status.daily_used);
    if let Some(expires) = status.expires_at {
        println!("  Expires:     {expires}");
    }

    Ok(())
}

fn handle_usage(registry_url: &str, days: u32) -> Result<()> {
    let url = registry_url.trim_end_matches('/');

    println!("Fetching usage history ({days} days)...");

    let client = reqwest::blocking::Client::new();
    let resp = client
        .get(format!("{url}/v1/account/usage?days={days}"))
        .send()
        .map_err(|e| anyhow::anyhow!("Failed to fetch usage: {e}"))?;

    if !resp.status().is_success() {
        return Err(anyhow::anyhow!("Registry returned {}", resp.status()));
    }

    let entries: Vec<UsageEntry> = resp
        .json()
        .map_err(|e| anyhow::anyhow!("Failed to parse response: {e}"))?;

    if entries.is_empty() {
        println!("\nNo usage data found.");
        return Ok(());
    }

    println!("\nUsage History:");
    for entry in &entries {
        println!("  {} -- {} requests", entry.date, entry.request_count);
    }

    Ok(())
}

impl ExecutableCommand for AccountCommand {
    fn execute(&self, _ctx: &CliConfig) -> Result<()> {
        match &self.subcommand {
            AccountSubcommand::Status { registry_url } => handle_status(registry_url),
            AccountSubcommand::Usage { registry_url, days } => handle_usage(registry_url, *days),
        }
    }
}
