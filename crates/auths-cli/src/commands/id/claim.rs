use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use auths_core::config::EnvironmentConfig;
use auths_core::signing::PassphraseProvider;
use auths_infra_http::{HttpGistPublisher, HttpGitHubOAuthProvider, HttpRegistryClaimClient};
use auths_sdk::workflows::platform::{GitHubClaimConfig, claim_github_identity};
use clap::{Parser, Subcommand};
use console::style;

use crate::config::Capabilities;
use crate::factories::storage::build_auths_context;
use crate::ux::format::{JsonResponse, is_json_mode};

use super::register::DEFAULT_REGISTRY_URL;

const DEFAULT_GITHUB_CLIENT_ID: &str = "Ov23lio2CiTHBjM2uIL4";

#[allow(clippy::disallowed_methods)] // CLI boundary: optional env override
fn github_client_id() -> String {
    std::env::var("AUTHS_GITHUB_CLIENT_ID").unwrap_or_else(|_| DEFAULT_GITHUB_CLIENT_ID.to_string())
}

#[derive(Parser, Debug, Clone)]
#[command(about = "Add a platform claim to an already-registered identity.")]
pub struct ClaimCommand {
    #[command(subcommand)]
    pub platform: ClaimPlatform,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ClaimPlatform {
    /// Link your GitHub account to your identity.
    Github {
        /// Registry URL to publish the claim to.
        #[arg(long, default_value = DEFAULT_REGISTRY_URL)]
        registry: String,
    },
}

pub fn handle_claim(
    cmd: &ClaimCommand,
    repo_path: &Path,
    passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync>,
    env_config: &EnvironmentConfig,
    now: chrono::DateTime<chrono::Utc>,
    caps: &Capabilities,
) -> Result<()> {
    let registry_url = match &cmd.platform {
        ClaimPlatform::Github { registry } => registry.clone(),
    };

    let ctx = build_auths_context(repo_path, env_config, Some(passphrase_provider), caps)
        .context("Failed to build auths context")?;

    let oauth = HttpGitHubOAuthProvider::new();
    let publisher = HttpGistPublisher::new();
    let registry_client = HttpRegistryClaimClient::new();

    let config = GitHubClaimConfig {
        client_id: github_client_id(),
        registry_url,
        scopes: "read:user gist".to_string(),
    };

    let on_device_code = |code: &auths_core::ports::platform::DeviceCodeResponse| {
        println!();
        println!("  Copy this code: {}", style(&code.user_code).bold().cyan());
        println!("  At: {}", style(&code.verification_uri).cyan());
        println!();
        println!(
            "  {}",
            style("Press 'enter' to open GitHub after copying the code above").blue()
        );
        // Wait for the user to press Enter before opening the browser.
        let _ = std::io::stdin().read_line(&mut String::new());
        println!();
        if let Err(e) = open::that(&code.verification_uri) {
            println!(
                "  {}",
                style(format!("Could not open browser: {e}")).yellow()
            );
            println!("  Please open the URL above manually.");
        } else {
            println!("  Browser opened — waiting for authorization...");
        }
    };

    let rt = tokio::runtime::Runtime::new().context("failed to create async runtime")?;
    let response = rt
        .block_on(claim_github_identity(
            &oauth,
            &publisher,
            &registry_client,
            &ctx,
            config,
            now,
            &on_device_code,
        ))
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    if is_json_mode() {
        let json_resp = JsonResponse::success("id claim", &response.message);
        json_resp.print()?;
    } else {
        println!("  {}", style(&response.message).green());
    }

    Ok(())
}
