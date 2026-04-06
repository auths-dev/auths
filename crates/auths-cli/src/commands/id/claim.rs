use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use auths_infra_http::{
    HttpGistPublisher, HttpGitHubOAuthProvider, HttpNpmAuthProvider, HttpRegistryClaimClient,
};
use auths_sdk::core_config::EnvironmentConfig;
use auths_sdk::signing::PassphraseProvider;
use auths_sdk::workflows::platform::{
    GitHubClaimConfig, NpmClaimConfig, PypiClaimConfig, claim_github_identity, claim_npm_identity,
    claim_pypi_identity,
};
use clap::{Parser, Subcommand};
use console::style;

use crate::factories::storage::build_auths_context;
use crate::ux::format::{JsonResponse, is_json_mode};

use super::register::DEFAULT_REGISTRY_URL;

const DEFAULT_GITHUB_CLIENT_ID: &str = "Ov23lio2CiTHBjM2uIL4";

#[allow(clippy::disallowed_methods)]
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
    /// Link your GitHub account to your identity via OAuth device flow.
    Github {
        /// Registry URL to publish the claim to.
        #[arg(long, default_value = DEFAULT_REGISTRY_URL)]
        registry: String,
    },
    /// Link your npm account to your identity via access token.
    Npm {
        /// Registry URL to publish the claim to.
        #[arg(long, default_value = DEFAULT_REGISTRY_URL)]
        registry: String,
    },
    /// Link your PyPI account to your identity via API token.
    Pypi {
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
) -> Result<()> {
    let registry_url = match &cmd.platform {
        ClaimPlatform::Github { registry }
        | ClaimPlatform::Npm { registry }
        | ClaimPlatform::Pypi { registry } => registry.clone(),
    };

    let ctx = build_auths_context(repo_path, env_config, Some(passphrase_provider))
        .context("Failed to build auths context")?;

    let registry_client = HttpRegistryClaimClient::new();

    match &cmd.platform {
        ClaimPlatform::Github { .. } => {
            let oauth = HttpGitHubOAuthProvider::new();
            let publisher = HttpGistPublisher::new();

            let config = GitHubClaimConfig {
                client_id: github_client_id(),
                registry_url,
                scopes: "read:user gist".to_string(),
            };

            let on_device_code = |code: &auths_sdk::ports::platform::DeviceCodeResponse| {
                println!();
                println!("  Copy this code: {}", style(&code.user_code).bold().cyan());
                println!("  At: {}", style(&code.verification_uri).cyan());
                println!();
                println!(
                    "  {}",
                    style("Press 'enter' to open GitHub after copying the code above").blue()
                );
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
                .map_err(anyhow::Error::from)?;

            print_response(&response.message)?;
        }

        ClaimPlatform::Npm { .. } => {
            println!();
            println!("  {}", style("npm platform claim").bold());
            println!();
            println!(
                "  Create a read-only access token at:\n  {}",
                style("https://www.npmjs.com/settings/~/tokens").cyan()
            );
            println!();

            let npm_token = rpassword::prompt_password("  Enter your npm access token: ")
                .context("Failed to read npm token")?;

            if npm_token.trim().is_empty() {
                return Err(anyhow::anyhow!("npm access token cannot be empty"));
            }

            println!("  Verifying token...");

            let npm_provider = HttpNpmAuthProvider::new();
            let rt = tokio::runtime::Runtime::new().context("failed to create async runtime")?;

            let profile = rt
                .block_on(npm_provider.verify_token(npm_token.trim()))
                .map_err(anyhow::Error::from)?;

            println!(
                "  {} Authenticated as {}",
                style("✓").green(),
                style(&profile.login).bold()
            );

            let config = NpmClaimConfig { registry_url };

            let response = rt
                .block_on(claim_npm_identity(
                    &profile.login,
                    npm_token.trim(),
                    &registry_client,
                    &ctx,
                    config,
                    now,
                ))
                .map_err(anyhow::Error::from)?;

            print_response(&response.message)?;
        }

        ClaimPlatform::Pypi { .. } => {
            println!();
            println!("  {}", style("PyPI platform claim").bold());
            println!();
            println!(
                "  Enter your PyPI username (visible at {}):",
                style("https://pypi.org/account/").cyan()
            );
            println!();
            println!(
                "  {}",
                style("Note: ownership is verified when you claim a package namespace,").dim()
            );
            println!(
                "  {}",
                style("not at this step. The PyPI JSON API confirms you are a maintainer.").dim()
            );
            println!();

            print!("  PyPI username: ");
            std::io::Write::flush(&mut std::io::stdout()).context("flush")?;
            let mut pypi_username = String::new();
            std::io::stdin()
                .read_line(&mut pypi_username)
                .context("Failed to read PyPI username")?;

            let trimmed = pypi_username.trim();
            if trimmed.is_empty() {
                return Err(anyhow::anyhow!("PyPI username cannot be empty"));
            }

            println!("  Claiming PyPI identity as {}...", style(trimmed).bold());

            let config = PypiClaimConfig { registry_url };

            let rt = tokio::runtime::Runtime::new().context("failed to create async runtime")?;
            let response = rt
                .block_on(claim_pypi_identity(
                    trimmed,
                    &registry_client,
                    &ctx,
                    config,
                    now,
                ))
                .map_err(anyhow::Error::from)?;

            print_response(&response.message)?;
        }
    }

    Ok(())
}

fn print_response(message: &str) -> Result<()> {
    if is_json_mode() {
        let json_resp = JsonResponse::success("id claim", message);
        json_resp.print()?;
    } else {
        println!("  {}", style(message).green());
    }
    Ok(())
}
