use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};

use auths_core::signing::PassphraseProvider;
use auths_id::storage::identity::IdentityStorage;
use auths_storage::git::RegistryIdentityStorage;

use crate::services::providers::github::GitHubProvider;
use crate::services::providers::{ClaimContext, PlatformClaimProvider};
use crate::ux::format::{JsonResponse, Output, is_json_mode};

use super::register::DEFAULT_REGISTRY_URL;

#[derive(Parser, Debug, Clone)]
#[command(about = "Add a platform claim to an already-registered identity.")]
pub struct ClaimCommand {
    #[command(subcommand)]
    pub platform: ClaimPlatform,

    #[arg(long, default_value = DEFAULT_REGISTRY_URL)]
    pub registry: String,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ClaimPlatform {
    /// Link your GitHub account to your identity.
    Github,
}

#[derive(Serialize)]
struct ClaimJsonResponse {
    platform: String,
    namespace: String,
    did: String,
}

#[derive(Deserialize)]
struct ServerClaimResponse {
    platform: String,
    namespace: String,
    did: String,
}

pub fn handle_claim(
    cmd: &ClaimCommand,
    repo_path: &Path,
    passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync>,
    http_client: &reqwest::Client,
) -> Result<()> {
    let out = Output::stdout();

    let identity_storage = RegistryIdentityStorage::new(repo_path.to_path_buf());
    let identity = identity_storage
        .load_identity()
        .context("Failed to load identity. Run `auths init` first.")?;

    let controller_did = &identity.controller_did;

    let provider: Box<dyn PlatformClaimProvider> = match cmd.platform {
        ClaimPlatform::Github => Box::new(GitHubProvider),
    };

    let ctx = ClaimContext {
        out: &out,
        controller_did: controller_did.as_str(),
        key_alias: "main",
        passphrase_provider: passphrase_provider.as_ref(),
        http_client,
    };

    let auth = provider.authenticate_and_publish(&ctx)?;

    out.print_info("Submitting claim to registry...");

    let rt = tokio::runtime::Runtime::new().context("failed to create async runtime")?;
    let resp = rt.block_on(submit_claim(
        http_client,
        &cmd.registry,
        controller_did.as_str(),
        &auth.proof_url,
    ))?;

    if is_json_mode() {
        let response = JsonResponse::success(
            "id claim",
            ClaimJsonResponse {
                platform: resp.platform.clone(),
                namespace: resp.namespace.clone(),
                did: resp.did.clone(),
            },
        );
        response.print()?;
    } else {
        out.print_success(&format!(
            "Platform claim indexed: {} @{} -> {}",
            resp.platform, resp.namespace, resp.did
        ));
    }

    Ok(())
}

async fn submit_claim(
    client: &reqwest::Client,
    registry_url: &str,
    did: &str,
    proof_url: &str,
) -> Result<ServerClaimResponse> {
    let url = format!(
        "{}/v1/identities/{}/claims",
        registry_url.trim_end_matches('/'),
        did
    );

    let resp = client
        .post(&url)
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({ "proof_url": proof_url }))
        .send()
        .await
        .context("failed to submit claim to registry")?;

    let status = resp.status();

    if status.as_u16() == 404 {
        anyhow::bail!("Identity not found at registry. Run `auths id register` first.");
    }

    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Registry returned {}: {}", status, body);
    }

    resp.json::<ServerClaimResponse>()
        .await
        .context("failed to parse registry response")
}
