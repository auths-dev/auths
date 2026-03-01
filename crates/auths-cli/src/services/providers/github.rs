use anyhow::{Context, Result};

use super::{ClaimContext, PlatformAuth, PlatformClaimProvider};
use crate::services::{gist, oauth, platform_claim};

pub struct GitHubProvider;

impl PlatformClaimProvider for GitHubProvider {
    fn platform_name(&self) -> &'static str {
        "github"
    }

    fn authenticate_and_publish(&self, ctx: &ClaimContext) -> Result<PlatformAuth> {
        let rt = tokio::runtime::Runtime::new().context("failed to create async runtime")?;

        let auth = rt
            .block_on(oauth::github_device_flow(ctx.http_client, ctx.out))
            .context("GitHub authentication failed")?;

        let claim_json = platform_claim::create_signed_platform_claim(
            "github",
            &auth.username,
            ctx.controller_did,
            ctx.key_alias,
            ctx.passphrase_provider,
        )?;

        let proof_url = rt
            .block_on(gist::publish_proof_gist(
                ctx.http_client,
                &auth.access_token,
                &claim_json,
            ))
            .context("failed to publish proof Gist")?;

        ctx.out.print_success(&format!(
            "Published proof Gist: {}",
            ctx.out.info(&proof_url)
        ));

        Ok(PlatformAuth {
            username: auth.username,
            proof_url,
        })
    }
}
