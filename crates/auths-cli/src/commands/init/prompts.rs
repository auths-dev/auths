//! Interactive prompt functions for the init command.

use anyhow::{Context, Result, anyhow};
use dialoguer::{Confirm, Input, Select};
use std::path::Path;
use std::sync::Arc;

use auths_core::signing::PassphraseProvider;
use auths_core::storage::keychain::IdentityDID;
use auths_id::storage::identity::IdentityStorage;
use auths_sdk::types::{GitSigningScope, IdentityConflictPolicy};
use auths_storage::git::RegistryIdentityStorage;

use super::InitCommand;
use super::InitProfile;
use super::helpers::get_auths_repo_path;
use crate::factories::storage::build_auths_context;
use crate::ux::format::Output;

pub(crate) fn prompt_profile(out: &Output) -> Result<InitProfile> {
    out.print_heading("Select Setup Profile");
    out.newline();

    let items = [
        "Developer - Full local setup with keychain and git signing",
        "CI - Ephemeral identity for CI/CD pipelines",
        "Agent - Scoped identity for AI agents",
    ];

    let selection = Select::new()
        .with_prompt("Choose your setup profile")
        .items(items)
        .default(0)
        .interact()?;

    Ok(match selection {
        0 => InitProfile::Developer,
        1 => InitProfile::Ci,
        _ => InitProfile::Agent,
    })
}

pub(crate) fn prompt_for_alias(interactive: bool, cmd: &InitCommand) -> Result<String> {
    if interactive {
        Ok(Input::new()
            .with_prompt("Key alias")
            .default(cmd.key_alias.clone())
            .interact_text()?)
    } else {
        Ok(cmd.key_alias.clone())
    }
}

pub(crate) fn prompt_for_conflict_policy(
    interactive: bool,
    cmd: &InitCommand,
    registry_path: &Path,
    out: &Output,
) -> Result<IdentityConflictPolicy> {
    if cmd.force {
        return Ok(IdentityConflictPolicy::ForceNew);
    }

    let identity_storage = RegistryIdentityStorage::new(registry_path.to_path_buf());
    if let Ok(existing) = identity_storage.load_identity() {
        out.println(&format!(
            "  Found existing identity: {}",
            out.info(existing.controller_did.as_str())
        ));

        if !interactive {
            return Ok(IdentityConflictPolicy::ReuseExisting);
        }

        let use_existing = Confirm::new()
            .with_prompt("Use existing identity?")
            .default(true)
            .interact()?;
        if use_existing {
            return Ok(IdentityConflictPolicy::ReuseExisting);
        }

        let overwrite = Confirm::new()
            .with_prompt("Create new identity? This will NOT delete the old one.")
            .default(false)
            .interact()?;
        if !overwrite {
            return Err(anyhow!("Setup cancelled by user"));
        }
    }

    Ok(IdentityConflictPolicy::ForceNew)
}

pub(crate) fn prompt_for_git_scope(interactive: bool) -> Result<GitSigningScope> {
    if !interactive {
        return Ok(GitSigningScope::Global);
    }

    let choice = Select::new()
        .with_prompt("Configure git signing for")
        .items([
            "This repository only (--local)",
            "All repositories (--global)",
        ])
        .default(1)
        .interact()?;

    if choice == 0 {
        let repo_path = std::env::current_dir()?;
        Ok(GitSigningScope::Local { repo_path })
    } else {
        Ok(GitSigningScope::Global)
    }
}

pub(crate) fn prompt_platform_verification(
    out: &Output,
    passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync>,
    env_config: &auths_core::config::EnvironmentConfig,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Option<(String, String)>> {
    let items = [
        "GitHub — link your GitHub identity (recommended)",
        "GitLab — coming soon",
        "Anonymous — skip platform verification",
    ];

    let selection = Select::new()
        .with_prompt("Claim your Developer Passport")
        .items(items)
        .default(0)
        .interact()?;

    match selection {
        0 => run_github_verification(out, passphrase_provider, env_config, now),
        1 => {
            out.print_warn("GitLab integration is coming soon. Continuing as anonymous.");
            Ok(None)
        }
        _ => Ok(None),
    }
}

fn run_github_verification(
    out: &Output,
    passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync>,
    env_config: &auths_core::config::EnvironmentConfig,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Option<(String, String)>> {
    use std::time::Duration;

    use auths_core::ports::platform::OAuthDeviceFlowProvider;
    use auths_core::ports::platform::PlatformProofPublisher;
    use auths_infra_http::{HttpGistPublisher, HttpGitHubOAuthProvider};
    use auths_sdk::workflows::platform::create_signed_platform_claim;

    const GITHUB_CLIENT_ID: &str = "Ov23lio2CiTHBjM2uIL4";
    let client_id =
        std::env::var("AUTHS_GITHUB_CLIENT_ID").unwrap_or_else(|_| GITHUB_CLIENT_ID.to_string());

    let auths_dir = get_auths_repo_path()?;
    let ctx = build_auths_context(&auths_dir, env_config, Some(passphrase_provider))?;

    let oauth = HttpGitHubOAuthProvider::new();
    let publisher = HttpGistPublisher::new();

    let rt = tokio::runtime::Runtime::new().context("failed to create async runtime")?;

    let device_code = rt
        .block_on(oauth.request_device_code(&client_id, "read:user gist"))
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    out.println(&format!(
        "  Enter this code: {}",
        out.bold(&device_code.user_code)
    ));
    out.println(&format!(
        "  At: {}",
        out.info(&device_code.verification_uri)
    ));
    if let Err(e) = open::that(&device_code.verification_uri) {
        out.print_warn(&format!("Could not open browser automatically: {e}"));
        out.println("  Please open the URL above manually.");
    } else {
        out.println("  Browser opened — waiting for authorization...");
    }

    let expires_in = Duration::from_secs(device_code.expires_in);
    let interval = Duration::from_secs(device_code.interval);

    let access_token = rt
        .block_on(oauth.poll_for_token(&client_id, &device_code.device_code, interval, expires_in))
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let profile = rt
        .block_on(oauth.fetch_user_profile(&access_token))
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    out.print_success(&format!("Authenticated as @{}", profile.login));

    let controller_did = auths_sdk::pairing::load_controller_did(ctx.identity_storage.as_ref())
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    #[allow(clippy::disallowed_methods)] // INVARIANT: controller_did from identity storage
    let identity_did = IdentityDID::new_unchecked(controller_did.clone());
    let aliases = ctx
        .key_storage
        .list_aliases_for_identity(&identity_did)
        .context("failed to list key aliases")?;
    let key_alias = aliases
        .into_iter()
        .find(|a| !a.contains("--next-"))
        .ok_or_else(|| anyhow::anyhow!("no signing key found for {controller_did}"))?;

    let claim_json = create_signed_platform_claim(
        "github",
        &profile.login,
        &controller_did,
        &key_alias,
        &ctx,
        now,
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    let proof_url = rt
        .block_on(publisher.publish_proof(&access_token, &claim_json))
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    out.print_success(&format!("Published proof Gist: {}", out.info(&proof_url)));

    Ok(Some((proof_url, profile.login)))
}
