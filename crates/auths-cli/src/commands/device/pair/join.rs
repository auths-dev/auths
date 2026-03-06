//! Join mode — join an existing pairing session via short code.

use anyhow::{Context, Result};
use auths_core::config::EnvironmentConfig;
use auths_infra_http::HttpPairingRelayClient;
use auths_sdk::pairing::{
    PairingCompletionResult, join_pairing_session, load_device_signing_material,
};
use chrono::Utc;
use console::style;

use crate::core::provider::CliPassphraseProvider;
use crate::factories::storage::build_auths_context;

use super::common::*;

/// Join an existing pairing session using a short code.
pub(crate) async fn handle_join(
    code: &str,
    registry: &str,
    env_config: &EnvironmentConfig,
) -> Result<()> {
    let normalized =
        auths_sdk::pairing::validate_short_code(code).map_err(|e| anyhow::anyhow!("{}", e))?;

    let formatted = format!("{}-{}", &normalized[..3], &normalized[3..]);

    println!();
    println!(
        "{}",
        style(format!("━━━ {LINK}Joining Pairing Session ━━━")).bold()
    );
    println!();
    println!(
        "  {} {}",
        style("Code:").dim(),
        style(&formatted).bold().cyan()
    );
    println!("  {} {}", style("Registry:").dim(), style(registry).cyan());
    println!();

    let relay = HttpPairingRelayClient::new();

    let auths_dir = auths_core::paths::auths_home_with_config(env_config).unwrap_or_default();

    if !auths_dir.exists() {
        anyhow::bail!("No local identity found. Run 'auths init' first.");
    }

    let passphrase_provider: std::sync::Arc<
        dyn auths_core::signing::PassphraseProvider + Send + Sync,
    > = std::sync::Arc::new(CliPassphraseProvider::new());

    let key_spinner = create_wait_spinner(&format!("{GEAR}Loading local device key..."));

    let ctx = build_auths_context(&auths_dir, env_config, Some(passphrase_provider))
        .context("Failed to build auths context")?;

    let material = load_device_signing_material(&ctx).map_err(|e| anyhow::anyhow!("{}", e))?;

    key_spinner.finish_with_message(format!("{CHECK}Device key loaded"));

    println!(
        "  {} {}",
        style("Device DID:").dim(),
        style(&material.device_did).dim()
    );
    println!();

    let create_spinner = create_wait_spinner(&format!("{GEAR}Creating and submitting response..."));

    match join_pairing_session(
        code,
        registry,
        &relay,
        Utc::now(),
        &material,
        Some(hostname()),
    )
    .await
    .map_err(|e| anyhow::anyhow!("{}", e))?
    {
        PairingCompletionResult::Success { .. } => {
            create_spinner.finish_with_message(format!("{CHECK}Response submitted"));
        }
        PairingCompletionResult::Fallback { error, .. } => {
            create_spinner.finish_and_clear();
            anyhow::bail!("Failed to submit pairing response: {}", error);
        }
    }

    println!();
    println!(
        "{}",
        style(format!("━━━ {CHECK}Response Submitted ━━━"))
            .green()
            .bold()
    );
    println!();
    println!(
        "  {}",
        style("The initiating device will verify the response and create").dim()
    );
    println!("  {}", style("a device attestation for this device.").dim());
    println!();

    Ok(())
}
