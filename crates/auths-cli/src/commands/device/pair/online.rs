//! Online pairing mode — uses a registry relay server.

use anyhow::{Context, Result};
use auths_sdk::core_config::EnvironmentConfig;
use auths_sdk::pairing::{PairingSessionParams, PairingStatus, initiate_online_pairing};
use auths_sdk::pairing::{QrOptions, render_qr};
use console::style;
use indicatif::ProgressBar;

use auths_infra_http::HttpPairingRelayClient;

use crate::core::provider::CliPassphraseProvider;
use crate::factories::storage::build_auths_context;

use super::common::*;

/// Initiate a pairing session using the registry relay.
pub(crate) async fn handle_initiate_online(
    now: chrono::DateTime<chrono::Utc>,
    registry: &str,
    no_qr: bool,
    expiry_secs: u64,
    capabilities: &[String],
    env_config: &EnvironmentConfig,
) -> Result<()> {
    let auths_dir = auths_sdk::paths::auths_home_with_config(env_config)
        .context("Could not determine Auths home directory. Check $AUTHS_HOME or $HOME.")?;

    let identity_storage = auths_sdk::storage::RegistryIdentityStorage::new(auths_dir.clone());
    let controller_did =
        auths_sdk::pairing::load_controller_did(&identity_storage).map_err(anyhow::Error::from)?;

    print_pairing_header("ONLINE", registry, &controller_did);

    let passphrase_provider: std::sync::Arc<
        dyn auths_sdk::signing::PassphraseProvider + Send + Sync,
    > = std::sync::Arc::new(CliPassphraseProvider::new());

    let ctx = build_auths_context(&auths_dir, env_config, Some(passphrase_provider))
        .context("Failed to build auths context")?;

    let relay = HttpPairingRelayClient::new();

    let session_spinner = create_wait_spinner(&format!("{GEAR}Registering session..."));
    // Clone so we can finish it inside the Fn callback (ProgressBar is Arc-backed).
    let session_sp = session_spinner.clone();

    let wait_spinner = ProgressBar::new_spinner();
    {
        use indicatif::ProgressStyle;
        #[allow(clippy::unwrap_used)] // INVARIANT: template is a compile-time constant
        let style = ProgressStyle::with_template("{spinner:.cyan} {msg}")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]);
        wait_spinner.set_style(style);
    }
    let wait_sp = wait_spinner.clone();

    let registry_str = registry.to_string();
    let no_qr_flag = no_qr;

    let on_status = move |status: PairingStatus| match status {
        PairingStatus::SessionCreated { token, ttl_seconds } => {
            session_sp.finish_with_message(format!("{CHECK}Session registered"));

            if !no_qr_flag {
                println!();
                let options = QrOptions::default();
                if let Ok(qr) = render_qr(&token, &options) {
                    println!("{}", qr);
                }
            }

            let sc = &token.short_code;
            let formatted_code = format!("{}-{}", &sc[..3], &sc[3..]);

            println!();
            println!("  Scan the QR code above, or enter this code manually:");
            println!();
            println!("    {}", style(&formatted_code).bold().cyan());
            println!();
            if !token.capabilities.is_empty() {
                println!(
                    "  {} {}",
                    style("Capabilities:").dim(),
                    token.capabilities.join(", ")
                );
            }
            println!(
                "  {} {} ({}s remaining)",
                style("Expires:").dim(),
                token.expires_at.format("%H:%M:%S"),
                ttl_seconds
            );
            println!();
            println!("  {}", style("(Press Ctrl+C to cancel)").dim());
            println!();

            wait_sp.set_message(format!("{PHONE}Waiting for device..."));
            use std::time::Duration;
            wait_sp.enable_steady_tick(Duration::from_millis(80));

            let _ = registry_str; // suppress unused warning for captured var
        }
        PairingStatus::WaitingForApproval => {}
        PairingStatus::Approved => {
            wait_sp.finish_with_message(format!("{CHECK}Response received!"));
        }
    };

    let params = PairingSessionParams {
        controller_did,
        registry: registry.to_string(),
        capabilities: capabilities.to_vec(),
        expiry_secs,
    };

    match initiate_online_pairing(params, &relay, &ctx, now, Some(&on_status))
        .await
        .map_err(anyhow::Error::from)?
    {
        auths_sdk::pairing::PairingCompletionResult::Success {
            device_did,
            device_name,
        } => {
            wait_spinner.finish_and_clear();
            print_completion(device_name.as_deref(), &device_did);
        }
        auths_sdk::pairing::PairingCompletionResult::Fallback {
            device_did,
            device_name: _,
            error,
        } => {
            wait_spinner.finish_and_clear();
            println!();
            println!(
                "  {}{} {}",
                WARN,
                style("Could not create attestation:").yellow(),
                error
            );
            println!("  You can manually link this device using:");
            println!(
                "    {}",
                style(format!("auths device link --device {} ...", device_did)).dim()
            );
        }
    }

    Ok(())
}
