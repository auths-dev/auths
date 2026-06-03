//! Join mode — join an existing pairing session via short code, as a KERI-delegated device.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use auths_crypto::CurveType;
use auths_infra_http::HttpPairingRelayClient;
use auths_pairing_protocol::sas;
use auths_sdk::core_config::EnvironmentConfig;
use auths_sdk::keychain::KeyAlias;
use auths_sdk::pairing::{
    PairingToken, build_delegated_join_response, finalize_delegated_join, validate_short_code,
};
use auths_sdk::ports::pairing::PairingRelayClient;
use console::style;

use crate::core::provider::CliPassphraseProvider;
use crate::factories::storage::build_auths_context;

use super::common::*;

/// Join an existing pairing session using a short code, as a KERI-delegated device.
///
/// The joining device generates its own key, ships a self-signed `dip` (delegated by
/// the session's controller), and — after the SAS ceremony — waits for the controller
/// to anchor it, then verifies the anchor and persists its own KEL + key. No
/// pre-existing identity is required; the device's registry is provisioned on first use.
pub(crate) async fn handle_join(
    now: chrono::DateTime<chrono::Utc>,
    code: &str,
    registry: &str,
    env_config: &EnvironmentConfig,
) -> Result<()> {
    let normalized = validate_short_code(code).map_err(anyhow::Error::from)?;
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

    let auths_dir = auths_sdk::paths::auths_home_with_config(env_config)
        .context("Could not determine Auths home directory. Check $AUTHS_HOME or $HOME.")?;

    let passphrase_provider: Arc<dyn auths_sdk::signing::PassphraseProvider + Send + Sync> =
        Arc::new(CliPassphraseProvider::new());
    let ctx = build_auths_context(&auths_dir, env_config, Some(passphrase_provider))
        .context("Failed to build auths context")?;

    // Look up the session by short code → token (the controller is the delegating root).
    let session_data = relay
        .lookup_by_code(registry, &normalized)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to look up session: {}", e))?;

    let token_data = session_data
        .token
        .ok_or_else(|| anyhow::anyhow!("session has no token data"))?;

    let token = PairingToken {
        controller_did: token_data.controller_did.clone(),
        endpoint: registry.to_string(),
        short_code: normalized.clone(),
        session_id: session_data.session_id.clone(),
        ephemeral_pubkey: token_data.ephemeral_pubkey.to_string(),
        expires_at: chrono::DateTime::from_timestamp(token_data.expires_at, 0).unwrap_or(now),
        capabilities: token_data.capabilities.clone(),
        kem_slot: None,
        daemon_spki_sha256: None,
    };

    if token.is_expired(now) {
        anyhow::bail!(
            "Pairing session expired. Start a new session with `auths pair` on the controller device."
        );
    }

    println!(
        "  {} {}",
        style("Controller:").dim(),
        style(&token.controller_did).cyan()
    );
    println!();

    // Generate our own key + a self-signed delegated inception, and sign the ECDH
    // response with that same key (so SAS + verify_response prove custody of the dip key).
    let create_spinner =
        create_wait_spinner(&format!("{GEAR}Creating delegated pairing response..."));
    let device_alias = KeyAlias::new_unchecked("device");
    let (submit_req, pending, shared_secret) = build_delegated_join_response(
        now,
        &token,
        CurveType::Ed25519,
        device_alias,
        Some(hostname()),
    )
    .map_err(anyhow::Error::from)
    .context("Failed to build delegated pairing response")?;

    // Derive SAS over the transcript-bound shared secret (MITM defence — unchanged).
    let initiator_ecdh_pub = token
        .ephemeral_pubkey_bytes()
        .map_err(|e| anyhow::anyhow!("Invalid initiator pubkey: {}", e))?;
    let responder_ecdh_pub = submit_req
        .device_ephemeral_pubkey
        .decode()
        .map_err(|e| anyhow::anyhow!("Invalid responder pubkey: {}", e))?;
    let sas_bytes = sas::derive_sas(
        &shared_secret,
        &initiator_ecdh_pub,
        &responder_ecdh_pub,
        &token.session_id,
        &normalized,
    );

    relay
        .submit_response(registry, &session_data.session_id, &submit_req)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to submit response: {}", e))?;
    create_spinner.finish_with_message(format!("{CHECK}Response submitted"));

    // SAS verification ceremony.
    let confirmed = prompt_sas_confirmation(&sas_bytes)?;
    if !confirmed {
        display_sas_mismatch_warning();
        anyhow::bail!(
            "Security codes didn't match — the connection may not be secure. Restart pairing with `auths pair`."
        );
    }

    // Wait for the controller to anchor our delegation, then verify it + persist locally.
    let wait_spinner = create_wait_spinner(&format!(
        "{GEAR}Waiting for the controller to anchor this device..."
    ));
    let confirmation = relay
        .wait_for_confirmation(registry, &session_data.session_id, Duration::from_secs(120))
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get confirmation: {}", e))?
        .ok_or_else(|| {
            anyhow::anyhow!("Timed out waiting for the controller to anchor this device")
        })?;

    if confirmation.aborted {
        wait_spinner.finish_and_clear();
        anyhow::bail!("The controller rejected the pairing — no delegation was anchored.");
    }

    let device_did = finalize_delegated_join(&ctx, pending, &confirmation)
        .map_err(anyhow::Error::from)
        .context("Failed to verify and persist the delegation")?;
    wait_spinner.finish_with_message(format!("{CHECK}Delegation anchored and persisted"));

    let device_name = hostname();
    print_completion(Some(&device_name), &device_did);

    Ok(())
}
