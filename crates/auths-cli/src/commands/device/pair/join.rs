//! Join mode — join an existing pairing session via short code.

use anyhow::{Context, Result};
use auths_core::config::EnvironmentConfig;
use auths_core::pairing::types::Base64UrlEncoded;
use auths_core::pairing::{PairingResponse, PairingToken};
use auths_core::ports::pairing::PairingRelayClient;
use auths_infra_http::HttpPairingRelayClient;
use auths_pairing_protocol::sas;
use auths_sdk::pairing::{load_device_signing_material, validate_short_code};
use console::style;

use crate::core::provider::CliPassphraseProvider;
use crate::factories::storage::build_auths_context;

use super::common::*;

/// Join an existing pairing session using a short code.
pub(crate) async fn handle_join(
    now: chrono::DateTime<chrono::Utc>,
    code: &str,
    registry: &str,
    env_config: &EnvironmentConfig,
) -> Result<()> {
    let normalized = validate_short_code(code).map_err(|e| anyhow::anyhow!("{}", e))?;

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

    // Look up the session by short code
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
        ephemeral_pubkey: token_data.ephemeral_pubkey.to_string(),
        expires_at: chrono::DateTime::from_timestamp(token_data.expires_at, 0).unwrap_or(now),
        capabilities: token_data.capabilities.clone(),
    };

    if token.is_expired(now) {
        anyhow::bail!("Session expired");
    }

    let create_spinner = create_wait_spinner(&format!("{GEAR}Creating pairing response..."));

    // Create the response + ECDH
    let (pairing_response, shared_secret) = PairingResponse::create(
        now,
        &token,
        &material.seed,
        &material.public_key,
        material.device_did.to_string(),
        Some(hostname()),
    )
    .map_err(|e| anyhow::anyhow!("Failed to create pairing response: {}", e))?;

    // Derive SAS from shared secret with transcript binding
    let initiator_x25519_pub = token
        .ephemeral_pubkey_bytes()
        .map_err(|e| anyhow::anyhow!("Invalid initiator pubkey: {}", e))?;
    let responder_x25519_pub = pairing_response
        .device_x25519_pubkey_bytes()
        .map_err(|e| anyhow::anyhow!("Invalid responder pubkey: {}", e))?;

    let sas_bytes = sas::derive_sas(
        &shared_secret,
        &initiator_x25519_pub,
        &responder_x25519_pub,
        &normalized,
    );
    let transport_key = sas::derive_transport_key(
        &shared_secret,
        &initiator_x25519_pub,
        &responder_x25519_pub,
        &normalized,
    );

    // Submit the response to the relay
    let submit_req = auths_core::pairing::types::SubmitResponseRequest {
        device_x25519_pubkey: Base64UrlEncoded::from_raw(
            pairing_response.device_x25519_pubkey.clone(),
        ),
        device_signing_pubkey: Base64UrlEncoded::from_raw(
            pairing_response.device_signing_pubkey.clone(),
        ),
        device_did: pairing_response.device_did.clone(),
        signature: Base64UrlEncoded::from_raw(pairing_response.signature.clone()),
        device_name: pairing_response.device_name.clone(),
    };

    relay
        .submit_response(registry, &session_data.session_id, &submit_req)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to submit response: {}", e))?;

    create_spinner.finish_with_message(format!("{CHECK}Response submitted"));

    // SAS verification ceremony
    let confirmed = prompt_sas_confirmation(&sas_bytes)?;
    if !confirmed {
        display_sas_mismatch_warning();
        drop(transport_key);
        anyhow::bail!("SAS verification failed — pairing aborted");
    }

    // Wait for encrypted attestation from initiator
    let wait_spinner = create_wait_spinner(&format!(
        "{GEAR}Waiting for initiator to confirm and send attestation..."
    ));

    let confirmation = relay
        .get_confirmation(registry, &session_data.session_id)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get confirmation: {}", e))?;

    if confirmation.aborted {
        wait_spinner.finish_and_clear();
        println!();
        println!(
            "  {}{}",
            WARN,
            style("The other device rejected the pairing.").red().bold()
        );
        println!("  {}", style("No attestation was created.").dim());
        println!();
        drop(transport_key);
        anyhow::bail!("Initiator rejected SAS — pairing aborted");
    }

    if let Some(encrypted) = confirmation.encrypted_attestation {
        let ciphertext = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &encrypted,
        )
        .context("Invalid base64 in encrypted attestation")?;

        let attestation_json =
            sas::decrypt_from_transport(&ciphertext, transport_key.as_bytes())
                .map_err(|e| anyhow::anyhow!("Failed to decrypt attestation: {}", e))?;

        wait_spinner.finish_with_message(format!("{CHECK}Attestation received and decrypted"));

        // Parse attestation from JSON
        let attestation: auths_verifier::core::Attestation =
            serde_json::from_slice(&attestation_json)
                .context("Failed to parse attestation JSON from pairing session")?;

        // TODO(fn-43.6): Full signature verification requires access to issuer's public key.
        // For now, trust the pairing channel and mark as verified.
        // TODO: Replace with full verify_with_resolver once we have a proper DID resolver for the identity.

        // Store attestation in local registry
        let verified =
            auths_verifier::core::VerifiedAttestation::dangerous_from_unchecked(attestation);
        ctx.attestation_sink
            .export(&verified)
            .context("Failed to store paired device attestation")?;
    } else {
        wait_spinner.finish_and_clear();
        println!();
        println!(
            "  {}{}",
            WARN,
            style("No attestation received from initiator.").yellow()
        );
        println!();
    }

    println!();
    println!(
        "{}",
        style(format!("━━━ {CHECK}Pairing Complete ━━━"))
            .green()
            .bold()
    );
    println!();

    Ok(())
}
