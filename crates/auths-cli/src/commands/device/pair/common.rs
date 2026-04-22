//! Shared helpers for pairing commands.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use console::{Emoji, style};
use indicatif::{ProgressBar, ProgressStyle};

use auths_sdk::core_config::EnvironmentConfig;
use auths_sdk::pairing::PairingSession;
use auths_sdk::pairing::SubmitResponseRequest;
use auths_sdk::signing::PassphraseProvider;

use crate::core::fs::{create_restricted_dir, write_sensitive_file};

// `CliPassphraseProvider` / `PrefilledPassphraseProvider` are no longer
// needed here — the caller threads in the CLI's pre-wrapped
// `KeychainPassphraseProvider`.

// Emoji with plain-text fallbacks for non-emoji terminals.
pub(crate) static LOCK: Emoji<'_, '_> = Emoji("🔐 ", "");
pub(crate) static LINK: Emoji<'_, '_> = Emoji("🔗 ", "");
pub(crate) static CHECK: Emoji<'_, '_> = Emoji("✅ ", "[OK] ");
pub(crate) static PHONE: Emoji<'_, '_> = Emoji("📱 ", "");
pub(crate) static GEAR: Emoji<'_, '_> = Emoji("⚙️  ", "");
pub(crate) static WARN: Emoji<'_, '_> = Emoji("⚠️  ", "[!] ");

/// Create a braille-style wait spinner.
pub(crate) fn create_wait_spinner(message: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    #[allow(clippy::unwrap_used)] // INVARIANT: template is a compile-time constant
    pb.set_style(
        ProgressStyle::with_template("{spinner:.cyan} {msg}")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
    pb.set_message(message.to_string());
    pb.enable_steady_tick(Duration::from_millis(80));
    pb
}

/// Print a styled pairing header with identity/registry info.
pub(crate) fn print_pairing_header(mode: &str, registry: &str, controller_did: &str) {
    println!();
    println!(
        "{}",
        style(format!("━━━ {LOCK}Auths Device Pairing ({mode}) ━━━")).bold()
    );
    println!();
    println!("  {} {}", style("Registry:").dim(), style(registry).cyan());
    println!(
        "  {} {}",
        style("Identity:").dim(),
        style(controller_did).cyan()
    );
    println!();
}

/// Print a styled completion footer with device info.
///
/// One-line format matching the Signal/WhatsApp "device linked" UX:
/// `✅ Paired with <device name> (<DID>)`.
pub(crate) fn print_completion(device_name: Option<&str>, device_did: &str) {
    println!();
    let label = device_name.unwrap_or("new device");
    println!(
        "{}Paired with {} {}",
        CHECK,
        style(label).bold(),
        style(format!("({device_did})")).dim()
    );
    println!();
}

/// Print a styled completion footer for a device-key rotation.
pub(crate) fn print_rotation_completion(device_name: Option<&str>, device_did: &str) {
    println!();
    let label = device_name.unwrap_or("device");
    println!(
        "{}Rotated signing key for {} {}",
        CHECK,
        style(label).bold(),
        style(format!("({device_did})")).dim()
    );
    println!();
}

/// Display SAS and prompt for explicit Y/N confirmation (no default).
///
/// Returns `true` if the user confirms the SAS matches, `false` on rejection.
pub(crate) fn prompt_sas_confirmation(sas_bytes: &[u8; 10]) -> Result<bool> {
    use auths_pairing_protocol::sas;

    println!();
    println!("{}", style(format!("━━━ {LOCK}Verify Pairing ━━━")).bold());
    println!();
    println!("  Confirm this code matches your other device:");
    println!();
    println!("    {}", style(sas::format_sas_emoji(sas_bytes)).bold());
    println!(
        "    {}",
        style(format!("({})", sas::format_sas_numeric(sas_bytes))).dim()
    );
    println!();
    println!(
        "  {}",
        style("If the codes don't match, someone may be intercepting this connection.").dim()
    );
    println!();

    let confirmed = dialoguer::Confirm::new()
        .with_prompt("Do the codes match? [y/N]")
        .default(false)
        .interact()
        .context("Failed to read confirmation")?;

    Ok(confirmed)
}

/// Display a warning when SAS verification fails.
pub(crate) fn display_sas_mismatch_warning() {
    println!();
    println!(
        "  {}{}",
        WARN,
        style("PAIRING ABORTED — possible interception detected")
            .red()
            .bold()
    );
    println!();
    println!("  The verification codes did not match. This could mean:");
    println!("    • An attacker is intercepting the connection (MITM)");
    println!("    • A network issue corrupted the key exchange");
    println!();
    println!("  Retry on a trusted network. If this persists, do not pair these devices.");
    println!("  No keys or attestations were created.");
    println!();
}

/// Handle a successful pairing response — verify signature, complete ECDH, create attestation.
///
/// When `verify_sas` is false (default for `auths pair`), the SAS is
/// printed for the user's reference but no Y/N prompt blocks the
/// flow — this matches the Signal/WhatsApp initial-pair experience
/// where the QR itself is the out-of-band channel. Pass `verify_sas:
/// true` to restore the interactive confirmation (via `auths pair
/// --verify`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_pairing_response(
    now: chrono::DateTime<chrono::Utc>,
    session: &mut PairingSession,
    response: SubmitResponseRequest,
    auths_dir: &Path,
    capabilities: &[String],
    passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync>,
    env_config: &EnvironmentConfig,
    verify_sas: bool,
) -> Result<()> {
    use auths_sdk::keychain::get_platform_keychain_with_config;
    use auths_sdk::pairing::{self, DecryptedPairingResponse, PairingCompletionResult};

    println!();
    println!(
        "{}",
        style(format!("━━━ {LINK}Response Received ━━━"))
            .bold()
            .cyan()
    );
    println!();

    if let Some(name) = &response.device_name {
        println!(
            "  {} {}",
            style(format!("{PHONE}Device:")).dim(),
            style(name).bold()
        );
    }
    println!(
        "  {} {}",
        style("DID:").dim(),
        style(&response.device_did).dim()
    );
    println!();

    // Decode response fields
    let device_ecdh_bytes = response
        .device_ephemeral_pubkey
        .decode()
        .context("Invalid ephemeral pubkey encoding")?;

    let device_signing_bytes = response
        .device_signing_pubkey
        .decode()
        .context("Invalid signing pubkey encoding")?;

    let signature_bytes = response
        .signature
        .decode()
        .context("Invalid signature encoding")?;

    // Verify signature binding; curve is carried in-band on the response.
    let verify_spinner = create_wait_spinner(&format!("{GEAR}Verifying signature..."));
    let curve: auths_crypto::CurveType = response.curve.into();
    session
        .verify_response(
            &device_signing_bytes,
            &device_ecdh_bytes,
            &signature_bytes,
            curve,
        )
        .context("Signature verification failed")?;
    verify_spinner.finish_with_message(format!("{CHECK}Signature verified"));

    // Complete ECDH key exchange
    let exchange_spinner = create_wait_spinner(&format!("{GEAR}Completing key exchange..."));
    let initiator_ecdh_pub = session
        .ephemeral_pubkey_bytes()
        .context("Failed to get initiator pubkey")?;
    let shared_secret = session
        .complete_exchange(&device_ecdh_bytes)
        .context("ECDH key exchange failed")?;
    exchange_spinner.finish_with_message(format!("{CHECK}Key exchange complete"));

    // Derive SAS with transcript binding
    let session_id = &session.token.session_id;
    let short_code = &session.token.short_code;
    let sas_bytes = auths_pairing_protocol::sas::derive_sas(
        &shared_secret,
        &initiator_ecdh_pub,
        &device_ecdh_bytes,
        session_id,
        short_code,
    );
    let transport_key = auths_pairing_protocol::sas::derive_transport_key(
        &shared_secret,
        &initiator_ecdh_pub,
        &device_ecdh_bytes,
        session_id,
        short_code,
    );

    // SAS display. Default path (matching Signal/WhatsApp initial-pair
    // UX): print the SAS for the user's reference and continue — the
    // QR scan is the authenticated out-of-band channel. Users who want
    // the interactive check opt in via `auths pair --verify`.
    if verify_sas {
        let confirmed = prompt_sas_confirmation(&sas_bytes)?;
        if !confirmed {
            display_sas_mismatch_warning();
            drop(transport_key);
            anyhow::bail!("SAS verification failed — pairing aborted");
        }
    } else {
        use auths_pairing_protocol::sas;
        println!(
            "  {} {}  {}",
            style("SAS:").dim(),
            sas::format_sas_emoji(&sas_bytes),
            style(format!("({})", sas::format_sas_numeric(&sas_bytes))).dim()
        );
    }

    if !auths_dir.exists() {
        println!();
        println!(
            "  {}{}",
            WARN,
            style("No local identity found at ~/.auths").yellow()
        );
        println!("  Run 'auths init' first to create an identity.");
        save_device_info(now, auths_dir, &response)?;
        return Ok(());
    }

    // Resolve identity key alias and collect passphrase before spinner
    use auths_sdk::attestation::AttestationSink;
    use auths_sdk::ports::IdentityStorage;
    use auths_sdk::storage::{RegistryAttestationStorage, RegistryIdentityStorage};
    let identity_store = Arc::new(RegistryIdentityStorage::new(auths_dir.to_path_buf()));
    let controller_did = pairing::load_controller_did(identity_store.as_ref())
        .map_err(anyhow::Error::from)
        .context("Failed to load identity from ~/.auths")?;

    println!(
        "  {} {}",
        style("Identity:").dim(),
        style(&controller_did).cyan(),
    );

    let keychain = get_platform_keychain_with_config(env_config)?;
    #[allow(clippy::disallowed_methods)] // INVARIANT: controller_did from managed identity
    let controller_identity_did =
        auths_sdk::keychain::IdentityDID::new_unchecked(controller_did.clone());
    let aliases = keychain
        .list_aliases_for_identity(&controller_identity_did)
        .context("Failed to list key aliases")?;
    let identity_key_alias = aliases
        .into_iter()
        .find(|a| !a.contains("--next-"))
        .ok_or_else(|| anyhow!("No signing key found for identity {}", controller_did))?;

    // `passphrase_provider` is the CLI-level provider configured by
    // `factories::load_cli_config` — already wrapped with
    // `KeychainPassphraseProvider` per user config, so first invocation
    // prompts + caches and subsequent invocations surface Touch ID
    // (or the user's configured policy) without re-prompting.
    let key_storage: Arc<dyn auths_sdk::keychain::KeyStorage + Send + Sync> = Arc::from(keychain);

    let attest_spinner = create_wait_spinner(&format!("{GEAR}Creating device attestation..."));

    let decrypted = DecryptedPairingResponse {
        auths_dir: auths_dir.to_path_buf(),
        device_pubkey: device_signing_bytes,
        curve,
        #[allow(clippy::disallowed_methods)] // INVARIANT: device_did from pairing protocol response
        device_did: auths_verifier::types::DeviceDID::new_unchecked(response.device_did.to_string()),
        device_name: response.device_name.clone(),
        capabilities: capabilities.to_vec(),
        identity_key_alias,
    };

    let attest_store = Arc::new(RegistryAttestationStorage::new(auths_dir));
    let attestation_sink: Arc<dyn AttestationSink + Send + Sync> =
        Arc::clone(&attest_store) as Arc<dyn AttestationSink + Send + Sync>;
    let identity_storage: Arc<dyn IdentityStorage + Send + Sync> = identity_store;

    match pairing::complete_pairing_from_response(
        decrypted,
        identity_storage,
        attestation_sink,
        key_storage,
        passphrase_provider,
        &auths_sdk::ports::SystemClock,
    )
    .map_err(anyhow::Error::from)
    .context("Pairing completion failed")?
    {
        PairingCompletionResult::Success {
            device_did,
            device_name,
        } => {
            attest_spinner.finish_with_message(format!("{CHECK}Device attestation created"));
            print_completion(device_name.as_deref(), &device_did);
        }
        PairingCompletionResult::Fallback {
            device_did,
            device_name: _,
            error,
        } => {
            attest_spinner.finish_and_clear();
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
            save_device_info(now, auths_dir, &response)?;
        }
    }

    Ok(())
}

/// Save device info as a JSON file (fallback when attestation creation fails).
pub(crate) fn save_device_info(
    now: chrono::DateTime<chrono::Utc>,
    auths_dir: &Path,
    response: &SubmitResponseRequest,
) -> Result<()> {
    let devices_dir = auths_dir.join("devices");
    create_restricted_dir(&devices_dir)?;

    let device_file = devices_dir.join(format!(
        "{}.json",
        &response.device_signing_pubkey[..8.min(response.device_signing_pubkey.len())]
    ));
    let device_info = serde_json::json!({
        "device_did": response.device_did.as_str(),
        "signing_pubkey": response.device_signing_pubkey.as_str(),
        "x25519_pubkey": response.device_ephemeral_pubkey.as_str(),
        "name": response.device_name,
        "paired_at": now.to_rfc3339(),
    });

    write_sensitive_file(&device_file, serde_json::to_string_pretty(&device_info)?)?;
    println!(
        "  {}{}",
        CHECK,
        style(format!("Device info saved to: {}", device_file.display())).dim()
    );

    Ok(())
}

/// Get the hostname of this machine for device naming.
#[allow(clippy::disallowed_methods)] // CLI boundary: hostname from env
pub(crate) fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("HOST"))
        .unwrap_or_else(|_| "unknown-device".to_string())
}
