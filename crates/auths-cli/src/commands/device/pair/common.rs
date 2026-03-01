//! Shared helpers for pairing commands.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use console::{Emoji, style};
use indicatif::{ProgressBar, ProgressStyle};

use auths_core::config::EnvironmentConfig;
use auths_core::pairing::PairingSession;
use auths_core::pairing::types::SubmitResponseRequest;
use auths_core::signing::PassphraseProvider;

use crate::core::provider::{CliPassphraseProvider, PrefilledPassphraseProvider};

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
pub(crate) fn print_completion(device_name: Option<&str>, device_did: &str) {
    println!();
    println!(
        "{}",
        style(format!("━━━ {CHECK}Pairing Complete ━━━"))
            .green()
            .bold()
    );
    println!();
    if let Some(name) = device_name {
        println!("  {} {}", style("Device:").dim(), style(name).bold());
    }
    println!("  {} {}", style("DID:").dim(), style(device_did).dim());
    println!();
}

/// Handle a successful pairing response — verify signature, complete ECDH, create attestation.
pub(crate) fn handle_pairing_response(
    session: &mut PairingSession,
    response: SubmitResponseRequest,
    auths_dir: &Path,
    capabilities: &[String],
    env_config: &EnvironmentConfig,
) -> Result<()> {
    use auths_core::storage::keychain::get_platform_keychain_with_config;
    use auths_sdk::pairing::{self, DecryptedPairingResponse, PairingCompletionResult};
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

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
    let device_x25519_bytes: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&response.device_x25519_pubkey)
        .context("Invalid X25519 pubkey encoding")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid X25519 pubkey length"))?;

    let device_signing_bytes = URL_SAFE_NO_PAD
        .decode(&response.device_signing_pubkey)
        .context("Invalid Ed25519 pubkey encoding")?;

    let signature_bytes = URL_SAFE_NO_PAD
        .decode(&response.signature)
        .context("Invalid signature encoding")?;

    // Verify Ed25519 signature binding
    let verify_spinner = create_wait_spinner(&format!("{GEAR}Verifying signature..."));
    session
        .verify_response(
            &device_signing_bytes,
            &device_x25519_bytes,
            &signature_bytes,
        )
        .context("Signature verification failed")?;
    verify_spinner.finish_with_message(format!("{CHECK}Signature verified"));

    // Complete ECDH key exchange
    let exchange_spinner = create_wait_spinner(&format!("{GEAR}Completing key exchange..."));
    let _shared_secret = session
        .complete_exchange(&device_x25519_bytes)
        .context("ECDH key exchange failed")?;
    exchange_spinner.finish_with_message(format!("{CHECK}Key exchange complete"));

    if !auths_dir.exists() {
        println!();
        println!(
            "  {}{}",
            WARN,
            style("No local identity found at ~/.auths").yellow()
        );
        println!("  Run 'auths init' first to create an identity.");
        save_device_info(auths_dir, &response)?;
        return Ok(());
    }

    // Resolve identity key alias and collect passphrase before spinner
    use auths_id::attestation::export::AttestationSink;
    use auths_id::storage::identity::IdentityStorage;
    use auths_storage::git::{RegistryAttestationStorage, RegistryIdentityStorage};
    let identity_store = Arc::new(RegistryIdentityStorage::new(auths_dir.to_path_buf()));
    let controller_did = pairing::load_controller_did(identity_store.as_ref())
        .map_err(|e| anyhow::anyhow!("{}", e))
        .context("Failed to load identity from ~/.auths")?;

    println!(
        "  {} {}",
        style("Identity:").dim(),
        style(&controller_did).cyan(),
    );

    let keychain = get_platform_keychain_with_config(env_config)?;
    let controller_identity_did =
        auths_core::storage::keychain::IdentityDID::new_unchecked(controller_did.clone());
    let aliases = keychain
        .list_aliases_for_identity(&controller_identity_did)
        .context("Failed to list key aliases")?;
    let identity_key_alias = aliases
        .into_iter()
        .find(|a| !a.contains("--next-"))
        .ok_or_else(|| anyhow!("No signing key found for identity {}", controller_did))?;

    let cli_provider = CliPassphraseProvider::new();
    let passphrase = cli_provider
        .get_passphrase(&format!(
            "Enter passphrase for key '{}' to sign:",
            identity_key_alias
        ))
        .context("Failed to get passphrase")?;
    let passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync> =
        Arc::new(PrefilledPassphraseProvider::new(passphrase));
    let key_storage: Arc<dyn auths_core::storage::keychain::KeyStorage + Send + Sync> =
        Arc::from(keychain);

    let attest_spinner = create_wait_spinner(&format!("{GEAR}Creating device attestation..."));

    let decrypted = DecryptedPairingResponse {
        auths_dir: auths_dir.to_path_buf(),
        device_pubkey: device_signing_bytes,
        device_did: response.device_did.clone(),
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
        &auths_core::ports::clock::SystemClock,
    )
    .map_err(|e| anyhow::anyhow!("{}", e))
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
                style(format!("auths device link --device-did {} ...", device_did)).dim()
            );
            save_device_info(auths_dir, &response)?;
        }
    }

    Ok(())
}

/// Save device info as a JSON file (fallback when attestation creation fails).
pub(crate) fn save_device_info(auths_dir: &Path, response: &SubmitResponseRequest) -> Result<()> {
    let devices_dir = auths_dir.join("devices");
    std::fs::create_dir_all(&devices_dir)?;

    let device_file = devices_dir.join(format!(
        "{}.json",
        &response.device_signing_pubkey[..8.min(response.device_signing_pubkey.len())]
    ));
    let device_info = serde_json::json!({
        "device_did": response.device_did,
        "signing_pubkey": response.device_signing_pubkey,
        "x25519_pubkey": response.device_x25519_pubkey,
        "name": response.device_name,
        "paired_at": chrono::Utc::now().to_rfc3339(),
    });

    std::fs::write(&device_file, serde_json::to_string_pretty(&device_info)?)?;
    println!(
        "  {}{}",
        CHECK,
        style(format!("Device info saved to: {}", device_file.display())).dim()
    );

    Ok(())
}

/// Get the hostname of this machine for device naming.
pub(crate) fn hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("HOST"))
        .unwrap_or_else(|_| "unknown-device".to_string())
}
