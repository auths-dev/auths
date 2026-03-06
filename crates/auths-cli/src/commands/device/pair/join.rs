//! Join mode — join an existing pairing session via short code.

use anyhow::{Context, Result, anyhow};
use auths_crypto::SecureSeed;
use auths_infra_http::HttpPairingRelayClient;
use auths_sdk::pairing::{DeviceSigningMaterial, PairingCompletionResult, join_pairing_session};
use auths_verifier::types::DeviceDID;
use chrono::Utc;
use console::style;

use super::common::*;

/// Join an existing pairing session using a short code.
pub(crate) async fn handle_join(code: &str, registry: &str) -> Result<()> {
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

    let auths_dir = dirs::home_dir()
        .map(|h| h.join(".auths"))
        .unwrap_or_default();

    if !auths_dir.exists() {
        anyhow::bail!("No local identity found. Run 'auths init' first.");
    }

    // Load device keypair from keychain
    use auths_core::crypto::signer::decrypt_keypair;
    use auths_core::storage::keychain::get_platform_keychain;
    use auths_id::identity::helpers::ManagedIdentity;
    use auths_id::storage::identity::IdentityStorage;
    use auths_storage::git::RegistryIdentityStorage;

    let key_spinner = create_wait_spinner(&format!("{GEAR}Loading local device key..."));

    let identity_storage = RegistryIdentityStorage::new(auths_dir.clone());
    let managed: ManagedIdentity = identity_storage
        .load_identity()
        .context("Failed to load identity")?;

    let key_storage = get_platform_keychain()?;

    let aliases = key_storage
        .list_aliases_for_identity(&managed.controller_did)
        .context("Failed to list key aliases")?;
    let key_alias = aliases
        .into_iter()
        .find(|a| !a.contains("--next-"))
        .ok_or_else(|| {
            anyhow!(
                "No signing key found for identity {}",
                managed.controller_did
            )
        })?;

    let (_controller_did, encrypted_key) = key_storage
        .load_key(&key_alias)
        .context("Failed to load device key from keychain")?;

    let passphrase =
        rpassword::prompt_password(format!("Enter passphrase for key '{}': ", key_alias))
            .context("Failed to read passphrase")?;

    let pkcs8_bytes =
        decrypt_keypair(&encrypted_key, &passphrase).context("Failed to decrypt key")?;

    let (device_seed, device_pubkey_32) = auths_crypto::parse_ed25519_key_material(&pkcs8_bytes)
        .map_err(|e| anyhow!("Failed to parse key data: {e}"))
        .and_then(|(seed, maybe_pk)| {
            let pk = maybe_pk.ok_or_else(|| {
                anyhow!("Key format does not include public key; expected PKCS#8 v2")
            })?;
            Ok((seed, pk))
        })
        .or_else(|_| -> Result<_> {
            let seed = auths_crypto::parse_ed25519_seed(&pkcs8_bytes)
                .map_err(|e| anyhow!("Cannot parse key data: {e}"))?;
            let pk = auths_core::crypto::provider_bridge::ed25519_public_key_from_seed_sync(&seed)
                .map_err(|e| anyhow!("Failed to derive public key: {e}"))?;
            Ok((seed, pk))
        })?;

    // Wrap seed in SecureSeed for the SDK
    let secure_seed = SecureSeed::new(*device_seed.as_bytes());

    let device_did = DeviceDID::from_ed25519(&device_pubkey_32);

    key_spinner.finish_with_message(format!("{CHECK}Device key loaded"));

    println!(
        "  {} {}",
        style("Device DID:").dim(),
        style(&device_did).dim()
    );
    println!();

    let material = DeviceSigningMaterial {
        seed: secure_seed,
        public_key: device_pubkey_32,
        device_did,
        controller_did: managed.controller_did.to_string(),
    };

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
