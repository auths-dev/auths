//! Join mode — join an existing pairing session via short code.

use anyhow::{Context, Result, anyhow};
use console::style;
use serde::Serialize;

use auths_core::pairing::PairingToken;
use auths_core::pairing::types::GetSessionResponse;

use super::common::*;

/// Join an existing pairing session using a short code.
pub(crate) async fn handle_join(code: &str, registry: &str) -> Result<()> {
    // Validate and normalize the code via SDK
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

    // Lookup session by short code
    let client = reqwest::Client::new();
    let lookup_url = format!(
        "{}/v1/pairing/sessions/by-code/{}",
        registry.trim_end_matches('/'),
        normalized
    );

    let lookup_spinner = create_wait_spinner(&format!("{GEAR}Looking up session..."));

    let response = client
        .get(&lookup_url)
        .send()
        .await
        .context("Failed to connect to registry server")?;

    if !response.status().is_success() {
        lookup_spinner.finish_and_clear();
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if status.as_u16() == 404 {
            anyhow::bail!("Short code not found. It may have expired or been cancelled.");
        }
        anyhow::bail!("Registry error ({}): {}", status, body);
    }

    let session_data: GetSessionResponse = response
        .json()
        .await
        .context("Failed to parse session data")?;

    lookup_spinner.finish_with_message(format!("{CHECK}Session found"));

    // Check session status via SDK
    auths_sdk::pairing::verify_session_status(&session_data.status)
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    // Parse the token data to get initiator's X25519 pubkey
    let token_data = session_data
        .token
        .ok_or_else(|| anyhow::anyhow!("Session has no token data"))?;

    let initiator_pubkey = token_data.ephemeral_pubkey.to_string();
    let controller_did = token_data.controller_did.clone();

    println!();
    println!(
        "  {} {}",
        style("Controller:").dim(),
        style(&controller_did).cyan()
    );
    println!(
        "  {} {}",
        style("Session:").dim(),
        style(&session_data.session_id).dim()
    );
    println!();

    // Load local device signing key
    let key_spinner = create_wait_spinner(&format!("{GEAR}Loading local device key..."));

    let auths_dir = dirs::home_dir()
        .map(|h| h.join(".auths"))
        .unwrap_or_default();

    if !auths_dir.exists() {
        anyhow::bail!("No local identity found. Run 'auths init' first.");
    }

    // Build a PairingToken from the session data for creating a response
    let token_for_response = PairingToken {
        controller_did: controller_did.clone(),
        endpoint: registry.to_string(),
        short_code: normalized.clone(),
        ephemeral_pubkey: initiator_pubkey,
        expires_at: chrono::DateTime::from_timestamp(token_data.expires_at, 0)
            .unwrap_or_else(chrono::Utc::now),
        capabilities: token_data.capabilities.clone(),
    };

    if token_for_response.is_expired(chrono::Utc::now()) {
        anyhow::bail!("Pairing session has expired.");
    }

    // Load device keypair from keychain
    use auths_core::crypto::signer::decrypt_keypair;
    use auths_core::storage::keychain::get_platform_keychain;
    use auths_id::identity::helpers::ManagedIdentity;
    use auths_id::storage::identity::IdentityStorage;
    use auths_storage::git::RegistryIdentityStorage;
    use auths_verifier::types::DeviceDID;

    let identity_storage = RegistryIdentityStorage::new(auths_dir.clone());
    let managed: ManagedIdentity = identity_storage
        .load_identity()
        .context("Failed to load identity")?;

    let key_storage = get_platform_keychain()?;

    // Look up the key alias dynamically from the identity's controller DID
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
            // Fallback: extract seed, derive pubkey via CryptoProvider
            let seed = auths_crypto::parse_ed25519_seed(&pkcs8_bytes)
                .map_err(|e| anyhow!("Cannot parse key data: {e}"))?;
            let pk = auths_core::crypto::provider_bridge::ed25519_public_key_from_seed_sync(&seed)
                .map_err(|e| anyhow!("Failed to derive public key: {e}"))?;
            Ok((seed, pk))
        })?;

    key_spinner.finish_with_message(format!("{CHECK}Device key loaded"));

    // Derive device DID
    let device_did = DeviceDID::from_ed25519(&device_pubkey_32);

    println!(
        "  {} {}",
        style("Device DID:").dim(),
        style(&device_did).dim()
    );
    println!();

    // Create PairingResponse (includes ECDH)
    let create_spinner = create_wait_spinner(&format!("{GEAR}Creating pairing response..."));

    let (pairing_response, _shared_secret) = auths_core::pairing::PairingResponse::create(
        chrono::Utc::now(),
        &token_for_response,
        &device_seed,
        &device_pubkey_32,
        device_did.to_string(),
        Some(hostname()),
    )
    .context("Failed to create pairing response")?;

    create_spinner.finish_with_message(format!("{CHECK}Response created"));

    // Submit response to registry
    let submit_spinner = create_wait_spinner(&format!("{GEAR}Submitting response..."));

    let submit_url = format!(
        "{}/v1/pairing/sessions/{}/response",
        registry.trim_end_matches('/'),
        session_data.session_id
    );

    #[derive(Serialize)]
    struct SubmitRequest {
        device_x25519_pubkey: String,
        device_signing_pubkey: String,
        device_did: String,
        signature: String,
        device_name: Option<String>,
    }

    let submit_req = SubmitRequest {
        device_x25519_pubkey: pairing_response.device_x25519_pubkey,
        device_signing_pubkey: pairing_response.device_signing_pubkey,
        device_did: pairing_response.device_did,
        signature: pairing_response.signature,
        device_name: pairing_response.device_name,
    };

    let resp = client
        .post(&submit_url)
        .json(&submit_req)
        .send()
        .await
        .context("Failed to submit response")?;

    if !resp.status().is_success() {
        submit_spinner.finish_and_clear();
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Failed to submit response ({}): {}", status, body);
    }

    submit_spinner.finish_with_message(format!("{CHECK}Response submitted"));

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
