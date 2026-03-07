//! LAN pairing mode — zero server required.
//!
//! Starts an ephemeral HTTP server on the local network. The mobile app
//! connects directly via the IP:port embedded in the QR code.

use std::time::Duration;

use anyhow::{Context, Result};
use console::style;

use auths_core::config::EnvironmentConfig;
use auths_core::pairing::types::CreateSessionRequest;
use auths_core::pairing::{PairingToken, QrOptions, render_qr};

use super::common::*;
use super::lan_server::{LanPairingServer, detect_lan_ip};
use super::mdns::PairingAdvertiser;

/// Initiate a LAN pairing session.
///
/// 1. Detect LAN IP
/// 2. Start ephemeral HTTP server
/// 3. Generate pairing token pointing at `http://LAN_IP:PORT`
/// 4. Optionally advertise via mDNS
/// 5. Display QR + short code
/// 6. Wait for response
/// 7. Verify + create attestation
pub async fn handle_initiate_lan(
    no_qr: bool,
    no_mdns: bool,
    expiry_secs: u64,
    capabilities: &[String],
    env_config: &EnvironmentConfig,
) -> Result<()> {
    let auths_dir = auths_core::paths::auths_home_with_config(env_config).unwrap_or_default();

    let identity_storage = auths_storage::git::RegistryIdentityStorage::new(auths_dir.clone());
    let controller_did = auths_sdk::pairing::load_controller_did(&identity_storage)
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    // Detect LAN IP
    let lan_ip =
        detect_lan_ip().context("Failed to detect LAN IP. Are you connected to a network?")?;

    let expiry = chrono::Duration::seconds(expiry_secs as i64);

    // Generate a session token with a placeholder endpoint — we'll update it after
    // the server starts and we know the actual port.
    let mut session = PairingToken::generate_with_expiry(
        chrono::Utc::now(),
        controller_did.clone(),
        "http://placeholder".to_string(), // replaced below
        capabilities.to_vec(),
        expiry,
    )
    .context("Failed to generate pairing token")?;

    let session_id = session.token.short_code.clone();

    // Build the CreateSessionRequest for the LAN server
    let request = CreateSessionRequest {
        session_id: session_id.clone(),
        controller_did: session.token.controller_did.clone(),
        ephemeral_pubkey: auths_core::pairing::types::Base64UrlEncoded::from_raw(
            session.token.ephemeral_pubkey.clone(),
        ),
        short_code: session.token.short_code.clone(),
        capabilities: session.token.capabilities.clone(),
        expires_at: session.token.expires_at.timestamp(),
    };

    // Start the LAN server bound to the detected LAN IP
    let server = LanPairingServer::start(request, lan_ip).await?;
    let port = server.addr().port();
    let endpoint = format!("http://{}:{}", lan_ip, port);

    // Update the token's endpoint to include the pairing token for auth
    session.token.endpoint = format!("{}?token={}", endpoint, server.pairing_token());

    // Self-test: verify the server is reachable from this machine
    let health_url = format!("{}/health", &endpoint);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .unwrap_or_default();
    match client.get(&health_url).send().await {
        Ok(resp) if resp.status().is_success() => {}
        _ => {
            let warning = format!(
                "LAN server started but self-test failed. Your Mac's firewall may be blocking port {}.",
                port
            );
            println!(
                "  {} {}",
                style("Warning:").yellow().bold(),
                style(&warning).yellow()
            );
            println!(
                "  {} Try: {}",
                style("→").yellow(),
                style("sudo pfctl -d").bold()
            );
            println!();
        }
    }

    print_pairing_header("LAN", &endpoint, &controller_did);

    // Optionally start mDNS advertisement
    let _advertiser = if !no_mdns {
        match PairingAdvertiser::advertise(port, &session.token.short_code, &controller_did) {
            Ok(adv) => {
                println!(
                    "  {} {}",
                    style("mDNS:").dim(),
                    style("advertising on local network").green()
                );
                Some(adv)
            }
            Err(e) => {
                println!("  {} {} {}", WARN, style("mDNS unavailable:").yellow(), e);
                None
            }
        }
    } else {
        None
    };

    // Display QR code
    if !no_qr {
        println!();
        let options = QrOptions::default();
        let qr = render_qr(&session.token, &options).context("Failed to render QR code")?;
        println!("{}", qr);
    }

    // Display short code
    let sc = &session.token.short_code;
    let formatted_code = format!("{}-{}", &sc[..3], &sc[3..]);

    println!();
    println!("  Scan the QR code above, or enter this code manually:");
    println!();
    println!("    {}", style(&formatted_code).bold().cyan());
    println!();
    if !capabilities.is_empty() {
        println!(
            "  {} {}",
            style("Capabilities:").dim(),
            capabilities.join(", ")
        );
    }
    println!(
        "  {} {} ({}s remaining)",
        style("Expires:").dim(),
        session.token.expires_at.format("%H:%M:%S"),
        expiry_secs
    );
    println!();
    println!("  {}", style("(Press Ctrl+C to cancel)").dim());
    println!();
    println!(
        "  {} Test from another terminal: {}",
        style("Debug:").dim(),
        style(format!("curl {}/health", &endpoint)).dim()
    );
    println!();

    // Wait for response
    let wait_spinner = create_wait_spinner(&format!("{PHONE}Waiting for device on LAN..."));

    let expiry_duration = Duration::from_secs(expiry_secs);
    match server.wait_for_response(expiry_duration).await {
        Ok(response_data) => {
            wait_spinner.finish_with_message(format!("{CHECK}Response received!"));

            // Shut down mDNS
            if let Some(adv) = _advertiser {
                adv.shutdown();
            }

            handle_pairing_response(
                &mut session,
                response_data,
                &auths_dir,
                capabilities,
                env_config,
            )?;
        }
        Err(auths_core::pairing::PairingError::LanTimeout) => {
            wait_spinner.finish_with_message(format!("{}", style("Session expired.").yellow()));
            if let Some(adv) = _advertiser {
                adv.shutdown();
            }
        }
        Err(e) => {
            wait_spinner.finish_and_clear();
            if let Some(adv) = _advertiser {
                adv.shutdown();
            }
            return Err(anyhow::anyhow!("LAN pairing failed: {}", e));
        }
    }

    Ok(())
}

/// Join a LAN pairing session by discovering it via mDNS.
pub async fn handle_join_lan(code: &str, env_config: &EnvironmentConfig) -> Result<()> {
    use auths_core::pairing::normalize_short_code;

    let normalized = normalize_short_code(code);
    if normalized.len() != 6 {
        anyhow::bail!(
            "Short code must be exactly 6 characters (got {})",
            normalized.len()
        );
    }

    let formatted = format!("{}-{}", &normalized[..3], &normalized[3..]);

    println!();
    println!(
        "{}",
        style(format!("━━━ {LINK}Discovering LAN Peer ━━━")).bold()
    );
    println!();
    println!(
        "  {} {}",
        style("Code:").dim(),
        style(&formatted).bold().cyan()
    );
    println!();

    let discover_spinner = create_wait_spinner(&format!("{GEAR}Searching for peer via mDNS..."));

    // Discover the LAN server via mDNS (30 second timeout)
    let addr = super::mdns::PairingDiscoverer::discover(&normalized, Duration::from_secs(30))
        .map_err(|e| anyhow::anyhow!("mDNS discovery failed: {}", e))?;

    discover_spinner.finish_with_message(format!("{CHECK}Found peer at {}", style(addr).cyan()));

    let registry = format!("http://{}", addr);

    // Delegate to the standard join flow
    super::join::handle_join(&normalized, &registry, env_config).await
}
