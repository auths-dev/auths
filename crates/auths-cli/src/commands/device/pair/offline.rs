//! Offline pairing mode — no registry server required (for testing).

use std::time::Duration;

use anyhow::{Context, Result};
use console::style;

use auths_core::pairing::{PairingToken, QrOptions, render_qr};

use super::common::*;

/// Initiate a pairing session without registry (for testing).
pub(crate) fn handle_initiate_offline(
    no_qr: bool,
    expiry_secs: u64,
    capabilities: &[String],
) -> Result<()> {
    // Try to load controller DID, fall back to placeholder
    let auths_dir = auths_core::paths::auths_home().unwrap_or_default();

    let controller_did = if auths_dir.exists() {
        let storage = auths_storage::git::RegistryIdentityStorage::new(auths_dir.clone());
        auths_sdk::pairing::load_controller_did(&storage)
            .unwrap_or_else(|_| "did:keri:offline-test".to_string())
    } else {
        "did:keri:offline-test".to_string()
    };

    let expiry = chrono::Duration::seconds(expiry_secs as i64);
    let session = PairingToken::generate_with_expiry(
        chrono::Utc::now(),
        controller_did.clone(),
        "offline".to_string(),
        capabilities.to_vec(),
        expiry,
    )
    .context("Failed to generate pairing token")?;

    print_pairing_header("OFFLINE", "offline", &controller_did);

    if !no_qr {
        let options = QrOptions::default();
        let qr = render_qr(&session.token, &options).context("Failed to render QR code")?;
        println!("{}", qr);
        println!();
    }

    let sc = &session.token.short_code;
    let formatted_code = format!("{}-{}", &sc[..3], &sc[3..]);

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
    println!("  {} {}", style("URI:").dim(), session.token.to_uri());
    println!();
    println!(
        "  {}{}",
        WARN,
        style("OFFLINE MODE — No registry connection.").yellow()
    );
    println!(
        "  {}",
        style("Mobile device must submit response directly or via another channel.").dim()
    );
    println!();
    println!("  {}", style("(Press Ctrl+C to cancel)").dim());
    println!();

    // In offline mode, just wait with countdown spinner
    let start = std::time::Instant::now();
    let expiry_duration = Duration::from_secs(expiry_secs);
    let spinner = create_wait_spinner(&format!("{PHONE}Waiting for device..."));

    loop {
        let elapsed = start.elapsed();
        if elapsed >= expiry_duration {
            spinner.finish_with_message(format!("{}", style("Session expired.").yellow()));
            return Ok(());
        }

        let remaining = expiry_duration - elapsed;
        spinner.set_message(format!(
            "{PHONE}Waiting for device... ({:02}:{:02})",
            remaining.as_secs() / 60,
            remaining.as_secs() % 60
        ));

        std::thread::sleep(Duration::from_secs(1));
    }
}
