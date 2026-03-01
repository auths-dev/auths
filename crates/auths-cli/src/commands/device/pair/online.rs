//! Online pairing mode — uses a registry relay server.

use std::time::Duration;

use anyhow::{Context, Result};
use console::style;
use indicatif::ProgressBar;

use auths_core::config::EnvironmentConfig;
use auths_core::pairing::types::{CreateSessionResponse, GetSessionResponse, SessionStatus};
use auths_core::pairing::{QrOptions, render_qr};
use auths_sdk::pairing::{PairingSessionParams, build_pairing_session_request};

use super::common::*;

/// Polling interval when waiting for responses.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Initiate a pairing session using the registry relay.
pub(crate) async fn handle_initiate_online(
    client: &reqwest::Client,
    registry: &str,
    no_qr: bool,
    expiry_secs: u64,
    capabilities: &[String],
    env_config: &EnvironmentConfig,
) -> Result<()> {
    let auths_dir = auths_core::paths::auths_home_with_config(env_config).unwrap_or_default();

    let identity_storage = auths_storage::git::RegistryIdentityStorage::new(auths_dir.clone());
    let controller_did = auths_sdk::pairing::load_controller_did(&identity_storage)
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    let session_params = PairingSessionParams {
        controller_did: controller_did.clone(),
        registry: registry.to_string(),
        capabilities: capabilities.to_vec(),
        expiry_secs,
    };
    let session_req = build_pairing_session_request(chrono::Utc::now(), session_params)
        .map_err(|e| anyhow::anyhow!("{}", e))
        .context("Failed to generate pairing session")?;
    let mut session = session_req.session;
    let request = session_req.create_request;
    let session_id = request.session_id.clone();

    print_pairing_header("ONLINE", registry, &controller_did);

    let base_url = format!("{}/v1/pairing/sessions", registry.trim_end_matches('/'));

    let spinner = create_wait_spinner(&format!("{GEAR}Registering session..."));

    let response = client
        .post(&base_url)
        .json(&request)
        .send()
        .await
        .context("Failed to connect to registry server")?;

    if !response.status().is_success() {
        spinner.finish_and_clear();
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Registry error ({}): {}", status, body);
    }

    let created: CreateSessionResponse = response
        .json()
        .await
        .context("Failed to parse registry response")?;

    spinner.finish_with_message(format!("{CHECK}Session registered"));

    // Display QR code
    if !no_qr {
        println!();
        let options = QrOptions::default();
        let qr = render_qr(&session.token, &options).context("Failed to render QR code")?;
        println!("{}", qr);
    }

    // Display short code (formatted with dash for readability)
    let sc = &created.short_code;
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
        created.ttl_seconds
    );
    println!();
    println!("  {}", style("(Press Ctrl+C to cancel)").dim());
    println!();

    // Wait for response via WebSocket (with polling fallback)
    let session_url = format!("{}/{}", base_url, session_id);
    let expiry_duration = Duration::from_secs(expiry_secs);

    let wait_spinner = create_wait_spinner(&format!("{PHONE}Waiting for device..."));

    let result = wait_for_response(
        client,
        registry,
        &session_id,
        &session_url,
        expiry_duration,
        Some(&wait_spinner),
    )
    .await?;

    match result {
        Some(status) => match status.status {
            SessionStatus::Responded => {
                wait_spinner.finish_with_message(format!("{CHECK}Response received!"));
                if let Some(response_data) = status.response {
                    handle_pairing_response(
                        &mut session,
                        response_data,
                        &auths_dir,
                        capabilities,
                        env_config,
                    )?;
                }
            }
            SessionStatus::Cancelled => {
                wait_spinner
                    .finish_with_message(format!("{}", style("Session cancelled.").yellow()));
            }
            SessionStatus::Expired => {
                wait_spinner.finish_with_message(format!("{}", style("Session expired.").yellow()));
            }
            other => {
                wait_spinner.finish_with_message(format!("Session ended (status: {:?}).", other));
            }
        },
        None => {
            wait_spinner.finish_with_message(format!("{}", style("Session expired.").yellow()));
        }
    }

    Ok(())
}

/// Wait for a session response, trying WebSocket first with polling fallback.
pub(crate) async fn wait_for_response(
    client: &reqwest::Client,
    registry: &str,
    session_id: &str,
    session_url: &str,
    expiry_duration: Duration,
    spinner: Option<&ProgressBar>,
) -> Result<Option<GetSessionResponse>> {
    use futures_util::StreamExt;
    use tokio_tungstenite::connect_async;

    let ws_url = format!(
        "{}/v1/pairing/sessions/{}/ws",
        registry
            .replace("http://", "ws://")
            .replace("https://", "wss://")
            .trim_end_matches('/'),
        session_id
    );

    let deadline = tokio::time::Instant::now() + expiry_duration;

    if let Some(pb) = spinner {
        pb.set_message(format!("{PHONE}Waiting for device..."));
    }

    // Try WebSocket first
    match connect_async(&ws_url).await {
        Ok((ws_stream, _)) => {
            let (_, mut read) = ws_stream.split();
            loop {
                tokio::select! {
                    _ = tokio::time::sleep_until(deadline) => return Ok(None),
                    msg = read.next() => match msg {
                        Some(Ok(tokio_tungstenite::tungstenite::Message::Text(text))) => {
                            if text.contains("\"responded\"") {
                                return fetch_session(client, session_url).await.map(Some);
                            }
                            if text.contains("\"cancelled\"") || text.contains("\"expired\"") {
                                return fetch_session(client, session_url).await.map(Some);
                            }
                        }
                        None | Some(Err(_)) => break, // fall through to polling
                        _ => {}
                    },
                }
            }
        }
        Err(_) => {
            // WebSocket unavailable, fall through to polling
        }
    }

    // Fallback: HTTP polling
    poll_for_response(client, session_url, expiry_duration, spinner).await
}

/// Fetch the current session state via HTTP GET.
async fn fetch_session(client: &reqwest::Client, session_url: &str) -> Result<GetSessionResponse> {
    let resp = client
        .get(session_url)
        .send()
        .await
        .context("Failed to fetch session")?;
    resp.json::<GetSessionResponse>()
        .await
        .context("Failed to parse session response")
}

/// Poll the registry for session state changes (fallback when WebSocket is unavailable).
async fn poll_for_response(
    client: &reqwest::Client,
    session_url: &str,
    expiry_duration: Duration,
    spinner: Option<&ProgressBar>,
) -> Result<Option<GetSessionResponse>> {
    let start = std::time::Instant::now();

    loop {
        let elapsed = start.elapsed();
        if elapsed >= expiry_duration {
            return Ok(None);
        }

        match client.get(session_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(status) = resp.json::<GetSessionResponse>().await {
                    match status.status {
                        SessionStatus::Responded
                        | SessionStatus::Cancelled
                        | SessionStatus::Expired => return Ok(Some(status)),
                        _ => {} // still pending
                    }
                }
            }
            _ => {} // network error, retry
        }

        let remaining = expiry_duration - elapsed;
        if let Some(pb) = spinner {
            pb.set_message(format!(
                "{PHONE}Waiting for device... ({:02}:{:02})",
                remaining.as_secs() / 60,
                remaining.as_secs() % 60
            ));
        }

        tokio::time::sleep(POLL_INTERVAL).await;
    }
}
