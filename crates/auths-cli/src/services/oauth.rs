use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

const DEFAULT_GITHUB_CLIENT_ID: &str = "Ov23lio2CiTHBjM2uIL4";

fn github_client_id() -> String {
    std::env::var("AUTHS_GITHUB_CLIENT_ID").unwrap_or_else(|_| DEFAULT_GITHUB_CLIENT_ID.to_string())
}

#[derive(Debug, Deserialize)]
struct DeviceCodeResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in: u64,
    interval: u64,
}

#[derive(Debug, Deserialize)]
struct TokenPollResponse {
    access_token: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubUser {
    login: String,
}

pub struct GithubAuth {
    pub access_token: String,
    pub username: String,
}

/// Runs the GitHub Device Flow (RFC 8628) to authenticate the user.
///
/// Args:
/// * `client`: Pre-configured HTTP client from the composition root.
/// * `out`: Output helper for progress messages.
///
/// Usage:
/// ```ignore
/// let auth = github_device_flow(&client, &out).await?;
/// println!("Authenticated as {}", auth.username);
/// ```
pub async fn github_device_flow(
    client: &reqwest::Client,
    out: &crate::ux::format::Output,
) -> Result<GithubAuth> {
    let client_id = github_client_id();

    // Step 1: Request device code
    let device_resp: DeviceCodeResponse = client
        .post("https://github.com/login/device/code")
        .header("Accept", "application/json")
        .form(&[
            ("client_id", client_id.as_str()),
            ("scope", "gist read:user"),
        ])
        .send()
        .await
        .context("Failed to request device code from GitHub")?
        .json()
        .await
        .context("Failed to parse device code response")?;

    // Step 2: Display user code and open browser
    out.newline();
    out.print_heading("GitHub Verification");
    out.println(&format!(
        "  Enter this code: {}",
        out.bold(&device_resp.user_code)
    ));
    out.println(&format!(
        "  At: {}",
        out.info(&device_resp.verification_uri)
    ));
    out.newline();

    // Best-effort browser open
    if let Err(e) = open::that(&device_resp.verification_uri) {
        out.print_warn(&format!("Could not open browser automatically: {e}"));
        out.println("  Please open the URL above manually.");
    } else {
        out.println("  Browser opened — waiting for authorization...");
    }

    // Step 3: Poll for token
    let mut interval = Duration::from_secs(device_resp.interval.max(5));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(device_resp.expires_in);

    let access_token = loop {
        tokio::time::sleep(interval).await;

        if tokio::time::Instant::now() > deadline {
            bail!("GitHub authorization timed out. Run `auths init` to try again.");
        }

        let poll_resp: TokenPollResponse = client
            .post("https://github.com/login/oauth/access_token")
            .header("Accept", "application/json")
            .form(&[
                ("client_id", client_id.as_str()),
                ("device_code", device_resp.device_code.as_str()),
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ])
            .send()
            .await
            .context("Failed to poll GitHub for access token")?
            .json()
            .await
            .context("Failed to parse token poll response")?;

        match poll_resp.error.as_deref() {
            Some("authorization_pending") => continue,
            Some("slow_down") => {
                interval += Duration::from_secs(5);
                continue;
            }
            Some("expired_token") => {
                bail!("GitHub authorization expired. Run `auths init` to try again.");
            }
            Some("access_denied") => {
                bail!("GitHub authorization was denied by the user.");
            }
            Some(other) => {
                bail!("GitHub OAuth error: {other}");
            }
            None => {}
        }

        if let Some(token) = poll_resp.access_token {
            break token;
        }
    };

    // Step 4: Fetch username
    let user: GitHubUser = client
        .get("https://api.github.com/user")
        .header("Authorization", format!("Bearer {access_token}"))
        .header("User-Agent", "auths-cli")
        .send()
        .await
        .context("Failed to fetch GitHub user profile")?
        .json()
        .await
        .context("Failed to parse GitHub user response")?;

    out.print_success(&format!("Authenticated as @{}", user.login));

    Ok(GithubAuth {
        access_token,
        username: user.login,
    })
}
