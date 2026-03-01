use std::time::Duration;

use anyhow::{Context, Result};

/// Builds a pre-configured HTTP client for CLI operations.
///
/// The client is configured with a 30-second timeout suitable for
/// registry, OAuth, and general API interactions.
///
/// Usage:
/// ```ignore
/// use auths_cli::factories::network::build_http_client;
///
/// let client = build_http_client()?;
/// ```
pub fn build_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("auths-cli")
        .build()
        .context("failed to create HTTP client")
}
