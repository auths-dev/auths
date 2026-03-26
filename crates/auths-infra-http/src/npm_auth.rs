//! npm access token verification.
//!
//! Verifies an npm access token via the `/-/whoami` endpoint and returns
//! the authenticated username.

use auths_core::ports::platform::{PlatformError, PlatformUserProfile};

use crate::default_http_client;

const NPM_REGISTRY: &str = "https://registry.npmjs.org";

/// HTTP client that verifies npm access tokens.
///
/// Usage:
/// ```ignore
/// let provider = HttpNpmAuthProvider::new();
/// let profile = provider.verify_token("npm_abc123").await?;
/// println!("Authenticated as: {}", profile.login);
/// ```
pub struct HttpNpmAuthProvider {
    client: reqwest::Client,
}

impl Default for HttpNpmAuthProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpNpmAuthProvider {
    pub fn new() -> Self {
        Self {
            client: default_http_client(),
        }
    }

    /// Verifies an npm access token and returns the username.
    ///
    /// Args:
    /// * `token`: npm access token (created at https://www.npmjs.com/settings/~/tokens)
    pub async fn verify_token(&self, token: &str) -> Result<PlatformUserProfile, PlatformError> {
        let url = format!("{NPM_REGISTRY}/-/whoami");
        let resp = self
            .client
            .get(&url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| PlatformError::Platform {
                message: format!("npm whoami request failed: {e}"),
            })?;

        if !resp.status().is_success() {
            return Err(PlatformError::Platform {
                message: format!(
                    "npm token verification failed (HTTP {}). \
                     Make sure your token is valid and has read access.",
                    resp.status()
                ),
            });
        }

        #[derive(serde::Deserialize)]
        struct WhoamiResponse {
            username: String,
        }

        let whoami: WhoamiResponse = resp.json().await.map_err(|e| PlatformError::Platform {
            message: format!("Failed to parse npm whoami response: {e}"),
        })?;

        Ok(PlatformUserProfile {
            login: whoami.username,
            name: None,
        })
    }
}
