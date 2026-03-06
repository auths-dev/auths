//! GitHub OAuth 2.0 device authorization flow (RFC 8628) HTTP implementation.

use std::future::Future;
use std::time::Duration;

use serde::Deserialize;

use auths_core::ports::platform::{
    DeviceCodeResponse, OAuthDeviceFlowProvider, PlatformError, PlatformUserProfile,
};

use crate::error::{map_reqwest_error, map_status_error};

#[derive(Deserialize)]
struct RawDeviceCodeResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in: u64,
    interval: u64,
}

#[derive(Deserialize)]
struct TokenPollResponse {
    access_token: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct GitHubUserResponse {
    login: String,
    name: Option<String>,
}

/// HTTP implementation of the GitHub device authorization flow (RFC 8628).
///
/// Usage:
/// ```ignore
/// let provider = HttpGitHubOAuthProvider::new();
/// let code = provider.request_device_code("Ov23li...", "read:user gist").await?;
/// let token = provider.poll_for_token("Ov23li...", &code.device_code,
///     Duration::from_secs(code.interval), Duration::from_secs(code.expires_in)).await?;
/// ```
pub struct HttpGitHubOAuthProvider {
    client: reqwest::Client,
}

impl HttpGitHubOAuthProvider {
    /// Create a new provider with a default HTTP client.
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

impl Default for HttpGitHubOAuthProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl OAuthDeviceFlowProvider for HttpGitHubOAuthProvider {
    fn request_device_code(
        &self,
        client_id: &str,
        scopes: &str,
    ) -> impl Future<Output = Result<DeviceCodeResponse, PlatformError>> + Send {
        let client = self.client.clone();
        let client_id = client_id.to_string();
        let scopes = scopes.to_string();
        async move {
            let raw: RawDeviceCodeResponse = client
                .post("https://github.com/login/device/code")
                .header("Accept", "application/json")
                .form(&[
                    ("client_id", client_id.as_str()),
                    ("scope", scopes.as_str()),
                ])
                .send()
                .await
                .map_err(|e| PlatformError::Network(map_reqwest_error(e, "github.com")))?
                .json()
                .await
                .map_err(|e| PlatformError::Platform {
                    message: format!("failed to parse device code response: {e}"),
                })?;

            Ok(DeviceCodeResponse {
                device_code: raw.device_code,
                user_code: raw.user_code,
                verification_uri: raw.verification_uri,
                expires_in: raw.expires_in,
                interval: raw.interval,
            })
        }
    }

    fn poll_for_token(
        &self,
        client_id: &str,
        device_code: &str,
        interval: Duration,
        expires_in: Duration,
    ) -> impl Future<Output = Result<String, PlatformError>> + Send {
        let client = self.client.clone();
        let client_id = client_id.to_string();
        let device_code = device_code.to_string();
        async move {
            // RFC 8628 §3.5: enforce minimum 5s interval
            let mut poll_interval = interval.max(Duration::from_secs(5));

            let inner = async {
                loop {
                    tokio::time::sleep(poll_interval).await;

                    let resp: TokenPollResponse = client
                        .post("https://github.com/login/oauth/access_token")
                        .header("Accept", "application/json")
                        .form(&[
                            ("client_id", client_id.as_str()),
                            ("device_code", device_code.as_str()),
                            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                        ])
                        .send()
                        .await
                        .map_err(|e| PlatformError::Network(map_reqwest_error(e, "github.com")))?
                        .json()
                        .await
                        .map_err(|e| PlatformError::Platform {
                            message: format!("failed to parse token poll response: {e}"),
                        })?;

                    match resp.error.as_deref() {
                        Some("authorization_pending") => continue,
                        Some("slow_down") => {
                            // RFC 8628 §3.5: increase interval by 5s on slow_down
                            poll_interval += Duration::from_secs(5);
                            continue;
                        }
                        Some("expired_token") => return Err(PlatformError::ExpiredToken),
                        Some("access_denied") => return Err(PlatformError::AccessDenied),
                        Some(other) => {
                            return Err(PlatformError::Platform {
                                message: format!("GitHub OAuth error: {other}"),
                            });
                        }
                        None => {}
                    }

                    if let Some(token) = resp.access_token {
                        return Ok(token);
                    }
                }
            };

            tokio::time::timeout(expires_in, inner)
                .await
                .unwrap_or(Err(PlatformError::ExpiredToken))
        }
    }

    fn fetch_user_profile(
        &self,
        access_token: &str,
    ) -> impl Future<Output = Result<PlatformUserProfile, PlatformError>> + Send {
        let client = self.client.clone();
        let access_token = access_token.to_string();
        async move {
            let resp = client
                .get("https://api.github.com/user")
                .header("Authorization", format!("Bearer {access_token}"))
                .header("User-Agent", "auths-cli")
                .send()
                .await
                .map_err(|e| PlatformError::Network(map_reqwest_error(e, "api.github.com")))?;

            if !resp.status().is_success() {
                let status = resp.status().as_u16();
                return Err(PlatformError::Network(map_status_error(status, "/user")));
            }

            let user: GitHubUserResponse =
                resp.json().await.map_err(|e| PlatformError::Platform {
                    message: format!("failed to parse user profile: {e}"),
                })?;

            Ok(PlatformUserProfile {
                login: user.login,
                name: user.name,
            })
        }
    }
}
