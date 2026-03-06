//! Auths registry platform claim submission HTTP implementation.

use std::future::Future;

use serde::Deserialize;

use auths_core::ports::platform::{ClaimResponse, PlatformError, RegistryClaimClient};

use crate::error::{map_reqwest_error, map_status_error};

#[derive(Deserialize)]
struct ServerClaimResponse {
    platform: String,
    namespace: String,
    did: String,
}

/// HTTP implementation that submits platform identity claims to the auths registry.
///
/// Usage:
/// ```ignore
/// let client = HttpRegistryClaimClient::new();
/// let response = client.submit_claim(registry_url, &did, &proof_url).await?;
/// println!("{}", response.message);
/// ```
pub struct HttpRegistryClaimClient {
    client: reqwest::Client,
}

impl HttpRegistryClaimClient {
    /// Create a new client with a default HTTP client.
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

impl Default for HttpRegistryClaimClient {
    fn default() -> Self {
        Self::new()
    }
}

impl RegistryClaimClient for HttpRegistryClaimClient {
    fn submit_claim(
        &self,
        registry_url: &str,
        did: &str,
        proof_url: &str,
    ) -> impl Future<Output = Result<ClaimResponse, PlatformError>> + Send {
        let client = self.client.clone();
        let url = format!(
            "{}/v1/identities/{}/claims",
            registry_url.trim_end_matches('/'),
            did
        );
        let proof_url = proof_url.to_string();
        async move {
            let resp = client
                .post(&url)
                .header("Content-Type", "application/json")
                .json(&serde_json::json!({ "proof_url": proof_url }))
                .send()
                .await
                .map_err(|e| PlatformError::Network(map_reqwest_error(e, &url)))?;

            let status = resp.status();

            if !status.is_success() {
                return Err(PlatformError::Network(map_status_error(
                    status.as_u16(),
                    &url,
                )));
            }

            let server: ServerClaimResponse =
                resp.json().await.map_err(|e| PlatformError::Platform {
                    message: format!("failed to parse claim response: {e}"),
                })?;

            Ok(ClaimResponse {
                message: format!(
                    "Platform claim indexed: {} @{} -> {}",
                    server.platform, server.namespace, server.did
                ),
            })
        }
    }
}
