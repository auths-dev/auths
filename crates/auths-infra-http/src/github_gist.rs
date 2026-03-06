//! GitHub Gist proof publisher HTTP implementation.

use std::future::Future;

use serde::Deserialize;

use auths_core::ports::platform::{PlatformError, PlatformProofPublisher};

use crate::error::map_reqwest_error;

#[derive(Deserialize)]
struct GistResponse {
    html_url: String,
}

/// HTTP implementation that publishes platform claim proofs as public GitHub Gists.
///
/// The Gist persists as a permanent, publicly-verifiable anchor. Anyone can
/// verify the Ed25519 signature inside the claim using only the DID's public key.
///
/// Usage:
/// ```ignore
/// let publisher = HttpGistPublisher::new();
/// let proof_url = publisher.publish_proof(&access_token, &claim_json).await?;
/// ```
pub struct HttpGistPublisher {
    client: reqwest::Client,
}

impl HttpGistPublisher {
    /// Create a new publisher with a default HTTP client.
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

impl Default for HttpGistPublisher {
    fn default() -> Self {
        Self::new()
    }
}

impl PlatformProofPublisher for HttpGistPublisher {
    fn publish_proof(
        &self,
        access_token: &str,
        claim_json: &str,
    ) -> impl Future<Output = Result<String, PlatformError>> + Send {
        let client = self.client.clone();
        let access_token = access_token.to_string();
        let claim_json = claim_json.to_string();
        async move {
            let payload = serde_json::json!({
                "description": "Auths Identity Proof — cryptographic link between DID and GitHub account",
                "public": true,
                "files": {
                    "auths-proof.json": {
                        "content": claim_json
                    }
                }
            });

            let resp = client
                .post("https://api.github.com/gists")
                .header("Authorization", format!("Bearer {access_token}"))
                .header("User-Agent", "auths-cli")
                .header("Accept", "application/vnd.github+json")
                .json(&payload)
                .send()
                .await
                .map_err(|e| PlatformError::Network(map_reqwest_error(e, "api.github.com")))?;

            if !resp.status().is_success() {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                return Err(PlatformError::Platform {
                    message: format!("GitHub Gist creation failed (HTTP {status}): {body}"),
                });
            }

            let gist: GistResponse = resp.json().await.map_err(|e| PlatformError::Platform {
                message: format!("failed to parse Gist response: {e}"),
            })?;

            Ok(gist.html_url)
        }
    }
}
