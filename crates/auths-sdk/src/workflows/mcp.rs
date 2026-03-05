//! MCP token exchange workflow.
//!
//! Acquires an OAuth Bearer token for MCP tool server access by exchanging
//! the agent's attestation chain for a scoped JWT via the OIDC bridge.

use auths_verifier::core::Attestation;
use serde::{Deserialize, Serialize};

use crate::error::McpAuthError;

/// Request body sent to the OIDC bridge's `/token` endpoint.
#[derive(Serialize)]
struct McpExchangeRequest {
    attestation_chain: Vec<Attestation>,
    root_public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    requested_capabilities: Option<Vec<String>>,
}

/// Response from the OIDC bridge's `/token` endpoint.
#[derive(Deserialize)]
struct McpTokenResponse {
    access_token: String,
    #[allow(dead_code)]
    token_type: String,
    #[allow(dead_code)]
    expires_in: u64,
    #[allow(dead_code)]
    subject: String,
}

/// Acquires an OAuth Bearer token for MCP tool server access.
///
/// Exchanges the agent's attestation chain for a scoped JWT via the OIDC bridge,
/// then returns the JWT string for use as a Bearer token.
///
/// Args:
/// * `bridge_url`: The OIDC bridge base URL (e.g., "http://localhost:3300").
/// * `chain`: The agent's attestation chain (root to leaf).
/// * `root_public_key_hex`: Hex-encoded Ed25519 public key of the root identity.
/// * `requested_capabilities`: Capabilities needed for this MCP session.
///
/// Usage:
/// ```ignore
/// let token = acquire_mcp_token(
///     "http://localhost:3300",
///     &attestation_chain,
///     "abcdef1234...",
///     &["fs:read", "fs:write"],
/// ).await?;
/// ```
pub async fn acquire_mcp_token(
    bridge_url: &str,
    chain: &[Attestation],
    root_public_key_hex: &str,
    requested_capabilities: &[&str],
) -> Result<String, McpAuthError> {
    let url = format!("{}/token", bridge_url.trim_end_matches('/'));

    let request_body = McpExchangeRequest {
        attestation_chain: chain.to_vec(),
        root_public_key: root_public_key_hex.to_string(),
        requested_capabilities: if requested_capabilities.is_empty() {
            None
        } else {
            Some(
                requested_capabilities
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            )
        },
    };

    // INVARIANT: reqwest Client::new() cannot fail
    #[allow(clippy::expect_used)]
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("failed to build HTTP client");

    let response = client
        .post(&url)
        .json(&request_body)
        .send()
        .await
        .map_err(|e| McpAuthError::BridgeUnreachable(e.to_string()))?;

    let status = response.status().as_u16();
    if status == 403 {
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "unknown".to_string());
        return Err(McpAuthError::InsufficientCapabilities {
            requested: requested_capabilities
                .iter()
                .map(|s| s.to_string())
                .collect(),
            detail: body,
        });
    }

    if !response.status().is_success() {
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "unknown".to_string());
        return Err(McpAuthError::TokenExchangeFailed { status, body });
    }

    let token_response: McpTokenResponse = response
        .json()
        .await
        .map_err(|e| McpAuthError::InvalidResponse(e.to_string()))?;

    Ok(token_response.access_token)
}
