use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct GistResponse {
    html_url: String,
}

/// Publishes a signed platform claim as a public GitHub Gist.
///
/// The Gist persists as a permanent, publicly-verifiable anchor even
/// after the OAuth token expires. Anyone can verify the Ed25519 signature
/// inside the claim using only the DID's public key.
///
/// Args:
/// * `client`: Pre-configured HTTP client from the composition root.
/// * `access_token`: GitHub OAuth access token (temporary, used only for creation).
/// * `claim_json`: The JSON string of the signed platform claim.
///
/// Usage:
/// ```ignore
/// let url = publish_proof_gist(&client, &auth.access_token, &signed_claim).await?;
/// println!("Proof published at: {url}");
/// ```
pub async fn publish_proof_gist(
    client: &reqwest::Client,
    access_token: &str,
    claim_json: &str,
) -> Result<String> {
    let payload = serde_json::json!({
        "description": "Auths Identity Proof — cryptographic link between DID and GitHub account",
        "public": true,
        "files": {
            "auths-proof.json": {
                "content": claim_json
            }
        }
    });

    let resp: GistResponse = client
        .post("https://api.github.com/gists")
        .header("Authorization", format!("Bearer {access_token}"))
        .header("User-Agent", "auths-cli")
        .header("Accept", "application/vnd.github+json")
        .json(&payload)
        .send()
        .await
        .context("Failed to create GitHub Gist")?
        .error_for_status()
        .context("GitHub Gist creation returned an error")?
        .json()
        .await
        .context("Failed to parse Gist response")?;

    Ok(resp.html_url)
}
