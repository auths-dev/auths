//! Fetches verified platform claims from the registry.
//!
//! SECURITY: This module is the single source of truth for building
//! `PlatformContext` from server-verified claims. All callers (CLI, SDK)
//! must use this function instead of accepting self-asserted usernames.

use auths_core::ports::namespace::PlatformContext;
use auths_core::ports::platform::PlatformError;

use crate::default_http_client;

/// Fetches verified platform claims from the registry for the given DID.
///
/// Returns a `PlatformContext` built ONLY from server-verified claims
/// (claims with `verified_at IS NOT NULL`). Rejects if the identity is
/// not registered or has no verified claims.
///
/// Args:
/// * `registry_url`: Base URL of the auths registry.
/// * `did`: The controller DID to look up.
///
/// Usage:
/// ```ignore
/// let ctx = resolve_verified_platform_context("http://localhost:3100", "did:keri:E...").await?;
/// assert!(ctx.github_username.is_some());
/// ```
pub async fn resolve_verified_platform_context(
    registry_url: &str,
    did: &str,
) -> Result<PlatformContext, PlatformError> {
    let client = default_http_client();
    let encoded_did = did.replace(':', "%3A").replace('/', "%2F");
    let url = format!(
        "{}/v1/identities/{}",
        registry_url.trim_end_matches('/'),
        encoded_did
    );

    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| PlatformError::Platform {
            message: format!("Failed to reach registry: {e}"),
        })?;

    if !resp.status().is_success() {
        return Err(PlatformError::Platform {
            message: format!(
                "Registry returned HTTP {}: identity not found or not registered.\n\n\
                 Run this first:\n\
                 \n  auths id register --registry {}",
                resp.status(),
                registry_url
            ),
        });
    }

    let body: serde_json::Value = resp.json().await.map_err(|e| PlatformError::Platform {
        message: format!("Failed to parse identity response: {e}"),
    })?;

    let status = body
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    if status == "unclaimed" || status == "unknown" {
        return Err(PlatformError::Platform {
            message: format!(
                "Your identity is not fully registered on this registry.\n\n\
                 Run this first:\n\
                 \n  auths id register --registry {}\n\n\
                 Then verify your platform identity:\n\
                 \n  auths id claim github --registry {}",
                registry_url, registry_url
            ),
        });
    }

    let mut ctx = PlatformContext::default();
    if let Some(claims) = body.get("platform_claims").and_then(|v| v.as_array()) {
        for claim in claims {
            let platform = claim.get("platform").and_then(|v| v.as_str()).unwrap_or("");
            let namespace = claim
                .get("namespace")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let verified = claim
                .get("verified")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if !verified || namespace.is_empty() {
                continue;
            }
            match platform {
                "github" => ctx.github_username = Some(namespace.to_string()),
                "npm" => ctx.npm_username = Some(namespace.to_string()),
                "pypi" => ctx.pypi_username = Some(namespace.to_string()),
                _ => {}
            }
        }
    }

    if ctx.github_username.is_none() && ctx.npm_username.is_none() && ctx.pypi_username.is_none() {
        return Err(PlatformError::Platform {
            message: format!(
                "No verified platform claims found for your identity.\n\n\
                 Namespace claims require a verified platform identity to prevent spoofing.\n\
                 Run one of:\n\
                 \n  auths id claim github --registry {}\
                 \n  auths id claim npm --registry {}\n\n\
                 This connects your platform account to your Auths identity.",
                registry_url, registry_url
            ),
        });
    }

    Ok(ctx)
}
