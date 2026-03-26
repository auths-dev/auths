//! Platform identity claim workflow orchestration.
//!
//! Orchestrates OAuth device flow, proof publishing, and registry submission
//! for linking platform identities (e.g. GitHub) to a controller DID.

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use auths_core::ports::platform::{
    ClaimResponse, DeviceCodeResponse, OAuthDeviceFlowProvider, PlatformError,
    PlatformProofPublisher, RegistryClaimClient,
};
use auths_core::signing::{SecureSigner, StorageSigner};
use auths_core::storage::keychain::{IdentityDID, KeyAlias};

use crate::context::AuthsContext;
use crate::pairing::PairingError;

/// Signed platform claim linking a controller DID to a platform identity.
///
/// Canonicalized (RFC 8785) before signing so that the Ed25519 signature
/// can be verified by anyone using only the DID's public key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformClaim {
    /// Claim type discriminant; always `"platform_claim"`.
    #[serde(rename = "type")]
    pub claim_type: String,
    /// Platform identifier (e.g. `"github"`).
    pub platform: String,
    /// Username on the platform.
    pub namespace: String,
    /// Controller DID being linked.
    pub did: String,
    /// RFC 3339 timestamp of claim creation.
    pub timestamp: String,
    /// Base64url-encoded Ed25519 signature over the canonical unsigned JSON.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// Configuration for GitHub identity claim workflow.
///
/// Args:
/// * `client_id`: GitHub OAuth application client ID.
/// * `registry_url`: Base URL of the auths registry.
/// * `scopes`: OAuth scopes to request (e.g. `"read:user gist"`).
pub struct GitHubClaimConfig {
    /// GitHub OAuth application client ID.
    pub client_id: String,
    /// Base URL of the auths registry.
    pub registry_url: String,
    /// OAuth scopes to request.
    pub scopes: String,
}

/// Create and sign a platform claim JSON string.
///
/// Builds the claim, canonicalizes (RFC 8785), signs with the identity key,
/// and returns the pretty-printed signed JSON.
///
/// Args:
/// * `platform`: Platform name (e.g. `"github"`).
/// * `namespace`: Username on the platform.
/// * `did`: Controller DID.
/// * `key_alias`: Keychain alias for the signing key.
/// * `ctx`: Runtime context supplying `key_storage` and `passphrase_provider`.
/// * `now`: Current time (injected by caller — no `Utc::now()` in SDK).
///
/// Usage:
/// ```ignore
/// let claim_json = create_signed_platform_claim("github", "octocat", &did, &alias, &ctx, now)?;
/// ```
pub fn create_signed_platform_claim(
    platform: &str,
    namespace: &str,
    did: &str,
    key_alias: &KeyAlias,
    ctx: &AuthsContext,
    now: DateTime<Utc>,
) -> Result<String, PairingError> {
    let mut claim = PlatformClaim {
        claim_type: "platform_claim".to_string(),
        platform: platform.to_string(),
        namespace: namespace.to_string(),
        did: did.to_string(),
        timestamp: now.to_rfc3339(),
        signature: None,
    };

    let unsigned_json = serde_json::to_value(&claim)
        .map_err(|e| PairingError::AttestationFailed(format!("failed to serialize claim: {e}")))?;
    let canonical = json_canon::to_string(&unsigned_json).map_err(|e| {
        PairingError::AttestationFailed(format!("failed to canonicalize claim: {e}"))
    })?;

    let signer = StorageSigner::new(std::sync::Arc::clone(&ctx.key_storage));
    let signature_bytes = signer
        .sign_with_alias(
            key_alias,
            ctx.passphrase_provider.as_ref(),
            canonical.as_bytes(),
        )
        .map_err(|e| {
            PairingError::AttestationFailed(format!("failed to sign platform claim: {e}"))
        })?;

    claim.signature = Some(URL_SAFE_NO_PAD.encode(&signature_bytes));

    serde_json::to_string_pretty(&claim).map_err(|e| {
        PairingError::AttestationFailed(format!("failed to serialize signed claim: {e}"))
    })
}

/// Orchestrate GitHub identity claiming end-to-end.
///
/// Steps:
/// 1. Request OAuth device code.
/// 2. Fire `on_device_code` callback (CLI displays `user_code`, opens browser).
/// 3. Poll for access token (RFC 8628 device flow).
/// 4. Fetch GitHub user profile.
/// 5. Create signed platform claim (injected `now`, no `Utc::now()` in SDK).
/// 6. Publish claim as a GitHub Gist proof.
/// 7. Submit claim to registry.
///
/// Args:
/// * `oauth`: OAuth device flow provider.
/// * `publisher`: Proof publisher (publishes Gist).
/// * `registry_claim`: Registry claim client.
/// * `ctx`: Runtime context (identity, key storage, passphrase provider).
/// * `config`: GitHub client ID, registry URL, and OAuth scopes.
/// * `now`: Current time (injected by caller).
/// * `on_device_code`: Callback fired after device code is obtained; CLI shows
///   `user_code`, opens browser, displays instructions.
///
/// Usage:
/// ```ignore
/// let response = claim_github_identity(
///     &oauth_provider,
///     &gist_publisher,
///     &registry_client,
///     &ctx,
///     GitHubClaimConfig { client_id: "...".into(), registry_url: "...".into(), scopes: "read:user gist".into() },
///     Utc::now(),
///     &|code| { open::that(&code.verification_uri).ok(); },
/// ).await?;
/// ```
pub async fn claim_github_identity<
    O: OAuthDeviceFlowProvider,
    P: PlatformProofPublisher,
    C: RegistryClaimClient,
>(
    oauth: &O,
    publisher: &P,
    registry_claim: &C,
    ctx: &AuthsContext,
    config: GitHubClaimConfig,
    now: DateTime<Utc>,
    on_device_code: &(dyn Fn(&DeviceCodeResponse) + Send + Sync),
) -> Result<ClaimResponse, PlatformError> {
    let device_code = oauth
        .request_device_code(&config.client_id, &config.scopes)
        .await?;

    on_device_code(&device_code);

    let expires_in = Duration::from_secs(device_code.expires_in);
    let interval = Duration::from_secs(device_code.interval);

    let access_token = oauth
        .poll_for_token(
            &config.client_id,
            &device_code.device_code,
            interval,
            expires_in,
        )
        .await?;

    let profile = oauth.fetch_user_profile(&access_token).await?;

    let controller_did = crate::pairing::load_controller_did(ctx.identity_storage.as_ref())
        .map_err(|e| PlatformError::Platform {
            message: e.to_string(),
        })?;

    let key_alias = resolve_signing_key_alias(ctx, &controller_did)?;

    let claim_json = create_signed_platform_claim(
        "github",
        &profile.login,
        &controller_did,
        &key_alias,
        ctx,
        now,
    )
    .map_err(|e| PlatformError::Platform {
        message: e.to_string(),
    })?;

    let proof_url = publisher.publish_proof(&access_token, &claim_json).await?;

    registry_claim
        .submit_claim(&config.registry_url, &controller_did, &proof_url)
        .await
}

/// Configuration for claiming an npm platform identity.
pub struct NpmClaimConfig {
    /// Registry URL to submit the claim to.
    pub registry_url: String,
}

/// Claims an npm platform identity by verifying an npm access token.
///
/// Args:
/// * `npm_username`: The verified npm username (from `HttpNpmAuthProvider::verify_token`).
/// * `registry_claim`: Client for submitting the claim to the auths registry.
/// * `ctx`: Auths context with identity storage and signing keys.
/// * `config`: npm claim configuration (registry URL).
/// * `now`: Current time for timestamp in the claim.
///
/// Usage:
/// ```ignore
/// let response = claim_npm_identity("bordumb", &registry_client, &ctx, config, now).await?;
/// ```
pub async fn claim_npm_identity<C: RegistryClaimClient>(
    npm_username: &str,
    npm_token: &str,
    registry_claim: &C,
    ctx: &AuthsContext,
    config: NpmClaimConfig,
    now: DateTime<Utc>,
) -> Result<ClaimResponse, PlatformError> {
    let controller_did = crate::pairing::load_controller_did(ctx.identity_storage.as_ref())
        .map_err(|e| PlatformError::Platform {
            message: e.to_string(),
        })?;

    let key_alias = resolve_signing_key_alias(ctx, &controller_did)?;

    let claim_json =
        create_signed_platform_claim("npm", npm_username, &controller_did, &key_alias, ctx, now)
            .map_err(|e| PlatformError::Platform {
                message: e.to_string(),
            })?;

    // npm has no Gist equivalent. Encode both the npm token (for server-side
    // verification via npm whoami) and the signed claim (for signature verification).
    // The server detects the "npm-token:" prefix, verifies the token, then discards it.
    let encoded_claim = URL_SAFE_NO_PAD.encode(claim_json.as_bytes());
    let encoded_token = URL_SAFE_NO_PAD.encode(npm_token.as_bytes());
    let proof_url = format!("npm-token:{encoded_token}:{encoded_claim}");

    registry_claim
        .submit_claim(&config.registry_url, &controller_did, &proof_url)
        .await
}

fn resolve_signing_key_alias(
    ctx: &AuthsContext,
    controller_did: &str,
) -> Result<KeyAlias, PlatformError> {
    #[allow(clippy::disallowed_methods)]
    // INVARIANT: controller_did comes from load_controller_did() which returns into_inner() of a validated IdentityDID from storage
    let identity_did = IdentityDID::new_unchecked(controller_did.to_string());
    let aliases = ctx
        .key_storage
        .list_aliases_for_identity(&identity_did)
        .map_err(|e| PlatformError::Platform {
            message: format!("failed to list key aliases: {e}"),
        })?;

    aliases
        .into_iter()
        .find(|a| !a.contains("--next-"))
        .ok_or_else(|| PlatformError::Platform {
            message: format!("no signing key found for identity {controller_did}"),
        })
}
