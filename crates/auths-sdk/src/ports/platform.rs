//! Platform claim port traits for OAuth device flow, proof publishing, and registry submission.

use std::future::Future;
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::error::PlatformError;

/// OAuth 2.0 device authorization grant response (RFC 8628 §3.2).
///
/// Returned by [`OAuthDeviceFlowProvider::request_device_code`].
/// The CLI displays `user_code` + `verification_uri` to the user,
/// then polls with `device_code`.
pub struct DeviceCodeResponse {
    /// Opaque device verification code used to poll for the token.
    pub device_code: String,
    /// Short user-facing code to enter at `verification_uri`.
    pub user_code: String,
    /// URL where the user enters `user_code`.
    pub verification_uri: String,
    /// Lifetime of the device code in seconds.
    pub expires_in: u64,
    /// Minimum polling interval in seconds.
    pub interval: u64,
}

/// Authenticated platform user profile returned after token exchange.
///
/// Returned by [`OAuthDeviceFlowProvider::fetch_user_profile`].
pub struct PlatformUserProfile {
    /// Platform login / username.
    pub login: String,
    /// Display name (optional).
    pub name: Option<String>,
}

/// Response from the registry after submitting a platform claim.
///
/// Returned by [`RegistryClaimClient::submit_claim`].
pub struct ClaimResponse {
    /// Human-readable confirmation message from the registry.
    pub message: String,
}

/// Two-phase OAuth 2.0 device authorization flow (RFC 8628).
///
/// The CLI calls [`request_device_code`](Self::request_device_code), displays the
/// `user_code` and `verification_uri`, optionally opens a browser, then calls
/// [`poll_for_token`](Self::poll_for_token). All presentation logic stays in the CLI.
///
/// Usage:
/// ```ignore
/// let resp = provider.request_device_code(CLIENT_ID, "read:user gist").await?;
/// // CLI: display resp.user_code, open resp.verification_uri
/// let token = provider.poll_for_token(CLIENT_ID, &resp.device_code, Duration::from_secs(resp.interval), expires_at).await?;
/// let profile = provider.fetch_user_profile(&token).await?;
/// ```
pub trait OAuthDeviceFlowProvider: Send + Sync {
    /// Request a device code to begin the device authorization flow.
    ///
    /// Args:
    /// * `client_id`: OAuth application client ID.
    /// * `scopes`: Space-separated OAuth scopes to request.
    fn request_device_code(
        &self,
        client_id: &str,
        scopes: &str,
    ) -> impl Future<Output = Result<DeviceCodeResponse, PlatformError>> + Send;

    /// Poll for the access token until granted, denied, or expired.
    ///
    /// Args:
    /// * `client_id`: OAuth application client ID.
    /// * `device_code`: Device code from [`request_device_code`](Self::request_device_code).
    /// * `interval`: Minimum time between poll attempts.
    /// * `expires_at`: When the device code expires; polling stops after this time.
    fn poll_for_token(
        &self,
        client_id: &str,
        device_code: &str,
        interval: Duration,
        expires_at: DateTime<Utc>,
    ) -> impl Future<Output = Result<String, PlatformError>> + Send;

    /// Fetch the authenticated user's profile using the access token.
    ///
    /// Args:
    /// * `access_token`: OAuth access token from [`poll_for_token`](Self::poll_for_token).
    fn fetch_user_profile(
        &self,
        access_token: &str,
    ) -> impl Future<Output = Result<PlatformUserProfile, PlatformError>> + Send;
}

/// Publish a signed platform claim as a publicly readable proof artifact.
///
/// For GitHub: publishes a Gist. Returns the URL of the published proof.
///
/// Usage:
/// ```ignore
/// let proof_url = publisher.publish_proof(&access_token, &claim_json).await?;
/// registry_client.submit_claim(registry, &did, &proof_url).await?;
/// ```
pub trait PlatformProofPublisher: Send + Sync {
    /// Publish the claim JSON as a proof artifact and return its public URL.
    ///
    /// Args:
    /// * `access_token`: OAuth access token with write permission to publish.
    /// * `claim_json`: Canonicalized, signed JSON claim to publish.
    fn publish_proof(
        &self,
        access_token: &str,
        claim_json: &str,
    ) -> impl Future<Output = Result<String, PlatformError>> + Send;
}

/// Submit a published platform claim to the auths registry for verification.
///
/// Usage:
/// ```ignore
/// let response = registry_client.submit_claim(registry_url, &did, &proof_url).await?;
/// println!("{}", response.message);
/// ```
pub trait RegistryClaimClient: Send + Sync {
    /// Submit a platform identity claim to the registry.
    ///
    /// Args:
    /// * `registry_url`: Base URL of the auths registry.
    /// * `did`: DID of the identity making the claim.
    /// * `proof_url`: Public URL of the published proof artifact.
    fn submit_claim(
        &self,
        registry_url: &str,
        did: &str,
        proof_url: &str,
    ) -> impl Future<Output = Result<ClaimResponse, PlatformError>> + Send;
}
