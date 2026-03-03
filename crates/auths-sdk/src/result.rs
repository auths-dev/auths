use auths_core::storage::keychain::{IdentityDID, KeyAlias};
use auths_verifier::core::ResourceId;
use auths_verifier::types::DeviceDID;
use auths_verifier::Capability;

/// Outcome of a successful developer identity setup.
///
/// Usage:
/// ```ignore
/// let result: SetupResult = sdk.setup_developer(config).await?;
/// println!("Created identity: {}", result.identity_did);
/// ```
#[derive(Debug, Clone)]
pub struct SetupResult {
    /// The controller DID of the created identity.
    pub identity_did: IdentityDID,
    /// The device DID bound to this identity.
    pub device_did: DeviceDID,
    /// The keychain alias used for the signing key.
    pub key_alias: KeyAlias,
    /// Result of platform verification, if performed.
    pub platform_claim: Option<PlatformClaimResult>,
    /// Whether git commit signing was configured.
    pub git_signing_configured: bool,
    /// Result of registry registration, if performed.
    pub registered: Option<RegistrationOutcome>,
}

/// Outcome of a successful CI/ephemeral identity setup.
///
/// Usage:
/// ```ignore
/// let result: CiSetupResult = sdk.setup_ci(config).await?;
/// for line in &result.env_block {
///     println!("{line}");
/// }
/// ```
#[derive(Debug, Clone)]
pub struct CiSetupResult {
    /// The controller DID of the CI identity.
    pub identity_did: IdentityDID,
    /// The device DID bound to this CI identity.
    pub device_did: DeviceDID,
    /// Shell `export` lines for configuring CI environment variables.
    pub env_block: Vec<String>,
}

/// Outcome of a successful agent identity setup.
///
/// Usage:
/// ```ignore
/// let result: AgentSetupResult = sdk.setup_agent(config).await?;
/// println!("Agent {} delegated by {}", result.agent_did, result.parent_did);
/// ```
#[derive(Debug, Clone)]
pub struct AgentSetupResult {
    /// The DID of the newly created agent identity.
    pub agent_did: IdentityDID,
    /// The DID of the parent identity that delegated authority.
    pub parent_did: IdentityDID,
    /// The capabilities granted to the agent.
    pub capabilities: Vec<Capability>,
}

/// Outcome of a successful device link operation.
///
/// Usage:
/// ```ignore
/// let result: DeviceLinkResult = sdk.link_device(config).await?;
/// println!("Linked device {} via attestation {}", result.device_did, result.attestation_id);
/// ```
#[derive(Debug, Clone)]
pub struct DeviceLinkResult {
    /// The DID of the linked device.
    pub device_did: DeviceDID,
    /// The resource identifier of the created attestation.
    pub attestation_id: ResourceId,
}

/// Outcome of a successful identity rotation.
///
/// Usage:
/// ```ignore
/// let result: RotationResult = rotate_identity(config, provider)?;
/// println!("Rotated DID: {}", result.controller_did);
/// println!("New key:  {}...", result.new_key_fingerprint);
/// println!("Old key:  {}...", result.previous_key_fingerprint);
/// ```
#[derive(Debug, Clone)]
pub struct RotationResult {
    /// The controller DID of the rotated identity.
    pub controller_did: IdentityDID,
    /// Hex-encoded fingerprint of the new signing key.
    pub new_key_fingerprint: String,
    /// Hex-encoded fingerprint of the previous signing key.
    pub previous_key_fingerprint: String,
}

/// Outcome of a successful device authorization extension.
///
/// Usage:
/// ```ignore
/// let result: DeviceExtensionResult = extend_device_authorization(config, provider)?;
/// println!("Extended {} until {}", result.device_did, result.new_expires_at.date_naive());
/// ```
#[derive(Debug, Clone)]
pub struct DeviceExtensionResult {
    /// The DID of the device whose authorization was extended.
    pub device_did: DeviceDID,
    /// The new expiration timestamp for the device authorization.
    pub new_expires_at: chrono::DateTime<chrono::Utc>,
}

/// Outcome of a successful platform claim verification.
///
/// Usage:
/// ```ignore
/// let claim: PlatformClaimResult = sdk.platform_claim(platform).await?;
/// println!("Verified as {} on {}", claim.username, claim.platform);
/// ```
#[derive(Debug, Clone)]
pub struct PlatformClaimResult {
    /// The platform name (e.g. `"github"`).
    pub platform: String,
    /// The verified username on the platform.
    pub username: String,
    /// Optional URL to the public proof artifact (e.g. a GitHub gist).
    pub proof_url: Option<String>,
}

/// Outcome of a successful registry registration.
///
/// Usage:
/// ```ignore
/// if let Some(reg) = result.registered {
///     println!("Registered {} at {}", reg.did_prefix, reg.registry);
/// }
/// ```
#[derive(Debug, Clone)]
pub struct RegistrationOutcome {
    /// The KERI prefix portion of the registered DID.
    pub did_prefix: String,
    /// The registry URL where the identity was registered.
    pub registry: String,
    /// Number of platform claims indexed by the registry.
    pub platform_claims_indexed: usize,
}
