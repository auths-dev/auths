use auths_core::storage::keychain::{IdentityDID, KeyAlias};
use auths_verifier::Capability;
use auths_verifier::core::ResourceId;
use auths_verifier::types::DeviceDID;

/// Outcome of a successful developer identity setup.
///
/// Usage:
/// ```ignore
/// let result = initialize(IdentityConfig::developer(alias), &ctx, keychain, &signer, &provider, git_cfg)?;
/// if let InitializeResult::Developer(r) = result {
///     println!("Created identity: {}", r.identity_did);
/// }
/// ```
#[derive(Debug, Clone)]
pub struct DeveloperIdentityResult {
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
/// let result = initialize(IdentityConfig::ci(registry_path), &ctx, keychain, &signer, &provider, None)?;
/// if let InitializeResult::Ci(r) = result {
///     for line in &r.env_block { println!("{line}"); }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct CiIdentityResult {
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
/// let result = initialize(IdentityConfig::agent(alias, path), &ctx, keychain, &signer, &provider, None)?;
/// if let InitializeResult::Agent(r) = result {
///     println!("Agent {} delegated by {}", r.agent_did, r.parent_did);
/// }
/// ```
#[derive(Debug, Clone)]
pub struct AgentIdentityResult {
    /// The DID of the newly created agent identity.
    pub agent_did: IdentityDID,
    /// The DID of the parent identity that delegated authority.
    pub parent_did: IdentityDID,
    /// The capabilities granted to the agent.
    pub capabilities: Vec<Capability>,
}

/// Outcome of [`crate::setup::initialize`] — one variant per identity persona.
///
/// Usage:
/// ```ignore
/// match initialize(config, &ctx, keychain, &signer, &provider, git_cfg)? {
///     InitializeResult::Developer(r) => display_developer_result(r),
///     InitializeResult::Ci(r) => display_ci_result(r),
///     InitializeResult::Agent(r) => display_agent_result(r),
/// }
/// ```
#[derive(Debug, Clone)]
pub enum InitializeResult {
    /// Developer identity result.
    Developer(DeveloperIdentityResult),
    /// CI/ephemeral identity result.
    Ci(CiIdentityResult),
    /// Agent identity result.
    Agent(AgentIdentityResult),
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
/// let result: IdentityRotationResult = rotate_identity(config, provider)?;
/// println!("Rotated DID: {}", result.controller_did);
/// println!("New key:  {}...", result.new_key_fingerprint);
/// println!("Old key:  {}...", result.previous_key_fingerprint);
/// ```
#[derive(Debug, Clone)]
pub struct IdentityRotationResult {
    /// The controller DID of the rotated identity.
    pub controller_did: IdentityDID,
    /// Hex-encoded fingerprint of the new signing key.
    pub new_key_fingerprint: String,
    /// Hex-encoded fingerprint of the previous signing key.
    pub previous_key_fingerprint: String,
    /// KERI sequence number after this rotation event.
    pub sequence: u64,
}

/// Outcome of a successful device authorization extension.
///
/// Usage:
/// ```ignore
/// let result: DeviceExtensionResult = extend_device(config, &ctx, &SystemClock)?;
/// println!("Extended {} until {}", result.device_did, result.new_expires_at.date_naive());
/// ```
#[derive(Debug, Clone)]
pub struct DeviceExtensionResult {
    /// The DID of the device whose authorization was extended.
    pub device_did: DeviceDID,
    /// The new expiration timestamp for the device authorization.
    pub new_expires_at: chrono::DateTime<chrono::Utc>,
    /// The previous expiration timestamp (None if the device had no expiry set).
    pub previous_expires_at: Option<chrono::DateTime<chrono::Utc>>,
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
