use auths_core::storage::keychain::{IdentityDID, KeyAlias};
use auths_verifier::Capability;
use auths_verifier::core::ResourceId;
use auths_verifier::types::DeviceDID;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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
///     println!("Agent {:?} delegated by {:?}", r.agent_did, r.parent_did);
/// }
/// ```
#[derive(Debug, Clone)]
pub struct AgentIdentityResult {
    /// The DID of the newly created agent identity (None for dry-run proposals).
    pub agent_did: Option<IdentityDID>,
    /// The DID of the parent identity that delegated authority (None if no parent).
    pub parent_did: Option<IdentityDID>,
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
///     println!("Registered {} at {}", reg.did, reg.registry);
/// }
/// ```
#[derive(Debug, Clone)]
pub struct RegistrationOutcome {
    /// The DID returned by the registry (e.g. `did:keri:EABC...`).
    pub did: IdentityDID,
    /// The registry URL where the identity was registered.
    pub registry: String,
    /// Number of platform claims indexed by the registry.
    pub platform_claims_indexed: usize,
}

/// Device readiness status for diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceReadiness {
    /// Device is valid and not expiring soon.
    Ok,
    /// Device is expiring within 7 days.
    ExpiringSoon,
    /// Device authorization has expired.
    Expired,
    /// Device has been revoked.
    Revoked,
}

/// Per-device status for reporting.
///
/// Usage:
/// ```ignore
/// for device in report.devices {
///     println!("{}: {}", device.device_did, device.readiness);
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceStatus {
    /// The device DID.
    pub device_did: DeviceDID,
    /// Current device readiness status.
    pub readiness: DeviceReadiness,
    /// Expiration timestamp, if set.
    pub expires_at: Option<DateTime<Utc>>,
    /// Seconds until expiration (RFC 6749 format).
    pub expires_in: Option<i64>,
    /// Revocation timestamp, if revoked.
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Identity status for status report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityStatus {
    /// The controller DID.
    pub controller_did: IdentityDID,
    /// Key aliases available in keychain.
    pub key_aliases: Vec<KeyAlias>,
}

/// Agent status for status report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStatus {
    /// Whether the agent is currently running.
    pub running: bool,
    /// Process ID if running.
    pub pid: Option<u32>,
    /// Socket path if running.
    pub socket_path: Option<String>,
}

/// Next step recommendation for users.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NextStep {
    /// Summary of what to do.
    pub summary: String,
    /// Command to run.
    pub command: String,
}

/// Full status report combining identity, devices, and agent state.
///
/// Usage:
/// ```ignore
/// let report = StatusWorkflow::query(&ctx, now)?;
/// println!("Identity: {}", report.identity.controller_did);
/// println!("Devices: {} linked", report.devices.len());
/// for step in report.next_steps {
///     println!("Try: {}", step.command);
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusReport {
    /// Current identity status, if initialized.
    pub identity: Option<IdentityStatus>,
    /// Per-device authorization status.
    pub devices: Vec<DeviceStatus>,
    /// Agent/SSH-agent status.
    pub agent: AgentStatus,
    /// Suggested next steps for the user.
    pub next_steps: Vec<NextStep>,
}
