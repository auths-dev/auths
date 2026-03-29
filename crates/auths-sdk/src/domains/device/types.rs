use auths_core::storage::keychain::KeyAlias;
use auths_verifier::Capability;
use auths_verifier::core::ResourceId;
use auths_verifier::types::DeviceDID;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Configuration for extending a device authorization's expiration.
///
/// Args:
/// * `repo_path`: Path to the auths registry.
/// * `device_did`: The DID of the device whose authorization to extend.
/// * `expires_in`: Duration in seconds until expiration (per RFC 6749).
/// * `identity_key_alias`: Keychain alias for the identity key (for re-signing).
/// * `device_key_alias`: Keychain alias for the device key (for re-signing).
///
/// Usage:
/// ```ignore
/// let config = DeviceExtensionConfig {
///     repo_path: PathBuf::from("/home/user/.auths"),
///     device_did: "did:key:z6Mk...".into(),
///     expires_in: 31_536_000,
///     identity_key_alias: "my-identity".into(),
///     device_key_alias: "my-device".into(),
/// };
/// ```
#[derive(Debug)]
pub struct DeviceExtensionConfig {
    /// Path to the auths registry.
    pub repo_path: PathBuf,
    /// DID of the device whose authorization to extend.
    pub device_did: DeviceDID,
    /// Duration in seconds until expiration (per RFC 6749).
    pub expires_in: u64,
    /// Keychain alias for the identity signing key.
    pub identity_key_alias: KeyAlias,
    /// Keychain alias for the device signing key (pass `None` to skip device co-signing).
    pub device_key_alias: Option<KeyAlias>,
}

/// Configuration for linking a device to an existing identity.
///
/// Args:
/// * `identity_key_alias`: Alias of the identity key in the keychain.
///
/// Usage:
/// ```ignore
/// let config = DeviceLinkConfig {
///     identity_key_alias: "my-identity".into(),
///     device_key_alias: Some("macbook-pro".into()),
///     device_did: None,
///     capabilities: vec!["sign-commit".into()],
///     expires_in: Some(31_536_000),
///     note: Some("Work laptop".into()),
///     payload: None,
/// };
/// ```
#[derive(Debug)]
pub struct DeviceLinkConfig {
    /// Alias of the identity key in the keychain.
    pub identity_key_alias: KeyAlias,
    /// Optional alias for the device key (defaults to identity alias).
    pub device_key_alias: Option<KeyAlias>,
    /// Optional pre-existing device DID (not yet supported).
    pub device_did: Option<String>,
    /// Capabilities to grant to the linked device.
    pub capabilities: Vec<Capability>,
    /// Duration in seconds until expiration (per RFC 6749).
    pub expires_in: Option<u64>,
    /// Optional human-readable note for the attestation.
    pub note: Option<String>,
    /// Optional JSON payload to embed in the attestation.
    pub payload: Option<serde_json::Value>,
}

// Result types

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
