//! Radicle-Auths bridge trait and types.
//!
//! Defines the boundary between Radicle and Auths. This adapter layer:
//! - Accepts Radicle types as input (commits, keys, repositories)
//! - Consumes Auths APIs internally (policy engine, attestations)
//! - Returns Auths-compatible verification results
//!
//! # Zero New Crypto
//!
//! This bridge does NOT:
//! - Replace Radicle's signature verification
//! - Introduce new signature formats
//! - Sign commits on behalf of Auths
//!
//! Auths **authorizes**, never signs. Radicle handles all cryptography.

use std::fmt;

use auths_verifier::IdentityDID;
use auths_verifier::types::DeviceDID;
use radicle_core::{Did, RepoId};
use radicle_crypto::PublicKey;
use thiserror::Error;

/// Timestamp type for verification requests.
///
/// With `std`: `chrono::DateTime<chrono::Utc>` (full datetime).
/// Without `std` (WASM): `i64` (Unix epoch seconds).
#[cfg(feature = "std")]
pub type Timestamp = chrono::DateTime<chrono::Utc>;

/// Timestamp type for verification requests (WASM-compatible).
#[cfg(not(feature = "std"))]
pub type Timestamp = i64;

/// Reason a signer was verified (authorized).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifyReason {
    DeviceAttested,
    LegacyDidKey,
    PolicyAllowed { message: String },
}

impl fmt::Display for VerifyReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeviceAttested => write!(f, "device attested"),
            Self::LegacyDidKey => write!(f, "legacy did:key delegate"),
            Self::PolicyAllowed { message } => write!(f, "{message}"),
        }
    }
}

/// Reason a signer was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RejectReason {
    NoAttestation { detail: String },
    KelCorrupt { detail: String },
    InsufficientKelSequence { have: u128, need: u128 },
    MissingCapability { capability: String },
    PolicyDenied { message: String },
    BridgeError { detail: String },
}

impl fmt::Display for RejectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAttestation { detail } => write!(f, "attestation not found: {detail}"),
            Self::KelCorrupt { detail } => write!(f, "identity corrupt: {detail}"),
            Self::InsufficientKelSequence { have, need } => {
                write!(f, "KEL sequence {have} below binding minimum {need}")
            }
            Self::MissingCapability { capability } => {
                write!(f, "device lacks required capability '{capability}'")
            }
            Self::PolicyDenied { message } => write!(f, "{message}"),
            Self::BridgeError { detail } => write!(f, "{detail}"),
        }
    }
}

/// Reason a signer was flagged with a warning.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WarnReason {
    ObserveModeRejection(RejectReason),
    ObserveModeQuarantine(QuarantineReason),
    PolicyIndeterminate { message: String },
}

impl fmt::Display for WarnReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ObserveModeRejection(r) => write!(f, "{r}"),
            Self::ObserveModeQuarantine(r) => write!(f, "{r}"),
            Self::PolicyIndeterminate { message } => write!(f, "{message}"),
        }
    }
}

/// Reason a signer was quarantined (insufficient local state).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum QuarantineReason {
    StaleNode { detail: String },
    MissingIdentityRepo { detail: String },
    NoIdentityFound { detail: String },
}

impl fmt::Display for QuarantineReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StaleNode { detail } => write!(f, "identity repo stale: {detail}"),
            Self::MissingIdentityRepo { detail } => {
                write!(f, "identity repo missing: {detail}")
            }
            Self::NoIdentityFound { detail } => {
                write!(f, "no identity found: {detail}")
            }
        }
    }
}

/// Result of verifying a signer against Auths policy.
///
/// Maps to Radicle's verification expectations:
/// - `Verified` -> Allow the update
/// - `Rejected` -> Block the update
/// - `Warn` -> Allow but flag for review (observe mode)
/// - `Quarantine` -> Insufficient local state to decide (fetch more data)
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifyResult {
    /// Signer is authorized by policy.
    Verified { reason: VerifyReason },

    /// Signer is rejected by policy.
    Rejected { reason: RejectReason },

    /// Signer is allowed but flagged (observe mode or indeterminate).
    Warn { reason: WarnReason },

    /// Insufficient local state to make a decision.
    ///
    /// The identity repo needs fetching before a decision can be made.
    /// In observe mode, this scenario is downgraded to `Warn`.
    Quarantine {
        reason: QuarantineReason,
        /// The RID of the identity repo to fetch, if known.
        identity_repo_rid: Option<RepoId>,
    },
}

impl VerifyResult {
    /// Returns true if the result allows the update.
    ///
    /// `Quarantine` is NOT allowed — it is treated like `Rejected` for callers.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Verified { .. } | Self::Warn { .. })
    }

    /// Returns true if the result rejects the update.
    pub fn is_rejected(&self) -> bool {
        matches!(self, Self::Rejected { .. })
    }

    /// Returns a human-readable reason string (via Display on the typed reason enums).
    pub fn reason(&self) -> String {
        match self {
            Self::Verified { reason } => reason.to_string(),
            Self::Rejected { reason } => reason.to_string(),
            Self::Warn { reason } => reason.to_string(),
            Self::Quarantine { reason, .. } => reason.to_string(),
        }
    }
}

/// Enforcement mode for the bridge.
///
/// Controls how the bridge handles rejection and missing state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum EnforcementMode {
    /// Detection-and-flagging only. Rejections are downgraded to warnings.
    /// The bridge never blocks updates.
    Observe,

    /// Hard authorization boundary. Rejections block updates.
    /// Missing identity state produces `Quarantine`.
    #[default]
    Enforce,
}

/// All parameters needed to verify a signer.
///
/// Bundles the verification request to avoid 8-parameter functions.
/// This struct is the contract between Heartwood's `CompositeAuthorityChecker`
/// and the auths bridge.
///
/// Usage:
/// ```ignore
/// let request = VerifyRequest {
///     signer_key: &key,
///     repo_id: &rid,
///     now: Utc::now(),
///     mode: EnforcementMode::Enforce,
///     known_remote_tip: None,
///     min_kel_seq: None,
///     required_capability: None,
/// };
/// let result = bridge.verify_signer(&request)?;
/// ```
pub struct VerifyRequest<'a> {
    /// The Ed25519 public key that signed the update.
    pub signer_key: &'a PublicKey,
    /// The Radicle repository ID (for scoped identity lookup).
    pub repo_id: &'a RepoId,
    /// Current time for checking attestation expiry.
    pub now: Timestamp,
    /// Enforcement mode (observe vs enforce).
    pub mode: EnforcementMode,
    /// Gossip-announced tip OID of the identity repo, if known.
    /// Used for staleness detection.
    pub known_remote_tip: Option<[u8; 20]>,
    /// Minimum KEL sequence from the project binding.
    /// A binding integrity check — NOT a freshness heuristic.
    pub min_kel_seq: Option<u128>,
    /// Required capability (e.g. "sign_commit", "sign_release").
    pub required_capability: Option<&'a str>,
}

/// Error type for bridge operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BridgeError {
    /// Identity repo missing or unreadable. Actionable: "fetch identity repo X".
    #[error("failed to load identity {did}: {reason}")]
    IdentityLoad { did: IdentityDID, reason: String },

    /// Failed to load attestation for device.
    #[error("failed to load attestation for device {device_did}: {reason}")]
    AttestationLoad {
        device_did: DeviceDID,
        reason: String,
    },

    /// Identity is corrupt — KEL validation failed, broken chain, etc.
    /// Not actionable by fetching. Needs investigation.
    #[error("identity {did} has corrupt KEL: {reason}")]
    IdentityCorrupt { did: IdentityDID, reason: String },

    /// Policy evaluation failed (internal error, not a policy denial).
    #[error("policy evaluation failed for {did}: {reason}")]
    PolicyEvaluation { did: IdentityDID, reason: String },

    /// Invalid device key format.
    #[error("invalid device key: {reason}")]
    InvalidDeviceKey { reason: String },

    /// Repository access error.
    #[error("repository access error: {reason}")]
    Repository { reason: String },
}

/// Bridge between Radicle and Auths.
///
/// This trait defines the adapter boundary. Implementations:
/// 1. Accept Radicle types (PublicKey, RepoId)
/// 2. Load Auths data (identities, attestations)
/// 3. Evaluate against Auths policy engine
/// 4. Return verification results
///
/// Usage:
/// ```ignore
/// use auths_radicle::bridge::{RadicleAuthsBridge, VerifyRequest, EnforcementMode};
///
/// let request = VerifyRequest {
///     signer_key: &key,
///     repo_id: &rid,
///     now: Utc::now(),
///     mode: EnforcementMode::Enforce,
///     known_remote_tip: None,
///     min_kel_seq: None,
///     required_capability: None,
/// };
/// let result = bridge.verify_signer(&request)?;
/// ```
pub trait RadicleAuthsBridge: Send + Sync {
    /// Map a Radicle public key to an Auths DeviceDID.
    fn device_did(&self, key: &PublicKey) -> Did;

    /// Verify a signer against Auths policy.
    ///
    /// This method assumes Radicle has already verified the cryptographic signature.
    /// We only check authorization (is this key allowed to sign for this identity?).
    ///
    /// Args:
    /// * `request`: All parameters bundled into a `VerifyRequest`.
    ///
    /// Usage:
    /// ```ignore
    /// let result = bridge.verify_signer(&request)?;
    /// ```
    fn verify_signer(&self, request: &VerifyRequest) -> Result<VerifyResult, BridgeError>;

    /// Find the KERI identity DID controlling a device key in a project.
    ///
    /// Scans the project's DID namespaces to find which identity (if any)
    /// has attested this device.
    ///
    /// Args:
    /// * `device_did`: The device's DID.
    /// * `repo_id`: The project repository ID for scoped lookup.
    ///
    /// Usage:
    /// ```ignore
    /// let identity = bridge.find_identity_for_device(&device_did, &rid)?;
    /// ```
    fn find_identity_for_device(
        &self,
        device_did: &Did,
        repo_id: &RepoId,
    ) -> Result<Option<Did>, BridgeError>;

    /// List all device DIDs that are attested by a given identity in this project.
    fn list_devices(&self, identity_did: &Did) -> Result<Vec<Did>, BridgeError>;
}

/// Input for mixed-delegate threshold verification.
///
/// Radicle supports hybrid delegate sets with both `Did::Key` (legacy nodes)
/// and `Did::Keri` (teams with KERI identities). The bridge only verifies
/// `Did::Keri` signers — `Did::Key` verification results are pre-computed
/// by Heartwood and passed through.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum SignerInput {
    /// `Did::Key` signer already verified by Heartwood's Ed25519 delegate check.
    /// The `did` field carries the `did:key:z6Mk...` for identity deduplication.
    PreVerified {
        /// The legacy device DID (used as the identity DID for grouping).
        did: Did,
        /// The pre-computed verification result.
        result: VerifyResult,
    },
    /// `Did::Keri` signer needing bridge verification.
    NeedsBridgeVerification(PublicKey),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_result_is_allowed() {
        assert!(
            VerifyResult::Verified {
                reason: VerifyReason::DeviceAttested,
            }
            .is_allowed()
        );
        assert!(
            VerifyResult::Warn {
                reason: WarnReason::PolicyIndeterminate {
                    message: "warn".into()
                },
            }
            .is_allowed()
        );
        assert!(
            !VerifyResult::Rejected {
                reason: RejectReason::PolicyDenied {
                    message: "no".into()
                },
            }
            .is_allowed()
        );
        assert!(
            !VerifyResult::Quarantine {
                reason: QuarantineReason::MissingIdentityRepo {
                    detail: "fetch".into()
                },
                identity_repo_rid: None,
            }
            .is_allowed()
        );
    }

    #[test]
    fn verify_result_is_rejected() {
        assert!(
            !VerifyResult::Verified {
                reason: VerifyReason::DeviceAttested,
            }
            .is_rejected()
        );
        assert!(
            !VerifyResult::Warn {
                reason: WarnReason::PolicyIndeterminate {
                    message: "warn".into()
                },
            }
            .is_rejected()
        );
        assert!(
            VerifyResult::Rejected {
                reason: RejectReason::PolicyDenied {
                    message: "no".into()
                },
            }
            .is_rejected()
        );
        assert!(
            !VerifyResult::Quarantine {
                reason: QuarantineReason::MissingIdentityRepo { detail: "q".into() },
                identity_repo_rid: None,
            }
            .is_rejected()
        );
    }

    #[test]
    fn verify_result_reason() {
        assert_eq!(
            VerifyResult::Verified {
                reason: VerifyReason::DeviceAttested,
            }
            .reason(),
            "device attested"
        );
        assert!(
            VerifyResult::Quarantine {
                reason: QuarantineReason::MissingIdentityRepo {
                    detail: "fetch needed".into()
                },
                identity_repo_rid: Some("rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5".parse().unwrap()),
            }
            .reason()
            .contains("fetch needed")
        );
    }

    #[test]
    fn enforcement_mode_default_is_enforce() {
        assert_eq!(EnforcementMode::default(), EnforcementMode::Enforce);
    }
}
