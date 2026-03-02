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

use chrono::{DateTime, Utc};
use thiserror::Error;

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
    Verified { reason: String },

    /// Signer is rejected by policy.
    Rejected { reason: String },

    /// Signer is allowed but flagged (observe mode or indeterminate).
    Warn { reason: String },

    /// Insufficient local state to make a decision.
    ///
    /// The identity repo needs fetching before a decision can be made.
    /// In observe mode, this scenario is downgraded to `Warn`.
    Quarantine {
        reason: String,
        /// The RID of the identity repo to fetch, if known.
        identity_repo_rid: Option<String>,
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

    /// Returns the reason string.
    pub fn reason(&self) -> &str {
        match self {
            Self::Verified { reason }
            | Self::Rejected { reason }
            | Self::Warn { reason }
            | Self::Quarantine { reason, .. } => reason,
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
///     signer_key: &key_bytes,
///     repo_id: "rad:z3gqabc",
///     now: Utc::now(),
///     mode: EnforcementMode::Enforce,
///     known_remote_tip: None,
///     min_kel_seq: None,
///     required_capability: None,
/// };
/// let result = bridge.verify_signer(&request)?;
/// ```
pub struct VerifyRequest<'a> {
    /// The Ed25519 public key that signed the update (32 bytes).
    pub signer_key: &'a [u8; 32],
    /// The Radicle repository ID (for scoped identity lookup).
    pub repo_id: &'a str,
    /// Current time for checking attestation expiry.
    pub now: DateTime<Utc>,
    /// Enforcement mode (observe vs enforce).
    pub mode: EnforcementMode,
    /// Gossip-announced tip OID of the identity repo, if known.
    /// Used for staleness detection.
    pub known_remote_tip: Option<[u8; 20]>,
    /// Minimum KEL sequence from the project binding.
    /// A binding integrity check — NOT a freshness heuristic.
    pub min_kel_seq: Option<u64>,
    /// Required capability (e.g. "sign_commit", "sign_release").
    pub required_capability: Option<&'a str>,
}

/// Error type for bridge operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BridgeError {
    /// Identity repo missing or unreadable. Actionable: "fetch identity repo X".
    #[error("failed to load identity: {0}")]
    IdentityLoad(String),

    /// Failed to load attestation for device.
    #[error("failed to load attestation: {0}")]
    AttestationLoad(String),

    /// Identity is corrupt — KEL validation failed, broken chain, etc.
    /// Not actionable by fetching. Needs investigation.
    #[error("identity is corrupt: {0}")]
    IdentityCorrupt(String),

    /// Policy evaluation failed (internal error, not a policy denial).
    #[error("policy evaluation failed: {0}")]
    PolicyEvaluation(String),

    /// Invalid device key format.
    #[error("invalid device key: {0}")]
    InvalidDeviceKey(String),

    /// Repository access error.
    #[error("repository error: {0}")]
    Repository(String),
}

/// Bridge between Radicle and Auths.
///
/// This trait defines the adapter boundary. Implementations:
/// 1. Accept raw Ed25519 keys and repository IDs (no Heartwood type imports)
/// 2. Load Auths data (identities, attestations)
/// 3. Evaluate against Auths policy engine
/// 4. Return verification results
///
/// Usage:
/// ```ignore
/// use auths_radicle::bridge::{RadicleAuthsBridge, VerifyRequest, EnforcementMode};
///
/// let request = VerifyRequest {
///     signer_key: &key_bytes,
///     repo_id: "rad:z3gqabc",
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
    ///
    /// Converts Radicle's Ed25519 public key format to Auths' `did:key:z...` format.
    fn device_did(&self, key_bytes: &[u8; 32]) -> String;

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
    /// * `device_did`: The device's DID (`did:key:z6Mk...`).
    /// * `repo_id`: The project repository ID for scoped lookup.
    ///
    /// Usage:
    /// ```ignore
    /// let identity = bridge.find_identity_for_device("did:key:z6Mk...", "rad:z3gq...")?;
    /// ```
    fn find_identity_for_device(
        &self,
        device_did: &str,
        repo_id: &str,
    ) -> Result<Option<String>, BridgeError>;
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
    PreVerified(VerifyResult),
    /// `Did::Keri` signer needing bridge verification.
    NeedsBridgeVerification([u8; 32]),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_result_is_allowed() {
        assert!(
            VerifyResult::Verified {
                reason: "ok".into()
            }
            .is_allowed()
        );
        assert!(
            VerifyResult::Warn {
                reason: "warn".into()
            }
            .is_allowed()
        );
        assert!(
            !VerifyResult::Rejected {
                reason: "no".into()
            }
            .is_allowed()
        );
        assert!(
            !VerifyResult::Quarantine {
                reason: "fetch".into(),
                identity_repo_rid: None,
            }
            .is_allowed()
        );
    }

    #[test]
    fn verify_result_is_rejected() {
        assert!(
            !VerifyResult::Verified {
                reason: "ok".into()
            }
            .is_rejected()
        );
        assert!(
            !VerifyResult::Warn {
                reason: "warn".into()
            }
            .is_rejected()
        );
        assert!(
            VerifyResult::Rejected {
                reason: "no".into()
            }
            .is_rejected()
        );
        assert!(
            !VerifyResult::Quarantine {
                reason: "q".into(),
                identity_repo_rid: None,
            }
            .is_rejected()
        );
    }

    #[test]
    fn verify_result_reason() {
        assert_eq!(
            VerifyResult::Verified {
                reason: "test".into()
            }
            .reason(),
            "test"
        );
        assert_eq!(
            VerifyResult::Quarantine {
                reason: "fetch me".into(),
                identity_repo_rid: Some("rad:z3gq".into()),
            }
            .reason(),
            "fetch me"
        );
    }

    #[test]
    fn enforcement_mode_default_is_enforce() {
        assert_eq!(EnforcementMode::default(), EnforcementMode::Enforce);
    }
}
