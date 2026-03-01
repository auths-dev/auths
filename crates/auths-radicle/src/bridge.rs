//! Radicle-Auths bridge trait.
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

/// Result of verifying a commit against Auths policy.
///
/// Maps to Radicle's verification expectations:
/// - `Verified` → Allow the commit
/// - `Rejected` → Block the commit
/// - `Warn` → Allow but flag for review (optional)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyResult {
    /// Commit is authorized by policy.
    Verified {
        /// Human-readable reason for verification.
        reason: String,
    },
    /// Commit is rejected by policy.
    Rejected {
        /// Human-readable reason for rejection.
        reason: String,
    },
    /// Commit is allowed but flagged (policy returned Indeterminate).
    Warn {
        /// Human-readable warning message.
        reason: String,
    },
}

impl VerifyResult {
    /// Returns true if the result allows the commit.
    pub fn is_allowed(&self) -> bool {
        matches!(
            self,
            VerifyResult::Verified { .. } | VerifyResult::Warn { .. }
        )
    }

    /// Returns true if the result rejects the commit.
    pub fn is_rejected(&self) -> bool {
        matches!(self, VerifyResult::Rejected { .. })
    }

    /// Returns the reason string.
    pub fn reason(&self) -> &str {
        match self {
            VerifyResult::Verified { reason } => reason,
            VerifyResult::Rejected { reason } => reason,
            VerifyResult::Warn { reason } => reason,
        }
    }
}

/// Error type for bridge operations.
#[derive(Debug, Error)]
pub enum BridgeError {
    /// Failed to load identity.
    #[error("failed to load identity: {0}")]
    IdentityLoad(String),

    /// Failed to load attestation.
    #[error("failed to load attestation: {0}")]
    AttestationLoad(String),

    /// Policy evaluation failed.
    #[error("policy evaluation failed: {0}")]
    PolicyEvaluation(String),

    /// Invalid device key.
    #[error("invalid device key: {0}")]
    InvalidDeviceKey(String),

    /// Repository access error.
    #[error("repository error: {0}")]
    Repository(String),
}

/// Bridge between Radicle and Auths.
///
/// This trait defines the adapter boundary. Implementations:
/// 1. Accept Radicle types (commits, keys, repositories)
/// 2. Load Auths data (identities, attestations)
/// 3. Evaluate against Auths policy engine
/// 4. Return verification results
///
/// # Example (with heartwood feature)
///
/// ```ignore
/// use auths_radicle::bridge::RadicleAuthsBridge;
///
/// let bridge = DefaultBridge::new(auths_storage, policy);
/// let result = bridge.verify_commit(&commit, now)?;
/// match result {
///     VerifyResult::Verified { reason } => println!("Allowed: {}", reason),
///     VerifyResult::Rejected { reason } => println!("Blocked: {}", reason),
///     VerifyResult::Warn { reason } => println!("Warning: {}", reason),
/// }
/// ```
pub trait RadicleAuthsBridge: Send + Sync {
    /// Map a Radicle public key to an Auths DeviceDID.
    ///
    /// Converts Radicle's Ed25519 public key format to Auths' `did:key:z...` format.
    fn device_did(&self, key_bytes: &[u8; 32]) -> String;

    /// Verify a commit against Auths policy.
    ///
    /// This method assumes Radicle has already verified the cryptographic signature.
    /// We only check authorization (is this key allowed to sign for this identity?).
    ///
    /// # Arguments
    ///
    /// * `signer_key` - The Ed25519 public key that signed the commit (32 bytes)
    /// * `repo_id` - The Radicle repository ID (for loading identity/attestations)
    /// * `now` - Current time for checking attestation expiry
    ///
    /// # Returns
    ///
    /// * `VerifyResult::Verified` - Policy allows this key to sign
    /// * `VerifyResult::Rejected` - Policy denies this key
    /// * `VerifyResult::Warn` - Policy is indeterminate (allow with warning)
    fn verify_signer(
        &self,
        signer_key: &[u8; 32],
        repo_id: &str,
        now: DateTime<Utc>,
    ) -> Result<VerifyResult, BridgeError>;
}

// Note: Heartwood-specific bridge trait is not included here due to sqlite
// library conflicts. When integrating with Radicle's native types, consumers
// should implement RadicleAuthsBridge and convert Radicle types to bytes:
//
// ```ignore
// impl RadicleAuthsBridge for MyBridge {
//     fn device_did(&self, key_bytes: &[u8; 32]) -> String {
//         // Convert to did:key format
//     }
//
//     fn verify_signer(&self, signer_key: &[u8; 32], repo_id: &str, now: DateTime<Utc>)
//         -> Result<VerifyResult, BridgeError>
//     {
//         // Load identity and attestation, evaluate policy
//     }
// }
//
// // Usage with Radicle types:
// let key_bytes: [u8; 32] = radicle_public_key.as_ref().try_into()?;
// let result = bridge.verify_signer(&key_bytes, &repo_id.to_string(), now)?;
// ```

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_result_is_allowed() {
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
    }

    #[test]
    fn test_verify_result_is_rejected() {
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
    }

    #[test]
    fn test_verify_result_reason() {
        assert_eq!(
            VerifyResult::Verified {
                reason: "test".into()
            }
            .reason(),
            "test"
        );
    }
}
