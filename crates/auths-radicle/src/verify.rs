//! Verification flow for Radicle commits.
//!
//! This module implements the verification flow that bridges Radicle's
//! signature verification with Auths' policy engine.
//!
//! # Zero New Crypto
//!
//! **This module does NOT sign anything.** Auths authorizes, never signs.
//!
//! - Radicle handles all Ed25519 signature verification
//! - This module only evaluates policy (is this key authorized?)
//! - No new signature formats are introduced
//!
//! # Flow
//!
//! 1. **Radicle verifies signature** (external, not in this module)
//!    - Cryptographic verification is done by Radicle
//!    - We trust this result
//!
//! 2. **Adapter loads** (this module):
//!    - Identity KEL for signer
//!    - Device attestation for signing key
//!
//! 3. **Adapter calls policy engine**:
//!    - Evaluates attestation against policy
//!
//! 4. **Map result to VerifyResult**:
//!    - `Allow` → `Verified`
//!    - `Deny` → `Rejected`
//!    - `Indeterminate` → `Warn`

use chrono::{DateTime, Utc};

use auths_id::identity::ed25519_to_did_key;
use auths_id::keri::KeyState;
use auths_id::policy::{CompiledPolicy, Decision, Outcome, PolicyBuilder, evaluate_compiled};
use auths_verifier::core::Attestation;

use crate::bridge::{BridgeError, RadicleAuthsBridge, VerifyResult};

/// Default implementation of the Radicle-Auths bridge.
///
/// This struct provides a concrete implementation of [`RadicleAuthsBridge`]
/// that loads identity and attestation data and evaluates against the policy engine.
///
/// # Example
///
/// ```rust,ignore
/// use auths_radicle::verify::DefaultBridge;
/// use auths_radicle::bridge::RadicleAuthsBridge;
///
/// let bridge = DefaultBridge::new(storage, policy);
/// let result = bridge.verify_signer(&signer_key, "repo-id", now)?;
/// ```
pub struct DefaultBridge<S> {
    /// Storage backend for loading identities and attestations.
    storage: S,
    /// Compiled policy to evaluate attestations against.
    policy: CompiledPolicy,
}

impl<S> DefaultBridge<S> {
    /// Creates a new bridge with the given storage and compiled policy.
    pub fn new(storage: S, policy: CompiledPolicy) -> Self {
        Self { storage, policy }
    }

    /// Creates a new bridge with default policy (not_revoked + not_expired).
    pub fn with_storage(storage: S) -> Self {
        Self {
            storage,
            policy: PolicyBuilder::new().not_revoked().not_expired().build(),
        }
    }

    /// Returns a reference to the compiled policy.
    pub fn policy(&self) -> &CompiledPolicy {
        &self.policy
    }
}

/// Trait for loading identity and attestation data.
///
/// This abstraction allows the bridge to work with different storage backends
/// (Git-based, indexed, etc.) without coupling to a specific implementation.
pub trait AuthsStorage: Send + Sync {
    /// Load the key state (identity) for a given DID.
    fn load_key_state(&self, identity_did: &str) -> Result<KeyState, BridgeError>;

    /// Load the device attestation for a given device DID.
    fn load_attestation(&self, device_did: &str) -> Result<Attestation, BridgeError>;

    /// Find the identity DID that controls a given device key.
    ///
    /// This searches for an attestation where the device's public key matches,
    /// then returns the issuer (identity) DID.
    fn find_identity_for_device(&self, device_did: &str) -> Result<String, BridgeError>;
}

impl<S: AuthsStorage> RadicleAuthsBridge for DefaultBridge<S> {
    fn device_did(&self, key_bytes: &[u8; 32]) -> String {
        ed25519_to_did_key(key_bytes)
    }

    fn verify_signer(
        &self,
        signer_key: &[u8; 32],
        _repo_id: &str,
        now: DateTime<Utc>,
    ) -> Result<VerifyResult, BridgeError> {
        // Step 1: Convert signer key to DeviceDID
        let device_did = self.device_did(signer_key);

        // Step 2: Find the identity that controls this device
        let identity_did = self.storage.find_identity_for_device(&device_did)?;

        // Step 3: Load attestation (key_state not needed for current policy evaluation)
        let _key_state = self.storage.load_key_state(&identity_did)?;
        let attestation = self.storage.load_attestation(&device_did)?;

        // Step 4: Evaluate policy
        let decision = evaluate_compiled(&attestation, &self.policy, now);

        // Step 5: Map decision to VerifyResult
        Ok(decision_to_verify_result(decision))
    }
}

/// Maps a policy [`Decision`] to a [`VerifyResult`].
pub fn decision_to_verify_result(decision: Decision) -> VerifyResult {
    match decision.outcome {
        Outcome::Allow => VerifyResult::Verified {
            reason: decision.message,
        },
        Outcome::Deny => VerifyResult::Rejected {
            reason: decision.message,
        },
        Outcome::Indeterminate => VerifyResult::Warn {
            reason: decision.message,
        },
    }
}

/// Verify multiple signers (for threshold identities).
///
/// Radicle supports threshold identities (e.g., 2-of-3). This function
/// checks all signers against the policy and returns results for each.
///
/// # Arguments
///
/// * `bridge` - The bridge implementation
/// * `signer_keys` - All Ed25519 public keys that signed
/// * `repo_id` - Repository identifier
/// * `now` - Current time
///
/// # Returns
///
/// A vector of results, one per signer. The caller can then apply
/// threshold logic (e.g., "at least M of N must be Verified").
pub fn verify_multiple_signers<B: RadicleAuthsBridge>(
    bridge: &B,
    signer_keys: &[[u8; 32]],
    repo_id: &str,
    now: DateTime<Utc>,
) -> Vec<Result<VerifyResult, BridgeError>> {
    signer_keys
        .iter()
        .map(|key| bridge.verify_signer(key, repo_id, now))
        .collect()
}

/// Check if enough signers are verified for a threshold.
///
/// # Arguments
///
/// * `results` - Results from `verify_multiple_signers`
/// * `threshold` - Minimum number of verified signers required
///
/// # Returns
///
/// `true` if at least `threshold` signers are `Verified` or `Warn`.
pub fn meets_threshold(results: &[Result<VerifyResult, BridgeError>], threshold: usize) -> bool {
    let verified_count = results
        .iter()
        .filter(|r| matches!(r, Ok(v) if v.is_allowed()))
        .count();
    verified_count >= threshold
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_verifier::IdentityDID;
    use auths_verifier::keri::{Prefix, Said};
    use std::collections::HashMap;

    /// Mock storage for testing.
    struct MockStorage {
        key_states: HashMap<String, KeyState>,
        attestations: HashMap<String, Attestation>,
        device_to_identity: HashMap<String, String>,
    }

    impl MockStorage {
        fn new() -> Self {
            Self {
                key_states: HashMap::new(),
                attestations: HashMap::new(),
                device_to_identity: HashMap::new(),
            }
        }

        fn add_identity(&mut self, identity_did: &str, key_state: KeyState) {
            self.key_states.insert(identity_did.to_string(), key_state);
        }

        fn add_attestation(&mut self, device_did: &str, attestation: Attestation) {
            self.attestations
                .insert(device_did.to_string(), attestation);
        }

        fn link_device_to_identity(&mut self, device_did: &str, identity_did: &str) {
            self.device_to_identity
                .insert(device_did.to_string(), identity_did.to_string());
        }
    }

    impl AuthsStorage for MockStorage {
        fn load_key_state(&self, identity_did: &str) -> Result<KeyState, BridgeError> {
            self.key_states
                .get(identity_did)
                .cloned()
                .ok_or_else(|| BridgeError::IdentityLoad(format!("Not found: {}", identity_did)))
        }

        fn load_attestation(&self, device_did: &str) -> Result<Attestation, BridgeError> {
            self.attestations
                .get(device_did)
                .cloned()
                .ok_or_else(|| BridgeError::AttestationLoad(format!("Not found: {}", device_did)))
        }

        fn find_identity_for_device(&self, device_did: &str) -> Result<String, BridgeError> {
            self.device_to_identity
                .get(device_did)
                .cloned()
                .ok_or_else(|| {
                    BridgeError::InvalidDeviceKey(format!("No identity for device: {}", device_did))
                })
        }
    }

    fn make_key_state(prefix: &str) -> KeyState {
        KeyState {
            prefix: Prefix::new_unchecked(prefix.to_string()),
            sequence: 0,
            current_keys: vec!["DTestKey".to_string()],
            next_commitment: vec![],
            last_event_said: Said::new_unchecked("ETestSaid".to_string()),
            is_abandoned: false,
        }
    }

    fn make_attestation(
        issuer: &str,
        device_did: &str,
        revoked_at: Option<DateTime<Utc>>,
    ) -> Attestation {
        use auths_verifier::types::DeviceDID;

        Attestation {
            version: 1,
            rid: "test".to_string(),
            issuer: IdentityDID::new(issuer),
            subject: DeviceDID::new(device_did),
            device_public_key: vec![0; 32],
            identity_signature: vec![0; 64],
            device_signature: vec![0; 64],
            revoked_at,
            expires_at: None,
            timestamp: None,
            note: None,
            payload: None,
            role: None,
            capabilities: vec![],
            delegated_by: None,
            signer_type: None,
        }
    }

    #[test]
    fn test_verify_valid_signer() {
        let mut storage = MockStorage::new();

        // Create a test key (32 bytes)
        let signer_key: [u8; 32] = [1; 32];
        let device_did = ed25519_to_did_key(&signer_key);
        let identity_did = "did:keri:ETestPrefix";

        // Setup storage
        storage.add_identity(identity_did, make_key_state("ETestPrefix"));
        storage.add_attestation(
            &device_did,
            make_attestation(identity_did, &device_did, None),
        );
        storage.link_device_to_identity(&device_did, identity_did);

        // Create bridge and verify
        let bridge = DefaultBridge::with_storage(storage);
        let result = bridge.verify_signer(&signer_key, "test-repo", Utc::now());

        assert!(result.is_ok());
        assert!(result.unwrap().is_allowed());
    }

    #[test]
    fn test_verify_revoked_attestation() {
        let mut storage = MockStorage::new();

        let signer_key: [u8; 32] = [2; 32];
        let device_did = ed25519_to_did_key(&signer_key);
        let identity_did = "did:keri:ETestPrefix";

        storage.add_identity(identity_did, make_key_state("ETestPrefix"));
        storage.add_attestation(
            &device_did,
            make_attestation(identity_did, &device_did, Some(Utc::now())),
        ); // revoked!
        storage.link_device_to_identity(&device_did, identity_did);

        let bridge = DefaultBridge::with_storage(storage);
        let result = bridge.verify_signer(&signer_key, "test-repo", Utc::now());

        assert!(result.is_ok());
        assert!(result.unwrap().is_rejected());
    }

    #[test]
    fn test_verify_unknown_device() {
        let storage = MockStorage::new();
        let signer_key: [u8; 32] = [3; 32];

        let bridge = DefaultBridge::with_storage(storage);
        let result = bridge.verify_signer(&signer_key, "test-repo", Utc::now());

        assert!(result.is_err());
        assert!(matches!(result, Err(BridgeError::InvalidDeviceKey(_))));
    }

    #[test]
    fn test_decision_to_verify_result_mapping() {
        use auths_id::policy::ReasonCode;

        assert!(matches!(
            decision_to_verify_result(Decision::allow(ReasonCode::AllChecksPassed, "ok")),
            VerifyResult::Verified { .. }
        ));
        assert!(matches!(
            decision_to_verify_result(Decision::deny(ReasonCode::Revoked, "no")),
            VerifyResult::Rejected { .. }
        ));
        assert!(matches!(
            decision_to_verify_result(Decision::indeterminate(ReasonCode::MissingField, "maybe")),
            VerifyResult::Warn { .. }
        ));
    }

    #[test]
    fn test_verify_multiple_signers() {
        let mut storage = MockStorage::new();
        let identity_did = "did:keri:ETestPrefix";
        storage.add_identity(identity_did, make_key_state("ETestPrefix"));

        // Add two valid signers
        let key1: [u8; 32] = [10; 32];
        let key2: [u8; 32] = [20; 32];
        let did1 = ed25519_to_did_key(&key1);
        let did2 = ed25519_to_did_key(&key2);

        storage.add_attestation(&did1, make_attestation(identity_did, &did1, None));
        storage.add_attestation(&did2, make_attestation(identity_did, &did2, None));
        storage.link_device_to_identity(&did1, identity_did);
        storage.link_device_to_identity(&did2, identity_did);

        let bridge = DefaultBridge::with_storage(storage);
        let results = verify_multiple_signers(&bridge, &[key1, key2], "test-repo", Utc::now());

        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.as_ref().unwrap().is_allowed()));
    }

    #[test]
    fn test_meets_threshold() {
        let results = vec![
            Ok(VerifyResult::Verified {
                reason: "ok".into(),
            }),
            Ok(VerifyResult::Rejected {
                reason: "no".into(),
            }),
            Ok(VerifyResult::Verified {
                reason: "ok".into(),
            }),
        ];

        assert!(meets_threshold(&results, 2)); // 2 verified, threshold 2
        assert!(!meets_threshold(&results, 3)); // 2 verified, threshold 3
        assert!(meets_threshold(&results, 1)); // 2 verified, threshold 1
    }

    #[test]
    fn test_device_did_format() {
        let key: [u8; 32] = [0xAB; 32];
        let bridge = DefaultBridge::with_storage(MockStorage::new());
        let did = bridge.device_did(&key);

        assert!(did.starts_with("did:key:z"));
    }
}
