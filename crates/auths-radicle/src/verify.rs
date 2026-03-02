//! Verification flow for Radicle commits.
//!
//! Implements the full authorization pipeline:
//! 1. DID translation (Ed25519 key → `did:key`)
//! 2. Identity lookup (find KERI identity for device)
//! 3. Binding integrity check (`min_kel_seq`)
//! 4. Staleness detection (gossip-informed tip comparison)
//! 5. Attestation verification (2-way signatures)
//! 6. Policy evaluation (revocation, expiry, capabilities)
//! 7. Mode-dependent result mapping (observe vs enforce)
//!
//! # Fail-Closed Design
//!
//! Any unhandled error in the pipeline produces `Rejected`, never `Verified`.
//! The only path to `Verified` is a complete successful evaluation.

use std::collections::BTreeMap;

use auths_id::identity::ed25519_to_did_key;
use auths_id::keri::KeyState;
use auths_id::policy::{CompiledPolicy, Decision, Outcome, PolicyBuilder, evaluate_compiled};
use auths_verifier::core::Attestation;

use crate::bridge::{
    BridgeError, EnforcementMode, RadicleAuthsBridge, SignerInput, VerifyRequest, VerifyResult,
};

/// An identity-level DID used for threshold deduplication.
///
/// For `did:keri:` signers, this is the controller identity DID (all devices
/// under the same identity share one `IdentityDid`). For legacy `did:key:`
/// signers, the device DID itself is the identity DID (one device = one vote).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IdentityDid(String);

impl IdentityDid {
    /// Creates a new `IdentityDid` from a DID string.
    pub fn new(did: impl Into<String>) -> Self {
        Self(did.into())
    }

    /// Returns the DID string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for IdentityDid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Default implementation of the Radicle-Auths bridge.
///
/// Generic over storage backend, allowing both real Git-backed storage
/// and mock storage for testing.
///
/// Usage:
/// ```ignore
/// let bridge = DefaultBridge::with_storage(storage);
/// let result = bridge.verify_signer(&request)?;
/// ```
pub struct DefaultBridge<S> {
    storage: S,
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
/// (Git-based, indexed, cached) without coupling to a specific implementation.
/// The trait signature is designed so that future implementations can add caching
/// (e.g., local SQLite index) without changing the trait contract.
pub trait AuthsStorage: Send + Sync {
    /// Load the key state (identity) for a given DID.
    fn load_key_state(&self, identity_did: &str) -> Result<KeyState, BridgeError>;

    /// Load the device attestation for a given device DID under an identity.
    fn load_attestation(
        &self,
        device_did: &str,
        identity_did: &str,
    ) -> Result<Attestation, BridgeError>;

    /// Find the identity DID that controls a given device key within a project.
    ///
    /// Returns `None` if the device is not attested under any identity in this project.
    fn find_identity_for_device(
        &self,
        device_did: &str,
        repo_id: &str,
    ) -> Result<Option<String>, BridgeError>;

    /// Get the local tip OID of an identity repo.
    ///
    /// Returns `None` if the identity repo is not available locally.
    fn local_identity_tip(&self, identity_did: &str) -> Result<Option<[u8; 20]>, BridgeError>;
}

impl<S: AuthsStorage> RadicleAuthsBridge for DefaultBridge<S> {
    fn device_did(&self, key_bytes: &[u8; 32]) -> String {
        ed25519_to_did_key(key_bytes)
    }

    fn verify_signer(&self, request: &VerifyRequest) -> Result<VerifyResult, BridgeError> {
        let device_did = self.device_did(request.signer_key);

        // Step 1: Find the identity that controls this device
        let identity_did = match self
            .storage
            .find_identity_for_device(&device_did, request.repo_id)?
        {
            Some(did) => did,
            None => {
                return Ok(match request.mode {
                    EnforcementMode::Observe => VerifyResult::Warn {
                        reason: format!("no identity found for device {device_did}"),
                    },
                    EnforcementMode::Enforce => VerifyResult::Quarantine {
                        reason: format!("no identity found for device {device_did}"),
                        identity_repo_rid: None,
                    },
                });
            }
        };

        // Step 2: Load key state
        let key_state = match self.storage.load_key_state(&identity_did) {
            Ok(ks) => ks,
            Err(BridgeError::IdentityLoad(msg)) => {
                return Ok(match request.mode {
                    EnforcementMode::Observe => VerifyResult::Warn {
                        reason: format!("identity repo missing: {msg}"),
                    },
                    EnforcementMode::Enforce => VerifyResult::Quarantine {
                        reason: format!("identity repo missing: {msg}"),
                        identity_repo_rid: Some(identity_did),
                    },
                });
            }
            Err(BridgeError::IdentityCorrupt(msg)) => {
                // Corrupt identity is always rejected, never downgraded
                return Ok(VerifyResult::Rejected {
                    reason: format!("identity corrupt: {msg}"),
                });
            }
            Err(e) => return Err(e),
        };

        // Step 3: Binding integrity — min_kel_seq check BEFORE policy evaluation.
        // A KEL below the binding minimum is a tamper indicator: hard reject in ALL modes.
        if let Some(min_seq) = request.min_kel_seq
            && key_state.sequence < min_seq
        {
            return Ok(VerifyResult::Rejected {
                reason: format!(
                    "KEL sequence {} below binding minimum {min_seq} for {identity_did}",
                    key_state.sequence
                ),
            });
        }

        // Step 4: Staleness detection — gossip-informed tip comparison.
        if let Some(remote_tip) = request.known_remote_tip {
            match self.storage.local_identity_tip(&identity_did)? {
                Some(local_tip) if local_tip != remote_tip => {
                    return Ok(match request.mode {
                        EnforcementMode::Observe => VerifyResult::Warn {
                            reason: format!("identity repo {identity_did} has newer tip available"),
                        },
                        EnforcementMode::Enforce => VerifyResult::Quarantine {
                            reason: format!(
                                "identity repo {identity_did} is stale (local tip differs from gossip)"
                            ),
                            identity_repo_rid: Some(identity_did),
                        },
                    });
                }
                None => {
                    // Identity repo missing but we have a remote tip — stale
                    return Ok(match request.mode {
                        EnforcementMode::Observe => VerifyResult::Warn {
                            reason: format!("identity repo {identity_did} not available locally"),
                        },
                        EnforcementMode::Enforce => VerifyResult::Quarantine {
                            reason: format!("identity repo {identity_did} not available locally"),
                            identity_repo_rid: Some(identity_did),
                        },
                    });
                }
                _ => {} // local == remote, no staleness
            }
        }

        // Step 5: Load attestation
        let attestation = match self.storage.load_attestation(&device_did, &identity_did) {
            Ok(att) => att,
            Err(BridgeError::AttestationLoad(msg)) => {
                return Ok(apply_mode(
                    request.mode,
                    VerifyResult::Rejected {
                        reason: format!("attestation not found: {msg}"),
                    },
                    None,
                ));
            }
            Err(e) => return Err(e),
        };

        // Step 6: Evaluate policy (revocation, expiry)
        let decision = evaluate_compiled(&attestation, &self.policy, request.now);

        // Step 7: Capability check
        if let Some(required_cap) = request.required_capability
            && decision.outcome == Outcome::Allow
        {
            let has_cap = attestation
                .capabilities
                .iter()
                .any(|c| c.to_string() == required_cap);
            if !has_cap && !attestation.capabilities.is_empty() {
                return Ok(apply_mode(
                    request.mode,
                    VerifyResult::Rejected {
                        reason: format!("device lacks required capability '{required_cap}'"),
                    },
                    None,
                ));
            }
        }

        // Step 8: Map decision to VerifyResult with mode
        let result = decision_to_verify_result(decision);
        Ok(apply_mode(request.mode, result, None))
    }

    fn find_identity_for_device(
        &self,
        device_did: &str,
        repo_id: &str,
    ) -> Result<Option<String>, BridgeError> {
        self.storage.find_identity_for_device(device_did, repo_id)
    }
}

/// Apply enforcement mode to a VerifyResult.
///
/// In Observe mode, `Rejected` is downgraded to `Warn`.
/// `Verified` and `Warn` pass through unchanged.
/// `Quarantine` stays as-is in Enforce, downgraded to `Warn` in Observe.
fn apply_mode(
    mode: EnforcementMode,
    result: VerifyResult,
    _identity_repo_rid: Option<String>,
) -> VerifyResult {
    match mode {
        EnforcementMode::Enforce => result,
        EnforcementMode::Observe => match result {
            VerifyResult::Rejected { reason } => VerifyResult::Warn { reason },
            VerifyResult::Quarantine { reason, .. } => VerifyResult::Warn { reason },
            other => other,
        },
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

/// Verify a mixed set of signers and group results by identity.
///
/// Implements Radicle's "Person Rule": one identity = one vote, regardless of
/// how many devices that identity has. Results are grouped by `IdentityDid`:
/// - `did:keri:` signers: grouped by their controller identity DID
/// - `did:key:` signers (legacy): each device is its own identity
///
/// Args:
/// * `bridge`: The bridge implementation.
/// * `signers`: Mixed signer inputs (pre-verified or needing bridge verification).
/// * `request_template`: Template for bridge verification requests.
///
/// Usage:
/// ```ignore
/// let signers = vec![
///     SignerInput::PreVerified { did: "did:key:z6Mk...".into(), result: VerifyResult::Verified { reason: "ok".into() } },
///     SignerInput::NeedsBridgeVerification(keri_key),
/// ];
/// let grouped = verify_multiple_signers(&bridge, &signers, &request);
/// assert!(meets_threshold(&grouped, 2));
/// ```
pub fn verify_multiple_signers<B: RadicleAuthsBridge>(
    bridge: &B,
    signers: &[SignerInput],
    request_template: &VerifyRequest,
) -> BTreeMap<IdentityDid, Vec<VerifyResult>> {
    let mut grouped: BTreeMap<IdentityDid, Vec<VerifyResult>> = BTreeMap::new();

    for signer in signers {
        match signer {
            SignerInput::PreVerified { did, result } => {
                grouped
                    .entry(IdentityDid::new(did))
                    .or_default()
                    .push(result.clone());
            }
            SignerInput::NeedsBridgeVerification(key) => {
                let device_did = bridge.device_did(key);

                let identity_did = bridge
                    .find_identity_for_device(&device_did, request_template.repo_id)
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| device_did.clone());

                let request = VerifyRequest {
                    signer_key: key,
                    repo_id: request_template.repo_id,
                    now: request_template.now,
                    mode: request_template.mode,
                    known_remote_tip: request_template.known_remote_tip,
                    min_kel_seq: request_template.min_kel_seq,
                    required_capability: request_template.required_capability,
                };

                let result = match bridge.verify_signer(&request) {
                    Ok(r) => r,
                    Err(_) => VerifyResult::Rejected {
                        reason: format!("bridge error for device {device_did}"),
                    },
                };

                grouped
                    .entry(IdentityDid::new(&identity_did))
                    .or_default()
                    .push(result);
            }
        }
    }

    grouped
}

/// Check if enough unique identities have verified results for a threshold.
///
/// Counts unique identity DIDs that have at least one `is_allowed()` result.
/// Multiple devices under the same `did:keri:` identity count as one vote.
///
/// Args:
/// * `results`: Grouped results from `verify_multiple_signers`.
/// * `threshold`: Minimum number of unique verified identities required.
///
/// Usage:
/// ```ignore
/// assert!(meets_threshold(&grouped, 2));
/// ```
pub fn meets_threshold(
    results: &BTreeMap<IdentityDid, Vec<VerifyResult>>,
    threshold: usize,
) -> bool {
    let verified_identities = results
        .values()
        .filter(|results| results.iter().any(|r| r.is_allowed()))
        .count();
    verified_identities >= threshold
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_verifier::IdentityDID;
    use auths_verifier::keri::{Prefix, Said};
    use chrono::{DateTime, Utc};
    use std::collections::HashMap;

    struct MockStorage {
        key_states: HashMap<String, KeyState>,
        attestations: HashMap<(String, String), Attestation>,
        device_to_identity: HashMap<(String, String), String>,
        identity_tips: HashMap<String, [u8; 20]>,
    }

    impl MockStorage {
        fn new() -> Self {
            Self {
                key_states: HashMap::new(),
                attestations: HashMap::new(),
                device_to_identity: HashMap::new(),
                identity_tips: HashMap::new(),
            }
        }

        fn add_identity(&mut self, identity_did: &str, key_state: KeyState) {
            self.key_states.insert(identity_did.to_string(), key_state);
        }

        fn add_attestation(
            &mut self,
            device_did: &str,
            identity_did: &str,
            attestation: Attestation,
        ) {
            self.attestations.insert(
                (device_did.to_string(), identity_did.to_string()),
                attestation,
            );
        }

        fn link_device_to_identity(&mut self, device_did: &str, identity_did: &str, repo_id: &str) {
            self.device_to_identity.insert(
                (device_did.to_string(), repo_id.to_string()),
                identity_did.to_string(),
            );
        }

        fn set_identity_tip(&mut self, identity_did: &str, tip: [u8; 20]) {
            self.identity_tips.insert(identity_did.to_string(), tip);
        }
    }

    impl AuthsStorage for MockStorage {
        fn load_key_state(&self, identity_did: &str) -> Result<KeyState, BridgeError> {
            self.key_states
                .get(identity_did)
                .cloned()
                .ok_or_else(|| BridgeError::IdentityLoad(format!("Not found: {identity_did}")))
        }

        fn load_attestation(
            &self,
            device_did: &str,
            identity_did: &str,
        ) -> Result<Attestation, BridgeError> {
            self.attestations
                .get(&(device_did.to_string(), identity_did.to_string()))
                .cloned()
                .ok_or_else(|| BridgeError::AttestationLoad(format!("Not found: {device_did}")))
        }

        fn find_identity_for_device(
            &self,
            device_did: &str,
            repo_id: &str,
        ) -> Result<Option<String>, BridgeError> {
            Ok(self
                .device_to_identity
                .get(&(device_did.to_string(), repo_id.to_string()))
                .cloned())
        }

        fn local_identity_tip(&self, identity_did: &str) -> Result<Option<[u8; 20]>, BridgeError> {
            Ok(self.identity_tips.get(identity_did).copied())
        }
    }

    fn make_key_state(prefix: &str, sequence: u64) -> KeyState {
        KeyState {
            prefix: Prefix::new_unchecked(prefix.to_string()),
            sequence,
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
        capabilities: Vec<String>,
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
            capabilities: capabilities
                .into_iter()
                .filter_map(|c| c.parse().ok())
                .collect(),
            delegated_by: None,
            signer_type: None,
        }
    }

    fn setup_valid_signer() -> (MockStorage, [u8; 32], &'static str, &'static str) {
        let mut storage = MockStorage::new();
        let signer_key: [u8; 32] = [1; 32];
        let device_did = ed25519_to_did_key(&signer_key);
        let identity_did = "did:keri:ETestPrefix";
        let repo_id = "test-repo";

        storage.add_identity(identity_did, make_key_state("ETestPrefix", 0));
        storage.add_attestation(
            &device_did,
            identity_did,
            make_attestation(identity_did, &device_did, None, vec![]),
        );
        storage.link_device_to_identity(&device_did, identity_did, repo_id);
        storage.set_identity_tip(identity_did, [0xAA; 20]);

        (storage, signer_key, identity_did, repo_id)
    }

    fn make_enforce_request<'a>(
        key: &'a [u8; 32],
        repo_id: &'a str,
        now: DateTime<Utc>,
    ) -> VerifyRequest<'a> {
        VerifyRequest {
            signer_key: key,
            repo_id,
            now,
            mode: EnforcementMode::Enforce,
            known_remote_tip: None,
            min_kel_seq: None,
            required_capability: None,
        }
    }

    #[test]
    fn verify_valid_signer() {
        let (storage, signer_key, _, repo_id) = setup_valid_signer();
        let bridge = DefaultBridge::with_storage(storage);
        let request = make_enforce_request(&signer_key, repo_id, Utc::now());
        let result = bridge.verify_signer(&request).unwrap();
        assert!(result.is_allowed());
    }

    #[test]
    fn verify_revoked_attestation() {
        let mut storage = MockStorage::new();
        let signer_key: [u8; 32] = [2; 32];
        let device_did = ed25519_to_did_key(&signer_key);
        let identity_did = "did:keri:ETestPrefix";
        let repo_id = "test-repo";

        storage.add_identity(identity_did, make_key_state("ETestPrefix", 0));
        storage.add_attestation(
            &device_did,
            identity_did,
            make_attestation(identity_did, &device_did, Some(Utc::now()), vec![]),
        );
        storage.link_device_to_identity(&device_did, identity_did, repo_id);
        storage.set_identity_tip(identity_did, [0xBB; 20]);

        let bridge = DefaultBridge::with_storage(storage);
        let request = make_enforce_request(&signer_key, repo_id, Utc::now());
        let result = bridge.verify_signer(&request).unwrap();
        assert!(result.is_rejected());
    }

    #[test]
    fn verify_unknown_device_enforce_quarantine() {
        let storage = MockStorage::new();
        let signer_key: [u8; 32] = [3; 32];
        let bridge = DefaultBridge::with_storage(storage);
        let request = make_enforce_request(&signer_key, "test-repo", Utc::now());
        let result = bridge.verify_signer(&request).unwrap();
        assert!(matches!(result, VerifyResult::Quarantine { .. }));
    }

    #[test]
    fn verify_unknown_device_observe_warn() {
        let storage = MockStorage::new();
        let signer_key: [u8; 32] = [3; 32];
        let bridge = DefaultBridge::with_storage(storage);
        let request = VerifyRequest {
            signer_key: &signer_key,
            repo_id: "test-repo",
            now: Utc::now(),
            mode: EnforcementMode::Observe,
            known_remote_tip: None,
            min_kel_seq: None,
            required_capability: None,
        };
        let result = bridge.verify_signer(&request).unwrap();
        assert!(matches!(result, VerifyResult::Warn { .. }));
    }

    #[test]
    fn observe_mode_downgrades_rejected_to_warn() {
        let mut storage = MockStorage::new();
        let signer_key: [u8; 32] = [4; 32];
        let device_did = ed25519_to_did_key(&signer_key);
        let identity_did = "did:keri:ETestPrefix";
        let repo_id = "test-repo";

        storage.add_identity(identity_did, make_key_state("ETestPrefix", 0));
        storage.add_attestation(
            &device_did,
            identity_did,
            make_attestation(identity_did, &device_did, Some(Utc::now()), vec![]),
        );
        storage.link_device_to_identity(&device_did, identity_did, repo_id);
        storage.set_identity_tip(identity_did, [0xCC; 20]);

        let bridge = DefaultBridge::with_storage(storage);
        let request = VerifyRequest {
            signer_key: &signer_key,
            repo_id,
            now: Utc::now(),
            mode: EnforcementMode::Observe,
            known_remote_tip: None,
            min_kel_seq: None,
            required_capability: None,
        };
        let result = bridge.verify_signer(&request).unwrap();
        assert!(matches!(result, VerifyResult::Warn { .. }));
    }

    #[test]
    fn min_kel_seq_rejects_below_minimum() {
        let (storage, signer_key, _, repo_id) = setup_valid_signer();
        let bridge = DefaultBridge::with_storage(storage);
        let request = VerifyRequest {
            signer_key: &signer_key,
            repo_id,
            now: Utc::now(),
            mode: EnforcementMode::Enforce,
            known_remote_tip: None,
            min_kel_seq: Some(5), // key_state.sequence is 0
            required_capability: None,
        };
        let result = bridge.verify_signer(&request).unwrap();
        assert!(result.is_rejected());
        assert!(result.reason().contains("below binding minimum"));
    }

    #[test]
    fn min_kel_seq_not_downgraded_in_observe_mode() {
        let (storage, signer_key, _, repo_id) = setup_valid_signer();
        let bridge = DefaultBridge::with_storage(storage);
        let request = VerifyRequest {
            signer_key: &signer_key,
            repo_id,
            now: Utc::now(),
            mode: EnforcementMode::Observe, // Even in observe...
            known_remote_tip: None,
            min_kel_seq: Some(5), // ...below binding is ALWAYS rejected
            required_capability: None,
        };
        let result = bridge.verify_signer(&request).unwrap();
        assert!(
            result.is_rejected(),
            "min_kel_seq violation must never be downgraded"
        );
    }

    #[test]
    fn min_kel_seq_passes_at_minimum() {
        let mut storage = MockStorage::new();
        let signer_key: [u8; 32] = [1; 32];
        let device_did = ed25519_to_did_key(&signer_key);
        let identity_did = "did:keri:ETestPrefix";
        let repo_id = "test-repo";

        storage.add_identity(identity_did, make_key_state("ETestPrefix", 5));
        storage.add_attestation(
            &device_did,
            identity_did,
            make_attestation(identity_did, &device_did, None, vec![]),
        );
        storage.link_device_to_identity(&device_did, identity_did, repo_id);
        storage.set_identity_tip(identity_did, [0xAA; 20]);

        let bridge = DefaultBridge::with_storage(storage);
        let request = VerifyRequest {
            signer_key: &signer_key,
            repo_id,
            now: Utc::now(),
            mode: EnforcementMode::Enforce,
            known_remote_tip: None,
            min_kel_seq: Some(5), // sequence == min
            required_capability: None,
        };
        let result = bridge.verify_signer(&request).unwrap();
        assert!(result.is_allowed());
    }

    #[test]
    fn staleness_detected_enforce_quarantine() {
        let (storage, signer_key, _, repo_id) = setup_valid_signer();
        let bridge = DefaultBridge::with_storage(storage);
        let request = VerifyRequest {
            signer_key: &signer_key,
            repo_id,
            now: Utc::now(),
            mode: EnforcementMode::Enforce,
            known_remote_tip: Some([0xBB; 20]), // differs from local [0xAA; 20]
            min_kel_seq: None,
            required_capability: None,
        };
        let result = bridge.verify_signer(&request).unwrap();
        assert!(matches!(result, VerifyResult::Quarantine { .. }));
    }

    #[test]
    fn staleness_detected_observe_warn() {
        let (storage, signer_key, _, repo_id) = setup_valid_signer();
        let bridge = DefaultBridge::with_storage(storage);
        let request = VerifyRequest {
            signer_key: &signer_key,
            repo_id,
            now: Utc::now(),
            mode: EnforcementMode::Observe,
            known_remote_tip: Some([0xBB; 20]),
            min_kel_seq: None,
            required_capability: None,
        };
        let result = bridge.verify_signer(&request).unwrap();
        assert!(matches!(result, VerifyResult::Warn { .. }));
    }

    #[test]
    fn no_staleness_when_tips_match() {
        let (storage, signer_key, _, repo_id) = setup_valid_signer();
        let bridge = DefaultBridge::with_storage(storage);
        let request = VerifyRequest {
            signer_key: &signer_key,
            repo_id,
            now: Utc::now(),
            mode: EnforcementMode::Enforce,
            known_remote_tip: Some([0xAA; 20]), // matches local
            min_kel_seq: None,
            required_capability: None,
        };
        let result = bridge.verify_signer(&request).unwrap();
        assert!(result.is_allowed());
    }

    #[test]
    fn no_staleness_when_no_remote_tip() {
        let (storage, signer_key, _, repo_id) = setup_valid_signer();
        let bridge = DefaultBridge::with_storage(storage);
        let request = VerifyRequest {
            signer_key: &signer_key,
            repo_id,
            now: Utc::now(),
            mode: EnforcementMode::Enforce,
            known_remote_tip: None, // disconnected
            min_kel_seq: None,
            required_capability: None,
        };
        let result = bridge.verify_signer(&request).unwrap();
        assert!(result.is_allowed());
    }

    #[test]
    fn capability_check_passes() {
        let mut storage = MockStorage::new();
        let signer_key: [u8; 32] = [1; 32];
        let device_did = ed25519_to_did_key(&signer_key);
        let identity_did = "did:keri:ETestPrefix";
        let repo_id = "test-repo";

        storage.add_identity(identity_did, make_key_state("ETestPrefix", 0));
        storage.add_attestation(
            &device_did,
            identity_did,
            make_attestation(
                identity_did,
                &device_did,
                None,
                vec!["sign_commit".to_string()],
            ),
        );
        storage.link_device_to_identity(&device_did, identity_did, repo_id);
        storage.set_identity_tip(identity_did, [0xAA; 20]);

        let bridge = DefaultBridge::with_storage(storage);
        let request = VerifyRequest {
            signer_key: &signer_key,
            repo_id,
            now: Utc::now(),
            mode: EnforcementMode::Enforce,
            known_remote_tip: None,
            min_kel_seq: None,
            required_capability: Some("sign_commit"),
        };
        let result = bridge.verify_signer(&request).unwrap();
        assert!(result.is_allowed());
    }

    #[test]
    fn capability_check_fails_wrong_cap() {
        let mut storage = MockStorage::new();
        let signer_key: [u8; 32] = [1; 32];
        let device_did = ed25519_to_did_key(&signer_key);
        let identity_did = "did:keri:ETestPrefix";
        let repo_id = "test-repo";

        storage.add_identity(identity_did, make_key_state("ETestPrefix", 0));
        storage.add_attestation(
            &device_did,
            identity_did,
            make_attestation(
                identity_did,
                &device_did,
                None,
                vec!["sign_release".to_string()],
            ),
        );
        storage.link_device_to_identity(&device_did, identity_did, repo_id);
        storage.set_identity_tip(identity_did, [0xAA; 20]);

        let bridge = DefaultBridge::with_storage(storage);
        let request = VerifyRequest {
            signer_key: &signer_key,
            repo_id,
            now: Utc::now(),
            mode: EnforcementMode::Enforce,
            known_remote_tip: None,
            min_kel_seq: None,
            required_capability: Some("sign_commit"),
        };
        let result = bridge.verify_signer(&request).unwrap();
        assert!(result.is_rejected());
    }

    #[test]
    fn empty_capabilities_skips_check() {
        let (storage, signer_key, _, repo_id) = setup_valid_signer();
        let bridge = DefaultBridge::with_storage(storage);
        let request = VerifyRequest {
            signer_key: &signer_key,
            repo_id,
            now: Utc::now(),
            mode: EnforcementMode::Enforce,
            known_remote_tip: None,
            min_kel_seq: None,
            required_capability: Some("sign_commit"),
        };
        // Attestation has empty capabilities — legacy device, check skipped
        let result = bridge.verify_signer(&request).unwrap();
        assert!(result.is_allowed());
    }

    #[test]
    fn decision_to_verify_result_mapping() {
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
    fn mixed_threshold_verification() {
        let (storage, signer_key, _, repo_id) = setup_valid_signer();
        let bridge = DefaultBridge::with_storage(storage);

        let signers = vec![
            SignerInput::PreVerified {
                did: "did:key:zAlice".into(),
                result: VerifyResult::Verified { reason: "did:key delegate ok".into() },
            },
            SignerInput::PreVerified {
                did: "did:key:zBob".into(),
                result: VerifyResult::Verified { reason: "did:key delegate ok".into() },
            },
            SignerInput::NeedsBridgeVerification(signer_key),
        ];

        let template = make_enforce_request(&signer_key, repo_id, Utc::now());
        let results = verify_multiple_signers(&bridge, &signers, &template);

        // 3 unique identities: Alice, Bob, and the KERI identity
        assert_eq!(results.len(), 3);
        assert!(meets_threshold(&results, 2));
        assert!(meets_threshold(&results, 3));
    }

    #[test]
    fn same_keri_identity_multiple_devices_one_vote() {
        let mut storage = MockStorage::new();
        let key_a: [u8; 32] = [1; 32];
        let key_b: [u8; 32] = [2; 32];
        let key_c: [u8; 32] = [3; 32];
        let did_a = ed25519_to_did_key(&key_a);
        let did_b = ed25519_to_did_key(&key_b);
        let did_c = ed25519_to_did_key(&key_c);
        let identity_did = "did:keri:EAlice";
        let repo_id = "test-repo";

        storage.add_identity(identity_did, make_key_state("EAlice", 0));
        for (device_did, key) in [(&did_a, &key_a), (&did_b, &key_b), (&did_c, &key_c)] {
            storage.add_attestation(
                device_did,
                identity_did,
                make_attestation(identity_did, device_did, None, vec![]),
            );
            storage.link_device_to_identity(device_did, identity_did, repo_id);
            let _ = key; // used for creating DIDs
        }
        storage.set_identity_tip(identity_did, [0xAA; 20]);

        let bridge = DefaultBridge::with_storage(storage);
        let signers = vec![
            SignerInput::NeedsBridgeVerification(key_a),
            SignerInput::NeedsBridgeVerification(key_b),
            SignerInput::NeedsBridgeVerification(key_c),
        ];

        let template = make_enforce_request(&key_a, repo_id, Utc::now());
        let results = verify_multiple_signers(&bridge, &signers, &template);

        // All 3 devices are under the same identity → 1 entry in map → 1 vote
        assert_eq!(results.len(), 1);
        assert!(meets_threshold(&results, 1));
        assert!(!meets_threshold(&results, 2));
    }

    #[test]
    fn two_different_keri_identities_two_votes() {
        let mut storage = MockStorage::new();
        let alice_key: [u8; 32] = [1; 32];
        let bob_key: [u8; 32] = [2; 32];
        let alice_did = ed25519_to_did_key(&alice_key);
        let bob_did = ed25519_to_did_key(&bob_key);
        let alice_id = "did:keri:EAlice";
        let bob_id = "did:keri:EBob";
        let repo_id = "test-repo";

        storage.add_identity(alice_id, make_key_state("EAlice", 0));
        storage.add_identity(bob_id, make_key_state("EBob", 0));
        storage.add_attestation(&alice_did, alice_id, make_attestation(alice_id, &alice_did, None, vec![]));
        storage.add_attestation(&bob_did, bob_id, make_attestation(bob_id, &bob_did, None, vec![]));
        storage.link_device_to_identity(&alice_did, alice_id, repo_id);
        storage.link_device_to_identity(&bob_did, bob_id, repo_id);
        storage.set_identity_tip(alice_id, [0xAA; 20]);
        storage.set_identity_tip(bob_id, [0xBB; 20]);

        let bridge = DefaultBridge::with_storage(storage);
        let signers = vec![
            SignerInput::NeedsBridgeVerification(alice_key),
            SignerInput::NeedsBridgeVerification(bob_key),
        ];

        let template = make_enforce_request(&alice_key, repo_id, Utc::now());
        let results = verify_multiple_signers(&bridge, &signers, &template);

        assert_eq!(results.len(), 2);
        assert!(meets_threshold(&results, 2));
    }

    #[test]
    fn mixed_did_key_and_did_keri_correct_count() {
        let (storage, signer_key, _, repo_id) = setup_valid_signer();
        let bridge = DefaultBridge::with_storage(storage);

        let signers = vec![
            SignerInput::PreVerified {
                did: "did:key:zLegacyNode".into(),
                result: VerifyResult::Verified { reason: "ok".into() },
            },
            SignerInput::NeedsBridgeVerification(signer_key),
        ];

        let template = make_enforce_request(&signer_key, repo_id, Utc::now());
        let results = verify_multiple_signers(&bridge, &signers, &template);

        // 1 legacy did:key + 1 KERI identity = 2 votes
        assert_eq!(results.len(), 2);
        assert!(meets_threshold(&results, 2));
    }

    #[test]
    fn mixed_threshold_one_keri_revoked() {
        let mut storage = MockStorage::new();
        let good_key: [u8; 32] = [1; 32];
        let bad_key: [u8; 32] = [2; 32];
        let good_did = ed25519_to_did_key(&good_key);
        let bad_did = ed25519_to_did_key(&bad_key);
        let identity_did = "did:keri:ETestPrefix";
        let repo_id = "test-repo";

        storage.add_identity(identity_did, make_key_state("ETestPrefix", 0));
        storage.add_attestation(
            &good_did,
            identity_did,
            make_attestation(identity_did, &good_did, None, vec![]),
        );
        storage.add_attestation(
            &bad_did,
            identity_did,
            make_attestation(identity_did, &bad_did, Some(Utc::now()), vec![]),
        );
        storage.link_device_to_identity(&good_did, identity_did, repo_id);
        storage.link_device_to_identity(&bad_did, identity_did, repo_id);
        storage.set_identity_tip(identity_did, [0xAA; 20]);

        let bridge = DefaultBridge::with_storage(storage);

        let signers = vec![
            SignerInput::PreVerified {
                did: "did:key:zLegacy".into(),
                result: VerifyResult::Verified { reason: "ok".into() },
            },
            // Both devices under same identity — one good, one revoked
            SignerInput::NeedsBridgeVerification(good_key),
            SignerInput::NeedsBridgeVerification(bad_key),
        ];

        let template = make_enforce_request(&good_key, repo_id, Utc::now());
        let results = verify_multiple_signers(&bridge, &signers, &template);

        // 2 unique identities: legacy + KERI. KERI has one good device → 1 vote.
        assert_eq!(results.len(), 2);
        assert!(meets_threshold(&results, 2)); // both identities have at least one verified
    }

    #[test]
    fn empty_signers_threshold_zero_passes() {
        let results: BTreeMap<IdentityDid, Vec<VerifyResult>> = BTreeMap::new();
        assert!(meets_threshold(&results, 0));
    }

    #[test]
    fn threshold_one_met_by_any_single_device() {
        let (storage, signer_key, _, repo_id) = setup_valid_signer();
        let bridge = DefaultBridge::with_storage(storage);

        let signers = vec![SignerInput::NeedsBridgeVerification(signer_key)];
        let template = make_enforce_request(&signer_key, repo_id, Utc::now());
        let results = verify_multiple_signers(&bridge, &signers, &template);

        assert!(meets_threshold(&results, 1));
    }

    #[test]
    fn device_did_format() {
        let key: [u8; 32] = [0xAB; 32];
        let bridge = DefaultBridge::with_storage(MockStorage::new());
        let did = bridge.device_did(&key);
        assert!(did.starts_with("did:key:z"));
    }

    #[test]
    fn find_identity_for_device_via_bridge() {
        let (storage, signer_key, identity_did, repo_id) = setup_valid_signer();
        let device_did = ed25519_to_did_key(&signer_key);
        let bridge = DefaultBridge::with_storage(storage);
        let found = bridge
            .find_identity_for_device(&device_did, repo_id)
            .unwrap();
        assert_eq!(found, Some(identity_did.to_string()));
    }

    #[test]
    fn stale_plus_revoked_rejects() {
        // If a device is revoked AND stale, Rejected takes priority
        let mut storage = MockStorage::new();
        let signer_key: [u8; 32] = [1; 32];
        let device_did = ed25519_to_did_key(&signer_key);
        let identity_did = "did:keri:ETestPrefix";
        let repo_id = "test-repo";

        storage.add_identity(identity_did, make_key_state("ETestPrefix", 0));
        storage.add_attestation(
            &device_did,
            identity_did,
            make_attestation(identity_did, &device_did, Some(Utc::now()), vec![]),
        );
        storage.link_device_to_identity(&device_did, identity_did, repo_id);
        // Same tip → no staleness → revocation check runs → Rejected
        storage.set_identity_tip(identity_did, [0xAA; 20]);

        let bridge = DefaultBridge::with_storage(storage);
        let request = VerifyRequest {
            signer_key: &signer_key,
            repo_id,
            now: Utc::now(),
            mode: EnforcementMode::Enforce,
            known_remote_tip: Some([0xAA; 20]),
            min_kel_seq: None,
            required_capability: None,
        };
        let result = bridge.verify_signer(&request).unwrap();
        assert!(result.is_rejected());
    }
}
