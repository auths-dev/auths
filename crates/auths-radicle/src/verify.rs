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

use auths_id::keri::KeyState;
use auths_id::policy::{CompiledPolicy, Decision, Outcome, PolicyBuilder, evaluate_compiled};
use auths_verifier::core::Attestation;
use radicle_core::{Did, RepoId};
use radicle_crypto::PublicKey;

use crate::bridge::{
    BridgeError, EnforcementMode, RadicleAuthsBridge, SignerInput, VerifyRequest, VerifyResult,
};
use crate::refs::Layout;

/// An identity-level DID used for threshold deduplication.
///
/// For `did:keri:` signers, this is the controller identity DID (all devices
/// under the same identity share one `IdentityDid`). For legacy `did:key:`
/// signers, the device DID itself is the identity DID (one device = one vote).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IdentityDid(Did);

impl IdentityDid {
    /// Creates a new `IdentityDid` from a `Did`.
    pub fn new(did: Did) -> Self {
        Self(did)
    }

    /// Returns the underlying `Did`.
    pub fn did(&self) -> &Did {
        &self.0
    }
}

impl std::fmt::Display for IdentityDid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
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
    layout: Layout,
}

impl<S> DefaultBridge<S> {
    /// Creates a new bridge with the given storage and compiled policy.
    pub fn new(storage: S, policy: CompiledPolicy) -> Self {
        Self {
            storage,
            policy,
            layout: Layout::radicle(),
        }
    }

    /// Creates a new bridge with default policy (not_revoked + not_expired).
    pub fn with_storage(storage: S) -> Self {
        Self {
            storage,
            policy: PolicyBuilder::new().not_revoked().not_expired().build(),
            layout: Layout::radicle(),
        }
    }

    /// Override the default layout configuration.
    pub fn with_layout(mut self, layout: Layout) -> Self {
        self.layout = layout;
        self
    }

    /// Returns a reference to the compiled policy.
    pub fn policy(&self) -> &CompiledPolicy {
        &self.policy
    }

    /// Returns a reference to the layout configuration.
    pub fn layout(&self) -> &Layout {
        &self.layout
    }
}

/// Trait for loading identity and attestation data.
///
/// This abstraction allows the bridge to work with different storage backends
/// (Git-based, indexed, cached) without coupling to a specific implementation.
/// The trait signature is designed so that future implementations can add caching
/// (e.g., local SQLite index) without changing the trait contract.
pub trait AuthsStorage: Send + Sync {
    /// Returns the layout configuration used by this storage.
    fn layout(&self) -> &Layout;

    /// Load the key state (identity) for a given identity DID.
    fn load_key_state(&self, identity_did: &Did) -> Result<KeyState, BridgeError>;

    /// Load the device attestation for a given device DID under an identity.
    fn load_attestation(
        &self,
        device_did: &Did,
        identity_did: &Did,
    ) -> Result<Attestation, BridgeError>;

    /// Find the identity DID that controls a given device key within a project.
    ///
    /// Returns `None` if the device is not attested under any identity in this project.
    fn find_identity_for_device(
        &self,
        device_did: &Did,
        repo_id: &RepoId,
    ) -> Result<Option<Did>, BridgeError>;

    /// List all device DIDs that are attested by a given identity in this project.
    fn list_devices(&self, identity_did: &Did) -> Result<Vec<Did>, BridgeError>;

    /// Get the local tip OID of an identity repo.
    ///
    /// Returns `None` if the identity repo is not available locally.
    fn local_identity_tip(&self, identity_did: &Did) -> Result<Option<[u8; 20]>, BridgeError>;
}

impl<S: AuthsStorage> RadicleAuthsBridge for DefaultBridge<S> {
    fn device_did(&self, key: &PublicKey) -> Did {
        Did::from(*key)
    }

    fn verify_signer(&self, request: &VerifyRequest) -> Result<VerifyResult, BridgeError> {
        let device_did = self.device_did(request.signer_key);

        // Step 1: Find the identity that controls this device
        let identity_did = match self
            .storage
            .find_identity_for_device(&device_did, request.repo_id)
        {
            Ok(Some(did)) => did,
            Ok(None) => {
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
            Err(BridgeError::IdentityCorrupt(msg)) => {
                return Ok(VerifyResult::Rejected {
                    reason: format!("identity corrupt: {msg}"),
                });
            }
            Err(e) => return Err(e),
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
                        identity_repo_rid: Some(*request.repo_id), // Use the repo_id as context for fetch
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
        if let Some(min_seq) = request.min_kel_seq {
            if key_state.sequence < min_seq {
                return Ok(VerifyResult::Rejected {
                    reason: format!(
                        "KEL sequence {} below binding minimum {min_seq} for {identity_did}",
                        key_state.sequence
                    ),
                });
            }
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
                            identity_repo_rid: Some(*request.repo_id),
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
                            identity_repo_rid: Some(*request.repo_id),
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
                ));
            }
            Err(e) => return Err(e),
        };

        // Step 6: Evaluate policy (revocation, expiry)
        let decision = evaluate_compiled(&attestation, &self.policy, request.now);

        // Step 7: Capability check
        if let Some(required_cap) = request.required_capability {
            if decision.outcome == Outcome::Allow {
                let has_cap = attestation
                    .capabilities
                    .iter()
                    .any(|c| c.to_string() == required_cap);
                if !has_cap && !attestation.capabilities.is_empty() {
                    return Ok(apply_mode(
                        request.mode,
                        VerifyResult::Rejected {
                            reason: format!(
                                "device lacks required capability '{required_cap}'"
                            ),
                        },
                    ));
                }
            }
        }

        // Step 8: Map decision to VerifyResult with mode
        let result = decision_to_verify_result(decision);
        Ok(apply_mode(request.mode, result))
    }

    fn find_identity_for_device(
        &self,
        device_did: &Did,
        repo_id: &RepoId,
    ) -> Result<Option<Did>, BridgeError> {
        self.storage.find_identity_for_device(device_did, repo_id)
    }

    fn list_devices(&self, identity_did: &Did) -> Result<Vec<Did>, BridgeError> {
        self.storage.list_devices(identity_did)
    }
}

/// Apply enforcement mode to a VerifyResult.
///
/// In Observe mode, `Rejected` is downgraded to `Warn`.
/// `Verified` and `Warn` pass through unchanged.
/// `Quarantine` stays as-is in Enforce, downgraded to `Warn` in Observe.
fn apply_mode(mode: EnforcementMode, result: VerifyResult) -> VerifyResult {
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
///     SignerInput::PreVerified { did: alice_did, result: VerifyResult::Verified { reason: "ok".into() } },
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
                    .entry(IdentityDid::new(did.clone()))
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
                    .entry(IdentityDid::new(identity_did))
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
    use std::str::FromStr;
    use auths_verifier::IdentityDID;
    use auths_verifier::keri::{Prefix, Said};
    use chrono::{DateTime, Utc};
    use std::collections::HashMap;

    struct MockStorage {
        key_states: HashMap<Did, KeyState>,
        attestations: HashMap<(Did, Did), Attestation>,
        device_to_identity: HashMap<(Did, RepoId), Did>,
        identity_tips: HashMap<Did, [u8; 20]>,
        layout: Layout,
    }

    impl MockStorage {
        fn new() -> Self {
            Self {
                key_states: HashMap::new(),
                attestations: HashMap::new(),
                device_to_identity: HashMap::new(),
                identity_tips: HashMap::new(),
                layout: Layout::radicle(),
            }
        }

        fn add_identity(&mut self, identity_did: Did, key_state: KeyState) {
            self.key_states.insert(identity_did, key_state);
        }

        fn add_attestation(
            &mut self,
            device_did: Did,
            identity_did: Did,
            attestation: Attestation,
        ) {
            self.attestations.insert(
                (device_did, identity_did),
                attestation,
            );
        }

        fn link_device_to_identity(&mut self, device_did: Did, identity_did: Did, repo_id: RepoId) {
            self.device_to_identity.insert(
                (device_did, repo_id),
                identity_did,
            );
        }

        fn set_identity_tip(&mut self, identity_did: Did, tip: [u8; 20]) {
            self.identity_tips.insert(identity_did, tip);
        }
    }

    impl AuthsStorage for MockStorage {
        fn layout(&self) -> &Layout {
            &self.layout
        }

        fn load_key_state(&self, identity_did: &Did) -> Result<KeyState, BridgeError> {
            self.key_states
                .get(identity_did)
                .cloned()
                .ok_or_else(|| BridgeError::IdentityLoad(format!("Not found: {identity_did}")))
        }

        fn load_attestation(
            &self,
            device_did: &Did,
            identity_did: &Did,
        ) -> Result<Attestation, BridgeError> {
            self.attestations
                .get(&(device_did.clone(), identity_did.clone()))
                .cloned()
                .ok_or_else(|| BridgeError::AttestationLoad(format!("Not found: {device_did}")))
        }

        fn find_identity_for_device(
            &self,
            device_did: &Did,
            repo_id: &RepoId,
        ) -> Result<Option<Did>, BridgeError> {
            Ok(self
                .device_to_identity
                .get(&(device_did.clone(), *repo_id))
                .cloned())
        }

        fn local_identity_tip(&self, identity_did: &Did) -> Result<Option<[u8; 20]>, BridgeError> {
            Ok(self.identity_tips.get(identity_did).copied())
        }

        fn list_devices(&self, _identity_did: &Did) -> Result<Vec<Did>, BridgeError> {
            Ok(Vec::new())
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
            threshold: 1,
            next_threshold: 1,
        }
    }

    fn make_attestation(
        issuer: &Did,
        device_did: &Did,
        revoked_at: Option<DateTime<Utc>>,
        capabilities: Vec<String>,
    ) -> Attestation {
        use auths_verifier::core::{Ed25519PublicKey, ResourceId};
        use auths_verifier::types::DeviceDID;

        Attestation {
            version: 1,
            rid: ResourceId::new("test"),
            issuer: IdentityDID::new(issuer.to_string()),
            subject: DeviceDID::new(device_did.to_string()),
            device_public_key: Ed25519PublicKey::from_bytes([0u8; 32]),
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

    fn setup_valid_signer() -> (MockStorage, PublicKey, Did, RepoId) {
        let mut storage = MockStorage::new();
        let signer_key = PublicKey::from([1; 32]);
        let device_did = Did::from(signer_key);
        let identity_did: Did = "did:keri:ETestPrefix".parse().unwrap();
        let repo_id = RepoId::from_str("rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5").unwrap();

        storage.add_identity(identity_did.clone(), make_key_state("ETestPrefix", 0));
        storage.add_attestation(
            device_did.clone(),
            identity_did.clone(),
            make_attestation(&identity_did, &device_did, None, vec![]),
        );
        storage.link_device_to_identity(device_did.clone(), identity_did.clone(), repo_id);
        storage.set_identity_tip(identity_did.clone(), [0xAA; 20]);

        (storage, signer_key, identity_did, repo_id)
    }

    fn make_enforce_request<'a>(
        key: &'a PublicKey,
        repo_id: &'a RepoId,
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
        let request = make_enforce_request(&signer_key, &repo_id, Utc::now());
        let result = bridge.verify_signer(&request).unwrap();
        assert!(result.is_allowed());
    }

    #[test]
    fn mixed_threshold_verification() {
        let (storage, signer_key, _, repo_id) = setup_valid_signer();
        let bridge = DefaultBridge::with_storage(storage);

        let alice_did: Did = "did:key:z6MknSLrJoTcukLrE435hVNQT4JUhbvWLX4kUzqkEStBU8Vi".parse().unwrap();
        let bob_did: Did = "did:key:z6Mkt67GdsW7715MEfRuP4pSZxT3tgCHHnQqBjgJs2ovUoND".parse().unwrap();

        let signers = vec![
            SignerInput::PreVerified {
                did: alice_did,
                result: VerifyResult::Verified {
                    reason: "did:key delegate ok".into(),
                },
            },
            SignerInput::PreVerified {
                did: bob_did,
                result: VerifyResult::Verified {
                    reason: "did:key delegate ok".into(),
                },
            },
            SignerInput::NeedsBridgeVerification(signer_key),
        ];

        let template = make_enforce_request(&signer_key, &repo_id, Utc::now());
        let results = verify_multiple_signers(&bridge, &signers, &template);

        assert_eq!(results.len(), 3);
        assert!(meets_threshold(&results, 2));
        assert!(meets_threshold(&results, 3));
    }
}
