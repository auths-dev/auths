//! Stale-state integration tests (fn-1.12).
//!
//! Simulates the stale-node scenario: Node A has revocation, Node B is stale.

use chrono::Utc;
use std::collections::HashMap;

use auths_id::identity::ed25519_to_did_key;
use auths_id::keri::KeyState;
use auths_radicle::bridge::{
    BridgeError, EnforcementMode, RadicleAuthsBridge, VerifyRequest, VerifyResult,
};
use auths_radicle::verify::{AuthsStorage, DefaultBridge};
use auths_verifier::IdentityDID;
use auths_verifier::core::Attestation;
use auths_verifier::keri::{Prefix, Said};
use auths_verifier::types::DeviceDID;

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

fn make_attestation(issuer: &str, device_did: &str, revoked: bool) -> Attestation {
    Attestation {
        version: 1,
        rid: "test".to_string(),
        issuer: IdentityDID::new(issuer),
        subject: DeviceDID::new(device_did),
        device_public_key: vec![0; 32],
        identity_signature: vec![0; 64],
        device_signature: vec![0; 64],
        revoked_at: if revoked { Some(Utc::now()) } else { None },
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

fn setup_stale_scenario() -> ([u8; 32], String, &'static str, &'static str) {
    let signer_key: [u8; 32] = [42; 32];
    let device_did = ed25519_to_did_key(&signer_key);
    let identity_did = "did:keri:EStaleTest";
    let repo_id = "test-repo";
    (signer_key, device_did, identity_did, repo_id)
}

/// Observe mode: stale node accepts with Warn, converges to Rejected after "sync".
#[test]
fn observe_stale_node_accepts_then_converges() {
    let (signer_key, device_did, identity_did, repo_id) = setup_stale_scenario();

    // Node B: stale, seq 2, no revocation
    let mut stale_storage = MockStorage::new();
    stale_storage
        .key_states
        .insert(identity_did.to_string(), make_key_state("EStaleTest", 2));
    stale_storage.attestations.insert(
        (device_did.clone(), identity_did.to_string()),
        make_attestation(identity_did, &device_did, false),
    );
    stale_storage.device_to_identity.insert(
        (device_did.clone(), repo_id.to_string()),
        identity_did.to_string(),
    );
    stale_storage
        .identity_tips
        .insert(identity_did.to_string(), [0xAA; 20]);

    let bridge = DefaultBridge::with_storage(stale_storage);
    let request = VerifyRequest {
        signer_key: &signer_key,
        repo_id,
        now: Utc::now(),
        mode: EnforcementMode::Observe,
        known_remote_tip: None, // No gossip info — stale node doesn't know
        min_kel_seq: None,
        required_capability: None,
    };

    // Stale node accepts (no staleness signal)
    let result = bridge.verify_signer(&request).unwrap();
    assert!(
        result.is_allowed(),
        "stale node should accept without gossip signal"
    );

    // After "sync" — simulate updated storage with revocation
    let mut synced_storage = MockStorage::new();
    synced_storage
        .key_states
        .insert(identity_did.to_string(), make_key_state("EStaleTest", 3));
    synced_storage.attestations.insert(
        (device_did.clone(), identity_did.to_string()),
        make_attestation(identity_did, &device_did, true), // now revoked
    );
    synced_storage.device_to_identity.insert(
        (device_did.clone(), repo_id.to_string()),
        identity_did.to_string(),
    );
    synced_storage
        .identity_tips
        .insert(identity_did.to_string(), [0xBB; 20]);

    let synced_bridge = DefaultBridge::with_storage(synced_storage);
    let result = synced_bridge.verify_signer(&request).unwrap();
    // Observe mode: revoked → Warn (downgraded from Rejected)
    assert!(matches!(result, VerifyResult::Warn { .. }));
}

/// Enforce mode: staleness detected → Quarantine, resolves after sync.
#[test]
fn enforce_staleness_detected_quarantine_then_resolves() {
    let (signer_key, device_did, identity_did, repo_id) = setup_stale_scenario();

    let mut storage = MockStorage::new();
    storage
        .key_states
        .insert(identity_did.to_string(), make_key_state("EStaleTest", 2));
    storage.attestations.insert(
        (device_did.clone(), identity_did.to_string()),
        make_attestation(identity_did, &device_did, false),
    );
    storage.device_to_identity.insert(
        (device_did.clone(), repo_id.to_string()),
        identity_did.to_string(),
    );
    storage
        .identity_tips
        .insert(identity_did.to_string(), [0xAA; 20]);

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

    // After sync: revocation present, tips now match
    let mut synced_storage = MockStorage::new();
    synced_storage
        .key_states
        .insert(identity_did.to_string(), make_key_state("EStaleTest", 3));
    synced_storage.attestations.insert(
        (device_did.clone(), identity_did.to_string()),
        make_attestation(identity_did, &device_did, true),
    );
    synced_storage.device_to_identity.insert(
        (device_did.clone(), repo_id.to_string()),
        identity_did.to_string(),
    );
    synced_storage
        .identity_tips
        .insert(identity_did.to_string(), [0xBB; 20]); // now matches remote

    let synced_bridge = DefaultBridge::with_storage(synced_storage);
    let synced_request = VerifyRequest {
        known_remote_tip: Some([0xBB; 20]),
        ..request
    };
    let result = synced_bridge.verify_signer(&synced_request).unwrap();
    assert!(
        result.is_rejected(),
        "after sync, revoked device should be rejected"
    );
}

/// Enforce mode: no staleness signal → Verified (irreducible risk).
#[test]
fn enforce_no_staleness_signal_accepts() {
    let (signer_key, device_did, identity_did, repo_id) = setup_stale_scenario();

    let mut storage = MockStorage::new();
    storage
        .key_states
        .insert(identity_did.to_string(), make_key_state("EStaleTest", 2));
    storage.attestations.insert(
        (device_did.clone(), identity_did.to_string()),
        make_attestation(identity_did, &device_did, false),
    );
    storage.device_to_identity.insert(
        (device_did.clone(), repo_id.to_string()),
        identity_did.to_string(),
    );
    storage
        .identity_tips
        .insert(identity_did.to_string(), [0xAA; 20]);

    let bridge = DefaultBridge::with_storage(storage);
    let request = VerifyRequest {
        signer_key: &signer_key,
        repo_id,
        now: Utc::now(),
        mode: EnforcementMode::Enforce,
        known_remote_tip: None, // disconnected — irreducible risk
        min_kel_seq: None,
        required_capability: None,
    };

    // Irreducible risk: no gossip info, local state says OK → Verified
    let result = bridge.verify_signer(&request).unwrap();
    assert!(result.is_allowed());
}

/// Below min_kel_seq → Rejected in both modes.
#[test]
fn below_min_kel_seq_rejected_in_both_modes() {
    let (signer_key, device_did, identity_did, repo_id) = setup_stale_scenario();

    for mode in [EnforcementMode::Observe, EnforcementMode::Enforce] {
        let mut storage = MockStorage::new();
        storage
            .key_states
            .insert(identity_did.to_string(), make_key_state("EStaleTest", 1));
        storage.attestations.insert(
            (device_did.clone(), identity_did.to_string()),
            make_attestation(identity_did, &device_did, false),
        );
        storage.device_to_identity.insert(
            (device_did.clone(), repo_id.to_string()),
            identity_did.to_string(),
        );
        storage
            .identity_tips
            .insert(identity_did.to_string(), [0xAA; 20]);

        let bridge = DefaultBridge::with_storage(storage);
        let request = VerifyRequest {
            signer_key: &signer_key,
            repo_id,
            now: Utc::now(),
            mode,
            known_remote_tip: None,
            min_kel_seq: Some(5), // way above seq 1
            required_capability: None,
        };

        let result = bridge.verify_signer(&request).unwrap();
        assert!(
            result.is_rejected(),
            "min_kel_seq violation must be Rejected in {:?} mode",
            mode
        );
    }
}

/// Tamper: corrupt identity → Rejected regardless of mode.
#[test]
fn corrupt_identity_rejected_regardless_of_mode() {
    let signer_key: [u8; 32] = [42; 32];
    let _device_did = ed25519_to_did_key(&signer_key);
    let identity_did = "did:keri:ECorrupt";
    let repo_id = "test-repo";

    // Storage that returns IdentityCorrupt error
    struct CorruptStorage {
        identity_did: String,
    }

    impl AuthsStorage for CorruptStorage {
        fn load_key_state(&self, _: &str) -> Result<KeyState, BridgeError> {
            Err(BridgeError::IdentityCorrupt("broken chain".into()))
        }
        fn load_attestation(&self, _: &str, _: &str) -> Result<Attestation, BridgeError> {
            unreachable!()
        }
        fn find_identity_for_device(
            &self,
            _device_did: &str,
            _repo_id: &str,
        ) -> Result<Option<String>, BridgeError> {
            Ok(Some(self.identity_did.clone()))
        }
        fn local_identity_tip(&self, _: &str) -> Result<Option<[u8; 20]>, BridgeError> {
            Ok(None)
        }
    }

    for mode in [EnforcementMode::Observe, EnforcementMode::Enforce] {
        let storage = CorruptStorage {
            identity_did: identity_did.to_string(),
        };
        let bridge = DefaultBridge::with_storage(storage);
        let request = VerifyRequest {
            signer_key: &signer_key,
            repo_id,
            now: Utc::now(),
            mode,
            known_remote_tip: None,
            min_kel_seq: None,
            required_capability: None,
        };

        let result = bridge.verify_signer(&request).unwrap();
        assert!(
            result.is_rejected(),
            "corrupt identity must be Rejected in {:?} mode",
            mode
        );
    }
}
