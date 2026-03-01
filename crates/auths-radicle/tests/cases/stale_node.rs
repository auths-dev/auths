//! Stale-node E2E tests (fn-1.16).
//!
//! **This is the most important test in the suite.** It validates the primary
//! security USP of the Radicle integration: safe behavior under the stale-node
//! adversarial scenario.

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

fn make_key_state(prefix: &str, seq: u64) -> KeyState {
    KeyState {
        prefix: Prefix::new_unchecked(prefix.to_string()),
        sequence: seq,
        current_keys: vec!["DTestKey".to_string()],
        next_commitment: vec![],
        last_event_said: Said::new_unchecked(format!("ESaid{seq}")),
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

fn setup_scenario() -> ([u8; 32], String, &'static str, &'static str) {
    let key: [u8; 32] = [0xDE; 32];
    let did = ed25519_to_did_key(&key);
    (key, did, "did:keri:EStaleNode", "test-repo")
}

fn build_storage(
    identity_did: &str,
    device_did: &str,
    repo_id: &str,
    seq: u64,
    revoked: bool,
    tip: [u8; 20],
) -> MockStorage {
    let prefix = identity_did
        .strip_prefix("did:keri:")
        .unwrap_or(identity_did);
    let mut storage = MockStorage::new();
    storage
        .key_states
        .insert(identity_did.to_string(), make_key_state(prefix, seq));
    storage.attestations.insert(
        (device_did.to_string(), identity_did.to_string()),
        make_attestation(identity_did, device_did, revoked),
    );
    storage.device_to_identity.insert(
        (device_did.to_string(), repo_id.to_string()),
        identity_did.to_string(),
    );
    storage.identity_tips.insert(identity_did.to_string(), tip);
    storage
}

/// Observe: stale node accepts with Warn, converges to Rejected after sync.
#[test]
fn observe_stale_node_accepts_then_converges() {
    let (key, did, identity_did, repo_id) = setup_scenario();

    // Stale storage: seq 2, no revocation, tip AA
    let storage = build_storage(identity_did, &did, repo_id, 2, false, [0xAA; 20]);
    let bridge = DefaultBridge::with_storage(storage);

    // No gossip info — stale node accepts
    let request = VerifyRequest {
        signer_key: &key,
        repo_id,
        now: Utc::now(),
        mode: EnforcementMode::Observe,
        known_remote_tip: None,
        min_kel_seq: None,
        required_capability: None,
    };
    let result = bridge.verify_signer(&request).unwrap();
    assert!(
        result.is_allowed(),
        "stale node should accept without gossip"
    );

    // After sync: seq 3, revoked, tip BB
    let synced = build_storage(identity_did, &did, repo_id, 3, true, [0xBB; 20]);
    let synced_bridge = DefaultBridge::with_storage(synced);
    let result = synced_bridge.verify_signer(&request).unwrap();
    assert!(
        matches!(result, VerifyResult::Warn { .. }),
        "observe + revoked → Warn"
    );
}

/// Enforce, staleness detected: stale node quarantines, resolves after sync.
#[test]
fn enforce_staleness_detected_quarantine_then_resolves() {
    let (key, did, identity_did, repo_id) = setup_scenario();

    let storage = build_storage(identity_did, &did, repo_id, 2, false, [0xAA; 20]);
    let bridge = DefaultBridge::with_storage(storage);

    let request = VerifyRequest {
        signer_key: &key,
        repo_id,
        now: Utc::now(),
        mode: EnforcementMode::Enforce,
        known_remote_tip: Some([0xBB; 20]), // different from local [0xAA; 20]
        min_kel_seq: None,
        required_capability: None,
    };
    let result = bridge.verify_signer(&request).unwrap();
    assert!(
        matches!(result, VerifyResult::Quarantine { .. }),
        "stale → Quarantine"
    );

    // After sync
    let synced = build_storage(identity_did, &did, repo_id, 3, true, [0xBB; 20]);
    let synced_bridge = DefaultBridge::with_storage(synced);
    let synced_request = VerifyRequest {
        known_remote_tip: Some([0xBB; 20]),
        ..request
    };
    let result = synced_bridge.verify_signer(&synced_request).unwrap();
    assert!(result.is_rejected(), "after sync, revoked → Rejected");
}

/// Enforce, no staleness signal: stale node accepts (irreducible risk).
///
/// This is the documented "irreducible risk" scenario: a fully disconnected
/// node has no gossip information and must rely on local state alone. If the
/// local state says the device is authorized, we accept it. This is correct
/// behavior — the alternative (rejecting all devices when disconnected) would
/// make the system unusable for offline-first workflows.
#[test]
fn enforce_no_staleness_signal_accepts_irreducible_risk() {
    let (key, did, identity_did, repo_id) = setup_scenario();

    let storage = build_storage(identity_did, &did, repo_id, 2, false, [0xAA; 20]);
    let bridge = DefaultBridge::with_storage(storage);

    let request = VerifyRequest {
        signer_key: &key,
        repo_id,
        now: Utc::now(),
        mode: EnforcementMode::Enforce,
        known_remote_tip: None, // disconnected
        min_kel_seq: None,
        required_capability: None,
    };
    let result = bridge.verify_signer(&request).unwrap();
    assert!(
        result.is_allowed(),
        "irreducible risk: disconnected node accepts based on local state"
    );
}

/// Below min_kel_seq → hard Rejected in both modes.
#[test]
fn below_min_kel_seq_hard_reject_both_modes() {
    let (key, did, identity_did, repo_id) = setup_scenario();

    for mode in [EnforcementMode::Observe, EnforcementMode::Enforce] {
        let storage = build_storage(identity_did, &did, repo_id, 1, false, [0xAA; 20]);
        let bridge = DefaultBridge::with_storage(storage);

        let request = VerifyRequest {
            signer_key: &key,
            repo_id,
            now: Utc::now(),
            mode,
            known_remote_tip: None,
            min_kel_seq: Some(5),
            required_capability: None,
        };
        let result = bridge.verify_signer(&request).unwrap();
        assert!(
            result.is_rejected(),
            "below min_kel_seq must be Rejected in {:?} mode",
            mode
        );
    }
}

/// Tamper: corrupt identity → Rejected regardless of mode.
#[test]
fn tamper_forged_kel_rejected() {
    let key: [u8; 32] = [0xDE; 32];
    let _did = ed25519_to_did_key(&key);
    let identity_did = "did:keri:ETamper";
    let repo_id = "test-repo";

    struct CorruptKelStorage {
        identity_did: String,
    }

    impl AuthsStorage for CorruptKelStorage {
        fn load_key_state(&self, _: &str) -> Result<KeyState, BridgeError> {
            Err(BridgeError::IdentityCorrupt(
                "forged KEL event mid-chain: SAID mismatch".into(),
            ))
        }
        fn load_attestation(&self, _: &str, _: &str) -> Result<Attestation, BridgeError> {
            unreachable!()
        }
        fn find_identity_for_device(
            &self,
            _: &str,
            _: &str,
        ) -> Result<Option<String>, BridgeError> {
            Ok(Some(self.identity_did.clone()))
        }
        fn local_identity_tip(&self, _: &str) -> Result<Option<[u8; 20]>, BridgeError> {
            Ok(None)
        }
    }

    for mode in [EnforcementMode::Observe, EnforcementMode::Enforce] {
        let storage = CorruptKelStorage {
            identity_did: identity_did.to_string(),
        };
        let bridge = DefaultBridge::with_storage(storage);
        let request = VerifyRequest {
            signer_key: &key,
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
            "tampered KEL must be Rejected in {:?} mode",
            mode
        );
    }
}
