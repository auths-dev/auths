//! Revocation E2E tests (fn-1.15).
//!
//! Tests that revocation stops a device from being authorized.

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
        last_event_said: Said::new_unchecked("ESaid".to_string()),
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

/// Enforce mode: device accepted before revocation, rejected after.
#[test]
fn enforce_revocation_rejects_device() {
    let key: [u8; 32] = [50; 32];
    let did = ed25519_to_did_key(&key);
    let identity_did = "did:keri:ERevTest";
    let repo_id = "test-repo";

    // Before revocation
    let mut storage = MockStorage::new();
    storage
        .key_states
        .insert(identity_did.to_string(), make_key_state("ERevTest", 2));
    storage.attestations.insert(
        (did.clone(), identity_did.to_string()),
        make_attestation(identity_did, &did, false),
    );
    storage
        .device_to_identity
        .insert((did.clone(), repo_id.to_string()), identity_did.to_string());
    storage
        .identity_tips
        .insert(identity_did.to_string(), [0xAA; 20]);

    let bridge = DefaultBridge::with_storage(storage);
    let request = VerifyRequest {
        signer_key: &key,
        repo_id,
        now: Utc::now(),
        mode: EnforcementMode::Enforce,
        known_remote_tip: None,
        min_kel_seq: None,
        required_capability: None,
    };
    let result = bridge.verify_signer(&request).unwrap();
    assert!(result.is_allowed(), "before revocation: should be allowed");

    // After revocation (simulate storage update)
    let mut revoked_storage = MockStorage::new();
    revoked_storage
        .key_states
        .insert(identity_did.to_string(), make_key_state("ERevTest", 3));
    revoked_storage.attestations.insert(
        (did.clone(), identity_did.to_string()),
        make_attestation(identity_did, &did, true),
    );
    revoked_storage
        .device_to_identity
        .insert((did.clone(), repo_id.to_string()), identity_did.to_string());
    revoked_storage
        .identity_tips
        .insert(identity_did.to_string(), [0xBB; 20]);

    let revoked_bridge = DefaultBridge::with_storage(revoked_storage);
    let result = revoked_bridge.verify_signer(&request).unwrap();
    assert!(result.is_rejected(), "after revocation: should be rejected");
}

/// Observe mode: device accepted before revocation, warned after.
#[test]
fn observe_revocation_warns_device() {
    let key: [u8; 32] = [51; 32];
    let did = ed25519_to_did_key(&key);
    let identity_did = "did:keri:ERevObs";
    let repo_id = "test-repo";

    let mut storage = MockStorage::new();
    storage
        .key_states
        .insert(identity_did.to_string(), make_key_state("ERevObs", 3));
    storage.attestations.insert(
        (did.clone(), identity_did.to_string()),
        make_attestation(identity_did, &did, true), // revoked
    );
    storage
        .device_to_identity
        .insert((did.clone(), repo_id.to_string()), identity_did.to_string());
    storage
        .identity_tips
        .insert(identity_did.to_string(), [0xAA; 20]);

    let bridge = DefaultBridge::with_storage(storage);
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
        matches!(result, VerifyResult::Warn { .. }),
        "observe mode: revoked → Warn"
    );
}

/// Revocation of one device does not affect other authorized devices.
#[test]
fn revocation_does_not_affect_other_devices() {
    let key_a: [u8; 32] = [60; 32];
    let key_b: [u8; 32] = [61; 32];
    let did_a = ed25519_to_did_key(&key_a);
    let did_b = ed25519_to_did_key(&key_b);
    let identity_did = "did:keri:ERevMulti";
    let repo_id = "test-repo";

    let mut storage = MockStorage::new();
    storage
        .key_states
        .insert(identity_did.to_string(), make_key_state("ERevMulti", 3));
    // Device A: revoked
    storage.attestations.insert(
        (did_a.clone(), identity_did.to_string()),
        make_attestation(identity_did, &did_a, true),
    );
    // Device B: still valid
    storage.attestations.insert(
        (did_b.clone(), identity_did.to_string()),
        make_attestation(identity_did, &did_b, false),
    );
    storage.device_to_identity.insert(
        (did_a.clone(), repo_id.to_string()),
        identity_did.to_string(),
    );
    storage.device_to_identity.insert(
        (did_b.clone(), repo_id.to_string()),
        identity_did.to_string(),
    );
    storage
        .identity_tips
        .insert(identity_did.to_string(), [0xAA; 20]);

    let bridge = DefaultBridge::with_storage(storage);

    let req_a = VerifyRequest {
        signer_key: &key_a,
        repo_id,
        now: Utc::now(),
        mode: EnforcementMode::Enforce,
        known_remote_tip: None,
        min_kel_seq: None,
        required_capability: None,
    };
    let req_b = VerifyRequest {
        signer_key: &key_b,
        repo_id,
        now: Utc::now(),
        mode: EnforcementMode::Enforce,
        known_remote_tip: None,
        min_kel_seq: None,
        required_capability: None,
    };

    assert!(
        bridge.verify_signer(&req_a).unwrap().is_rejected(),
        "device A should be rejected"
    );
    assert!(
        bridge.verify_signer(&req_b).unwrap().is_allowed(),
        "device B should still be allowed"
    );
}

/// Re-authorization after revocation works.
#[test]
fn reauthorization_after_revocation() {
    let key: [u8; 32] = [70; 32];
    let did = ed25519_to_did_key(&key);
    let identity_did = "did:keri:EReauth";
    let repo_id = "test-repo";

    // New attestation (not revoked) replaces the old one
    let mut storage = MockStorage::new();
    storage
        .key_states
        .insert(identity_did.to_string(), make_key_state("EReauth", 4));
    storage.attestations.insert(
        (did.clone(), identity_did.to_string()),
        make_attestation(identity_did, &did, false), // new attestation, not revoked
    );
    storage
        .device_to_identity
        .insert((did.clone(), repo_id.to_string()), identity_did.to_string());
    storage
        .identity_tips
        .insert(identity_did.to_string(), [0xAA; 20]);

    let bridge = DefaultBridge::with_storage(storage);
    let request = VerifyRequest {
        signer_key: &key,
        repo_id,
        now: Utc::now(),
        mode: EnforcementMode::Enforce,
        known_remote_tip: None,
        min_kel_seq: None,
        required_capability: None,
    };
    let result = bridge.verify_signer(&request).unwrap();
    assert!(
        result.is_allowed(),
        "re-authorized device should be Verified"
    );
}
