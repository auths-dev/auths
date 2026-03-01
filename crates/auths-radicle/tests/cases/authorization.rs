//! Multi-device authorization E2E tests (fn-1.14).
//!
//! Tests the full flow: identity → attestation → verification.
//! Uses MockStorage to simulate RIP-X layout.

use chrono::Utc;
use std::collections::HashMap;

use auths_id::identity::ed25519_to_did_key;
use auths_id::keri::KeyState;
use auths_id::policy::PolicyBuilder;
use auths_radicle::bridge::{BridgeError, EnforcementMode, RadicleAuthsBridge, VerifyRequest};
use auths_radicle::verify::{AuthsStorage, DefaultBridge};
use auths_verifier::IdentityDID;
use auths_verifier::core::{Attestation, Capability};
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

fn make_attestation_with_caps(
    issuer: &str,
    device_did: &str,
    capabilities: Vec<Capability>,
) -> Attestation {
    Attestation {
        version: 1,
        rid: "test-project".to_string(),
        issuer: IdentityDID::new(issuer),
        subject: DeviceDID::new(device_did),
        device_public_key: vec![0; 32],
        identity_signature: vec![0; 64],
        device_signature: vec![0; 64],
        revoked_at: None,
        expires_at: None,
        timestamp: None,
        note: None,
        payload: None,
        role: None,
        capabilities,
        delegated_by: None,
        signer_type: None,
    }
}

/// Full flow: authorized device → Verified.
#[test]
fn authorized_device_verified() {
    let mut storage = MockStorage::new();
    let identity_did = "did:keri:EMultiDevice";
    let repo_id = "test-project";

    // Two devices under the same identity
    let key_a: [u8; 32] = [10; 32];
    let key_b: [u8; 32] = [20; 32];
    let did_a = ed25519_to_did_key(&key_a);
    let did_b = ed25519_to_did_key(&key_b);

    storage.key_states.insert(
        identity_did.to_string(),
        KeyState {
            prefix: Prefix::new_unchecked("EMultiDevice".to_string()),
            sequence: 1,
            current_keys: vec!["DTestKey".to_string()],
            next_commitment: vec![],
            last_event_said: Said::new_unchecked("ESaid1".to_string()),
            is_abandoned: false,
        },
    );

    storage.attestations.insert(
        (did_a.clone(), identity_did.to_string()),
        make_attestation_with_caps(identity_did, &did_a, vec![Capability::sign_commit()]),
    );
    storage.attestations.insert(
        (did_b.clone(), identity_did.to_string()),
        make_attestation_with_caps(identity_did, &did_b, vec![Capability::sign_commit()]),
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

    let policy = PolicyBuilder::new().not_revoked().not_expired().build();
    let bridge = DefaultBridge::new(storage, policy);

    for key in [key_a, key_b] {
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
        assert!(result.is_allowed(), "authorized device should be Verified");
    }
}

/// Unauthorized device (no attestation) → Rejected.
#[test]
fn unauthorized_device_rejected() {
    let storage = MockStorage::new();
    let key: [u8; 32] = [99; 32];

    let bridge = DefaultBridge::with_storage(storage);
    let request = VerifyRequest {
        signer_key: &key,
        repo_id: "test-project",
        now: Utc::now(),
        mode: EnforcementMode::Enforce,
        known_remote_tip: None,
        min_kel_seq: None,
        required_capability: None,
    };
    let result = bridge.verify_signer(&request).unwrap();
    assert!(
        !result.is_allowed(),
        "unauthorized device should not be allowed"
    );
}

/// Device with wrong capabilities → Rejected.
#[test]
fn wrong_capability_rejected() {
    let mut storage = MockStorage::new();
    let identity_did = "did:keri:ECapTest";
    let repo_id = "test-project";
    let key: [u8; 32] = [30; 32];
    let did = ed25519_to_did_key(&key);

    storage.key_states.insert(
        identity_did.to_string(),
        KeyState {
            prefix: Prefix::new_unchecked("ECapTest".to_string()),
            sequence: 0,
            current_keys: vec!["DTestKey".to_string()],
            next_commitment: vec![],
            last_event_said: Said::new_unchecked("ESaid".to_string()),
            is_abandoned: false,
        },
    );
    storage.attestations.insert(
        (did.clone(), identity_did.to_string()),
        make_attestation_with_caps(identity_did, &did, vec![Capability::sign_release()]),
    );
    storage
        .device_to_identity
        .insert((did.clone(), repo_id.to_string()), identity_did.to_string());
    storage
        .identity_tips
        .insert(identity_did.to_string(), [0xAA; 20]);

    let policy = PolicyBuilder::new().not_revoked().not_expired().build();
    let bridge = DefaultBridge::new(storage, policy);

    let request = VerifyRequest {
        signer_key: &key,
        repo_id,
        now: Utc::now(),
        mode: EnforcementMode::Enforce,
        known_remote_tip: None,
        min_kel_seq: None,
        required_capability: Some("sign_commit"), // requires sign_commit, has sign_release
    };
    let result = bridge.verify_signer(&request).unwrap();
    assert!(result.is_rejected(), "wrong capability should be rejected");
}
