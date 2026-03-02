use std::collections::HashMap;

use auths_id::keri::KeyState;
use auths_radicle::bridge::BridgeError;
use auths_radicle::verify::AuthsStorage;
use auths_verifier::IdentityDID;
use auths_verifier::core::{Attestation, Capability};
use auths_verifier::keri::{Prefix, Said};
use auths_verifier::types::DeviceDID;

pub struct MockStorage {
    pub key_states: HashMap<String, KeyState>,
    pub attestations: HashMap<(String, String), Attestation>,
    pub device_to_identity: HashMap<(String, String), String>,
    pub identity_tips: HashMap<String, [u8; 20]>,
}

impl MockStorage {
    pub fn new() -> Self {
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

pub fn make_key_state(prefix: &str, seq: u64) -> KeyState {
    KeyState {
        prefix: Prefix::new_unchecked(prefix.to_string()),
        sequence: seq,
        current_keys: vec!["DTestKey".to_string()],
        next_commitment: vec![],
        last_event_said: Said::new_unchecked(format!("ESaid{seq}")),
        is_abandoned: false,
    }
}

pub fn make_test_attestation(
    issuer: &str,
    device_did: &str,
    rid: &str,
    revoked: bool,
    capabilities: Vec<Capability>,
) -> Attestation {
    use chrono::Utc;
    Attestation {
        version: 1,
        rid: rid.to_string(),
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
        capabilities,
        delegated_by: None,
        signer_type: None,
    }
}

pub struct DeviceFixture {
    pub key: [u8; 32],
    pub did: String,
}

impl DeviceFixture {
    pub fn new(seed: u8) -> Self {
        let key = [seed; 32];
        let did = auths_id::identity::ed25519_to_did_key(&key);
        Self { key, did }
    }
}

pub fn register_device(
    storage: &mut MockStorage,
    device: &DeviceFixture,
    identity_did: &str,
    repo_id: &str,
    revoked: bool,
    capabilities: Vec<Capability>,
) {
    storage.attestations.insert(
        (device.did.clone(), identity_did.to_string()),
        make_test_attestation(identity_did, &device.did, repo_id, revoked, capabilities),
    );
    storage.device_to_identity.insert(
        (device.did.clone(), repo_id.to_string()),
        identity_did.to_string(),
    );
}
