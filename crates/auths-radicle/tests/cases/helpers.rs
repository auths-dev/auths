use std::collections::HashMap;

use auths_id::keri::KeyState;
use auths_radicle::bridge::BridgeError;
use auths_radicle::refs::Layout;
use auths_radicle::verify::AuthsStorage;
use auths_verifier::IdentityDID;
use auths_verifier::core::{Attestation, Capability};
use auths_verifier::keri::{Prefix, Said};
use auths_verifier::types::DeviceDID;
use radicle_core::{Did, RepoId};
use radicle_crypto::PublicKey;

pub struct MockStorage {
    pub key_states: HashMap<Did, KeyState>,
    pub attestations: HashMap<(Did, Did), Attestation>,
    pub device_to_identity: HashMap<(Did, RepoId), Did>,
    pub identity_tips: HashMap<Did, [u8; 20]>,
    pub layout: Layout,
}

impl MockStorage {
    pub fn new() -> Self {
        Self {
            key_states: HashMap::new(),
            attestations: HashMap::new(),
            device_to_identity: HashMap::new(),
            identity_tips: HashMap::new(),
            layout: Layout::radicle(),
        }
    }

    pub fn add_identity(&mut self, identity_did: Did, key_state: KeyState) {
        self.key_states.insert(identity_did, key_state);
    }

    pub fn add_attestation(&mut self, device_did: Did, identity_did: Did, attestation: Attestation) {
        self.attestations.insert((device_did, identity_did), attestation);
    }

    pub fn link_device_to_identity(&mut self, device_did: Did, identity_did: Did, repo_id: RepoId) {
        self.device_to_identity.insert((device_did, repo_id), identity_did);
    }

    pub fn set_identity_tip(&mut self, identity_did: Did, tip: [u8; 20]) {
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

pub fn make_key_state(prefix: &str, seq: u64) -> KeyState {
    KeyState {
        prefix: Prefix::new_unchecked(prefix.to_string()),
        sequence: seq,
        current_keys: vec!["DTestKey".to_string()],
        next_commitment: vec![],
        last_event_said: Said::new_unchecked(format!("ESaid{seq}")),
        is_abandoned: false,
        threshold: 1,
        next_threshold: 1,
    }
}

pub fn make_test_attestation(
    issuer: &Did,
    device_did: &Did,
    rid: &RepoId,
    revoked: bool,
    capabilities: Vec<Capability>,
) -> Attestation {
    use chrono::Utc;
    Attestation {
        version: 1,
        rid: rid.to_string(),
        issuer: IdentityDID::new(issuer.to_string()),
        subject: DeviceDID::new(device_did.to_string()),
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
    pub key: PublicKey,
    pub did: Did,
}

impl DeviceFixture {
    pub fn new(seed: u8) -> Self {
        let key_bytes = [seed; 32];
        let key = PublicKey::from(key_bytes);
        let did = Did::from(key);
        Self { key, did }
    }
}

pub fn register_device(
    storage: &mut MockStorage,
    device: &DeviceFixture,
    identity_did: &Did,
    repo_id: &RepoId,
    revoked: bool,
    capabilities: Vec<Capability>,
) {
    storage.attestations.insert(
        (device.did.clone(), identity_did.clone()),
        make_test_attestation(identity_did, &device.did, repo_id, revoked, capabilities),
    );
    storage.device_to_identity.insert(
        (device.did.clone(), *repo_id),
        identity_did.clone(),
    );
}
