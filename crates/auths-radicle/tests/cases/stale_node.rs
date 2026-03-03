use std::str::FromStr;
use chrono::Utc;

use auths_radicle::bridge::{EnforcementMode, RadicleAuthsBridge, VerifyRequest};
use auths_radicle::verify::DefaultBridge;
use radicle_core::{Did, RepoId};

use super::helpers::{DeviceFixture, MockStorage, make_key_state, register_device};

#[test]
fn stale_identity_repo_rejected_in_enforce() {
    let mut storage = MockStorage::new();
    let identity_did: Did = "did:keri:EAlice".parse().unwrap();
    let repo_id = RepoId::from_str("rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5").unwrap();
    let device = DeviceFixture::new(1);

    storage.add_identity(identity_did.clone(), make_key_state("EAlice", 1));
    register_device(&mut storage, &device, &identity_did, &repo_id, false, vec![]);

    // Local tip is AA
    storage.set_identity_tip(identity_did.clone(), [0xAA; 20]);

    let bridge = DefaultBridge::with_storage(storage);

    // Request announces a NEWER tip BB
    let request = VerifyRequest {
        signer_key: &device.key,
        repo_id: &repo_id,
        now: Utc::now(),
        mode: EnforcementMode::Enforce,
        known_remote_tip: Some([0xBB; 20]),
        min_kel_seq: None,
        required_capability: None,
    };

    let result = bridge.verify_signer(&request).unwrap();

    // Should return Quarantine (fetch more)
    assert!(matches!(
        result,
        auths_radicle::bridge::VerifyResult::Quarantine { .. }
    ));
    assert!(result.reason().contains("stale"));
}

#[test]
fn missing_identity_repo_quarantined_in_enforce() {
    let mut storage = MockStorage::new();
    let identity_did: Did = "did:keri:EAlice".parse().unwrap();
    let repo_id = RepoId::from_str("rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5").unwrap();
    let device = DeviceFixture::new(1);

    // Identity repo is NOT in storage (load_key_state will return error)
    register_device(&mut storage, &device, &identity_did, &repo_id, false, vec![]);

    let bridge = DefaultBridge::with_storage(storage);
    let request = VerifyRequest {
        signer_key: &device.key,
        repo_id: &repo_id,
        now: Utc::now(),
        mode: EnforcementMode::Enforce,
        known_remote_tip: None,
        min_kel_seq: None,
        required_capability: None,
    };

    let result = bridge.verify_signer(&request).unwrap();
    assert!(matches!(
        result,
        auths_radicle::bridge::VerifyResult::Quarantine { .. }
    ));
    assert!(result.reason().contains("identity repo missing"));
}

#[test]
fn min_kel_seq_violation_rejected() {
    let mut storage = MockStorage::new();
    let identity_did: Did = "did:keri:EAlice".parse().unwrap();
    let repo_id = RepoId::from_str("rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5").unwrap();
    let device = DeviceFixture::new(1);

    // Identity is at sequence 5
    storage.add_identity(identity_did.clone(), make_key_state("EAlice", 5));
    register_device(&mut storage, &device, &identity_did, &repo_id, false, vec![]);

    let bridge = DefaultBridge::with_storage(storage);

    // Request specifies MIN sequence 10 (future binding)
    let request = VerifyRequest {
        signer_key: &device.key,
        repo_id: &repo_id,
        now: Utc::now(),
        mode: EnforcementMode::Enforce,
        known_remote_tip: None,
        min_kel_seq: Some(10),
        required_capability: None,
    };

    let result = bridge.verify_signer(&request).unwrap();
    assert!(result.is_rejected());
    assert!(result.reason().contains("below binding minimum"));
}

#[test]
fn corrupt_identity_hard_rejected() {
    use auths_radicle::bridge::BridgeError;
    use auths_verifier::core::Attestation;
    use auths_id::keri::KeyState;

    struct CorruptKelStorage {
        layout: auths_radicle::refs::Layout,
    }
    impl auths_radicle::verify::AuthsStorage for CorruptKelStorage {
        fn layout(&self) -> &auths_radicle::refs::Layout {
            &self.layout
        }
        fn load_key_state(&self, _: &Did) -> Result<KeyState, BridgeError> {
            Err(BridgeError::IdentityCorrupt("broken chain".into()))
        }
        fn load_attestation(&self, _: &Did, _: &Did) -> Result<Attestation, BridgeError> {
            unreachable!()
        }
        fn find_identity_for_device(
            &self,
            _: &Did,
            _: &RepoId,
        ) -> Result<Option<Did>, BridgeError> {
            Ok(Some("did:keri:EAlice".parse().unwrap()))
        }
        fn local_identity_tip(&self, _: &Did) -> Result<Option<[u8; 20]>, BridgeError> {
            Ok(None)
        }
        fn list_devices(&self, _: &Did) -> Result<Vec<Did>, BridgeError> {
            Ok(Vec::new())
        }
    }

    let bridge = DefaultBridge::with_storage(CorruptKelStorage {
        layout: auths_radicle::refs::Layout::radicle(),
    });
    let key = radicle_crypto::PublicKey::from([1; 32]);
    let repo_id = RepoId::from_str("rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5").unwrap();

    let request = VerifyRequest {
        signer_key: &key,
        repo_id: &repo_id,
        now: Utc::now(),
        mode: EnforcementMode::Observe, // even in observe mode!
        known_remote_tip: None,
        min_kel_seq: None,
        required_capability: None,
    };

    let result = bridge.verify_signer(&request).unwrap();
    assert!(result.is_rejected());
    assert!(result.reason().contains("identity corrupt"));
}
