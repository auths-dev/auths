use std::str::FromStr;
use chrono::Utc;

use auths_radicle::bridge::{EnforcementMode, RadicleAuthsBridge, VerifyRequest, VerifyResult};
use auths_radicle::verify::DefaultBridge;
use radicle_core::{Did, RepoId};

use super::helpers::{MockStorage, make_key_state, make_test_attestation};

#[test]
fn stale_attestation_warning_in_observe() {
    let mut storage = MockStorage::new();
    let identity_did: Did = "did:keri:EAlice".parse().unwrap();
    let repo_id = RepoId::from_str("rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5").unwrap();
    let signer_key = radicle_crypto::PublicKey::from([1; 32]);
    let device_did = Did::from(signer_key);

    storage.add_identity(identity_did.clone(), make_key_state("EAlice", 1));
    // Valid attestation in storage
    storage.add_attestation(
        device_did.clone(),
        identity_did.clone(),
        make_test_attestation(&identity_did, &device_did, &repo_id, false, vec![]),
    );
    storage.link_device_to_identity(device_did.clone(), identity_did.clone(), repo_id);

    // Local tip is AA
    storage.set_identity_tip(identity_did.clone(), [0xAA; 20]);

    let bridge = DefaultBridge::with_storage(storage);

    // Gossip announces tip BB (we are stale)
    let request = VerifyRequest {
        signer_key: &signer_key,
        repo_id: &repo_id,
        now: Utc::now(),
        mode: EnforcementMode::Observe,
        known_remote_tip: Some([0xBB; 20]),
        min_kel_seq: None,
        required_capability: None,
    };

    let result = bridge.verify_signer(&request).unwrap();

    // In Observe mode, staleness should be a Warn, not a reject
    assert!(result.is_allowed());
    assert!(matches!(result, VerifyResult::Warn { .. }));
}

#[test]
fn local_identity_not_available_quarantined_in_enforce() {
    let mut storage = MockStorage::new();
    let identity_did: Did = "did:keri:EAlice".parse().unwrap();
    let repo_id = RepoId::from_str("rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5").unwrap();
    let signer_key = radicle_crypto::PublicKey::from([1; 32]);
    let device_did = Did::from(signer_key);

    // Identity repo tip is NOT set in local storage
    register_device_to_storage(&mut storage, &signer_key, &device_did, &identity_did, &repo_id);

    let bridge = DefaultBridge::with_storage(storage);

    // But gossip tells us there IS a tip BB
    let request = VerifyRequest {
        signer_key: &signer_key,
        repo_id: &repo_id,
        now: Utc::now(),
        mode: EnforcementMode::Enforce,
        known_remote_tip: Some([0xBB; 20]),
        min_kel_seq: None,
        required_capability: None,
    };

    let result = bridge.verify_signer(&request).unwrap();

    // Should return Quarantine because we have no local copy of identity repo
    assert!(matches!(result, VerifyResult::Quarantine { .. }));
    assert!(result.reason().contains("not available locally"));
}

fn register_device_to_storage(
    storage: &mut MockStorage,
    _key: &radicle_crypto::PublicKey,
    device_did: &Did,
    identity_did: &Did,
    repo_id: &RepoId,
) {
    storage.add_identity(identity_did.clone(), make_key_state("EAlice", 1));
    storage.add_attestation(
        device_did.clone(),
        identity_did.clone(),
        make_test_attestation(identity_did, device_did, repo_id, false, vec![]),
    );
    storage.link_device_to_identity(device_did.clone(), identity_did.clone(), *repo_id);
}

#[test]
fn corrupt_storage_hard_reject() {
    use auths_radicle::bridge::BridgeError;
    use auths_verifier::core::Attestation;
    use auths_id::keri::KeyState;

    struct CorruptStorage {
        layout: auths_radicle::refs::Layout,
    }
    impl auths_radicle::verify::AuthsStorage for CorruptStorage {
        fn layout(&self) -> &auths_radicle::refs::Layout {
            &self.layout
        }
        fn load_key_state(&self, _: &Did) -> Result<KeyState, BridgeError> {
            Ok(make_key_state("EAlice", 1))
        }
        fn load_attestation(&self, _: &Did, _: &Did) -> Result<Attestation, BridgeError> {
            unreachable!()
        }
        fn find_identity_for_device(
            &self,
            _device_did: &Did,
            _repo_id: &RepoId,
        ) -> Result<Option<Did>, BridgeError> {
            Err(BridgeError::IdentityCorrupt {
                did: auths_verifier::IdentityDID::new("unknown"),
                reason: "damaged files".into(),
            })
        }
        fn local_identity_tip(&self, _: &Did) -> Result<Option<[u8; 20]>, BridgeError> {
            Ok(None)
        }
        fn list_devices(&self, _: &Did) -> Result<Vec<Did>, BridgeError> {
            Ok(Vec::new())
        }
    }

    let bridge = DefaultBridge::with_storage(CorruptStorage {
        layout: auths_radicle::refs::Layout::radicle(),
    });
    let signer_key = radicle_crypto::PublicKey::from([1; 32]);
    let repo_id = RepoId::from_str("rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5").unwrap();

    let request = VerifyRequest {
        signer_key: &signer_key,
        repo_id: &repo_id,
        now: Utc::now(),
        mode: EnforcementMode::Enforce,
        known_remote_tip: None,
        min_kel_seq: None,
        required_capability: None,
    };

    let result = bridge.verify_signer(&request).unwrap();
    assert!(result.is_rejected());
    assert!(result.reason().contains("identity corrupt"));
}
