use std::str::FromStr;
use chrono::{Duration, Utc};

use auths_id::policy::PolicyBuilder;
use auths_radicle::bridge::{EnforcementMode, RadicleAuthsBridge, VerifyRequest};
use auths_radicle::verify::DefaultBridge;
use radicle_core::{Did, RepoId};

use super::helpers::{DeviceFixture, MockStorage, make_key_state, register_device};

#[test]
fn revoked_device_rejected_in_enforce() {
    let mut storage = MockStorage::new();
    let identity_did: Did = "did:keri:EAlice".parse().unwrap();
    let repo_id = RepoId::from_str("rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5").unwrap();
    let device = DeviceFixture::new(1);

    storage.add_identity(identity_did.clone(), make_key_state("EAlice", 1));

    // Register device as REVOKED
    register_device(&mut storage, &device, &identity_did, &repo_id, true, vec![]);

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
    assert!(result.is_rejected());
    assert!(result.reason().contains("revoked"));
}

#[test]
fn revoked_device_warns_in_observe() {
    let mut storage = MockStorage::new();
    let identity_did: Did = "did:keri:EAlice".parse().unwrap();
    let repo_id = RepoId::from_str("rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5").unwrap();
    let device = DeviceFixture::new(1);

    storage.add_identity(identity_did.clone(), make_key_state("EAlice", 1));
    register_device(&mut storage, &device, &identity_did, &repo_id, true, vec![]);

    let bridge = DefaultBridge::with_storage(storage);
    let request = VerifyRequest {
        signer_key: &device.key,
        repo_id: &repo_id,
        now: Utc::now(),
        mode: EnforcementMode::Observe,
        known_remote_tip: None,
        min_kel_seq: None,
        required_capability: None,
    };

    let result = bridge.verify_signer(&request).unwrap();
    // In observe mode, should allow but Warn
    assert!(result.is_allowed());
    assert!(matches!(result, auths_radicle::bridge::VerifyResult::Warn { .. }));
}

#[test]
fn expired_attestation_rejected() {
    let mut storage = MockStorage::new();
    let identity_did: Did = "did:keri:EAlice".parse().unwrap();
    let repo_id = RepoId::from_str("rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5").unwrap();
    let device = DeviceFixture::new(1);

    storage.add_identity(identity_did.clone(), make_key_state("EAlice", 1));

    // Create an attestation that EXPIRES in the past
    let mut attestation = super::helpers::make_test_attestation(&identity_did, &device.did, &repo_id, false, vec![]);
    attestation.expires_at = Some(Utc::now() - Duration::days(1));

    storage.add_attestation(device.did.clone(), identity_did.clone(), attestation);
    storage.link_device_to_identity(device.did.clone(), identity_did.clone(), repo_id);

    let policy = PolicyBuilder::new().not_expired().build();
    let bridge = DefaultBridge::new(storage, policy);

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
    assert!(result.is_rejected());
    assert!(result.reason().contains("expired"));
}
