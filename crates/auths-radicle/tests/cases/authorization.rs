use std::str::FromStr;
use chrono::Utc;

use auths_id::policy::PolicyBuilder;
use auths_radicle::bridge::{EnforcementMode, RadicleAuthsBridge, VerifyRequest};
use auths_radicle::verify::DefaultBridge;
use auths_verifier::core::Capability;
use radicle_core::{Did, RepoId};
use radicle_crypto::PublicKey;

use super::helpers::{MockStorage, make_key_state, make_test_attestation};

#[test]
fn authorized_device_verified() {
    let mut storage = MockStorage::new();
    let identity_did: Did = "did:keri:EMultiDevice".parse().unwrap();
    let repo_id = RepoId::from_str("rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5").unwrap();

    let key_a = PublicKey::from([10; 32]);
    let key_b = PublicKey::from([20; 32]);
    let did_a = Did::from(key_a);
    let did_b = Did::from(key_b);

    storage
        .key_states
        .insert(identity_did.clone(), make_key_state("EMultiDevice", 1));

    storage.attestations.insert(
        (did_a.clone(), identity_did.clone()),
        make_test_attestation(
            &identity_did,
            &did_a,
            &repo_id,
            false,
            vec![Capability::sign_commit()],
        ),
    );
    storage.attestations.insert(
        (did_b.clone(), identity_did.clone()),
        make_test_attestation(
            &identity_did,
            &did_b,
            &repo_id,
            false,
            vec![Capability::sign_commit()],
        ),
    );
    storage.device_to_identity.insert(
        (did_a.clone(), repo_id),
        identity_did.clone(),
    );
    storage.device_to_identity.insert(
        (did_b.clone(), repo_id),
        identity_did.clone(),
    );
    storage
        .identity_tips
        .insert(identity_did.clone(), [0xAA; 20]);

    let policy = PolicyBuilder::new().not_revoked().not_expired().build();
    let bridge = DefaultBridge::new(storage, policy);

    for key in [key_a, key_b] {
        let request = VerifyRequest {
            signer_key: &key,
            repo_id: &repo_id,
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

#[test]
fn unauthorized_device_rejected() {
    let storage = MockStorage::new();
    let key = PublicKey::from([99; 32]);
    let repo_id = RepoId::from_str("rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5").unwrap();

    let bridge = DefaultBridge::with_storage(storage);
    let request = VerifyRequest {
        signer_key: &key,
        repo_id: &repo_id,
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

#[test]
fn wrong_capability_rejected() {
    let mut storage = MockStorage::new();
    let identity_did: Did = "did:keri:ECapCheck".parse().unwrap();
    let repo_id = RepoId::from_str("rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5").unwrap();
    let key = PublicKey::from([1; 32]);
    let device_did = Did::from(key);

    storage.key_states.insert(identity_did.clone(), make_key_state("ECapCheck", 1));
    storage.attestations.insert(
        (device_did.clone(), identity_did.clone()),
        make_test_attestation(
            &identity_did,
            &device_did,
            &repo_id,
            false,
            vec![Capability::parse("sign_commit").unwrap()],
        ),
    );
    storage.device_to_identity.insert(
        (device_did.clone(), repo_id),
        identity_did.clone(),
    );

    let bridge = DefaultBridge::with_storage(storage);

    // Requesting a capability the device DOES have
    let req_ok = VerifyRequest {
        signer_key: &key,
        repo_id: &repo_id,
        now: Utc::now(),
        mode: EnforcementMode::Enforce,
        known_remote_tip: None,
        min_kel_seq: None,
        required_capability: Some("sign_commit"),
    };
    assert!(bridge.verify_signer(&req_ok).unwrap().is_allowed());

    // Requesting a capability the device DOES NOT have
    let req_fail = VerifyRequest {
        signer_key: &key,
        repo_id: &repo_id,
        now: Utc::now(),
        mode: EnforcementMode::Enforce,
        known_remote_tip: None,
        min_kel_seq: None,
        required_capability: Some("sign_release"),
    };
    let res = bridge.verify_signer(&req_fail).unwrap();
    assert!(!res.is_allowed());
    assert!(res.reason().contains("lacks required capability"));
}
