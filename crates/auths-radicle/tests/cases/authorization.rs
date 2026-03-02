use chrono::Utc;

use auths_id::identity::ed25519_to_did_key;
use auths_id::policy::PolicyBuilder;
use auths_radicle::bridge::{EnforcementMode, RadicleAuthsBridge, VerifyRequest};
use auths_radicle::verify::DefaultBridge;
use auths_verifier::core::Capability;

use super::helpers::{MockStorage, make_key_state, make_test_attestation};

#[test]
fn authorized_device_verified() {
    let mut storage = MockStorage::new();
    let identity_did = "did:keri:EMultiDevice";
    let repo_id = "test-project";

    let key_a: [u8; 32] = [10; 32];
    let key_b: [u8; 32] = [20; 32];
    let did_a = ed25519_to_did_key(&key_a);
    let did_b = ed25519_to_did_key(&key_b);

    storage
        .key_states
        .insert(identity_did.to_string(), make_key_state("EMultiDevice", 1));

    storage.attestations.insert(
        (did_a.clone(), identity_did.to_string()),
        make_test_attestation(
            identity_did,
            &did_a,
            repo_id,
            false,
            vec![Capability::sign_commit()],
        ),
    );
    storage.attestations.insert(
        (did_b.clone(), identity_did.to_string()),
        make_test_attestation(
            identity_did,
            &did_b,
            repo_id,
            false,
            vec![Capability::sign_commit()],
        ),
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

#[test]
fn wrong_capability_rejected() {
    let mut storage = MockStorage::new();
    let identity_did = "did:keri:ECapTest";
    let repo_id = "test-project";
    let key: [u8; 32] = [30; 32];
    let did = ed25519_to_did_key(&key);

    storage
        .key_states
        .insert(identity_did.to_string(), make_key_state("ECapTest", 0));
    storage.attestations.insert(
        (did.clone(), identity_did.to_string()),
        make_test_attestation(
            identity_did,
            &did,
            repo_id,
            false,
            vec![Capability::sign_release()],
        ),
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
        required_capability: Some("sign_commit"),
    };
    let result = bridge.verify_signer(&request).unwrap();
    assert!(result.is_rejected(), "wrong capability should be rejected");
}
