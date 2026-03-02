use chrono::Utc;

use auths_id::identity::ed25519_to_did_key;
use auths_radicle::bridge::{EnforcementMode, RadicleAuthsBridge, VerifyRequest, VerifyResult};
use auths_radicle::verify::DefaultBridge;

use super::helpers::{MockStorage, make_key_state, make_test_attestation};

#[test]
fn enforce_revocation_rejects_device() {
    let key: [u8; 32] = [50; 32];
    let did = ed25519_to_did_key(&key);
    let identity_did = "did:keri:ERevTest";
    let repo_id = "test-repo";

    let mut storage = MockStorage::new();
    storage
        .key_states
        .insert(identity_did.to_string(), make_key_state("ERevTest", 2));
    storage.attestations.insert(
        (did.clone(), identity_did.to_string()),
        make_test_attestation(identity_did, &did, "test", false, vec![]),
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

    let mut revoked_storage = MockStorage::new();
    revoked_storage
        .key_states
        .insert(identity_did.to_string(), make_key_state("ERevTest", 3));
    revoked_storage.attestations.insert(
        (did.clone(), identity_did.to_string()),
        make_test_attestation(identity_did, &did, "test", true, vec![]),
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
        make_test_attestation(identity_did, &did, "test", true, vec![]),
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
    storage.attestations.insert(
        (did_a.clone(), identity_did.to_string()),
        make_test_attestation(identity_did, &did_a, "test", true, vec![]),
    );
    storage.attestations.insert(
        (did_b.clone(), identity_did.to_string()),
        make_test_attestation(identity_did, &did_b, "test", false, vec![]),
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

#[test]
fn reauthorization_after_revocation() {
    let key: [u8; 32] = [70; 32];
    let did = ed25519_to_did_key(&key);
    let identity_did = "did:keri:EReauth";
    let repo_id = "test-repo";

    let mut storage = MockStorage::new();
    storage
        .key_states
        .insert(identity_did.to_string(), make_key_state("EReauth", 4));
    storage.attestations.insert(
        (did.clone(), identity_did.to_string()),
        make_test_attestation(identity_did, &did, "test", false, vec![]),
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
