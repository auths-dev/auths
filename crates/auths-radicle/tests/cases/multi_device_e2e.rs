use std::str::FromStr;
use chrono::Utc;

use auths_radicle::bridge::{EnforcementMode, RadicleAuthsBridge, SignerInput, VerifyRequest, VerifyResult};
use auths_radicle::verify::{DefaultBridge, IdentityDid, meets_threshold, verify_multiple_signers};
use radicle_core::{Did, RepoId};

use super::helpers::{DeviceFixture, MockStorage, make_key_state, register_device};

#[test]
fn multi_device_authorized_group() {
    let mut storage = MockStorage::new();
    let controller_did: Did = "did:keri:EAlice".parse().unwrap();
    let repo_id = RepoId::from_str("rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5").unwrap();

    // Alice has two devices
    let alice_laptop = DeviceFixture::new(1);
    let alice_phone = DeviceFixture::new(2);

    storage.add_identity(controller_did.clone(), make_key_state("EAlice", 1));

    // Register both devices under Alice's identity
    register_device(&mut storage, &alice_laptop, &controller_did, &repo_id, false, vec![]);
    register_device(&mut storage, &alice_phone, &controller_did, &repo_id, false, vec![]);

    let bridge = DefaultBridge::with_storage(storage);

    // Verify both devices individually
    for device in [&alice_laptop, &alice_phone] {
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
        assert!(result.is_allowed());
    }

    // Verify both devices as a set — they should group under one identity
    let signers = vec![
        SignerInput::NeedsBridgeVerification(alice_laptop.key),
        SignerInput::NeedsBridgeVerification(alice_phone.key),
    ];
    let template = VerifyRequest {
        signer_key: &alice_laptop.key, // template key doesn't matter for grouping
        repo_id: &repo_id,
        now: Utc::now(),
        mode: EnforcementMode::Enforce,
        known_remote_tip: None,
        min_kel_seq: None,
        required_capability: None,
    };

    let grouped = verify_multiple_signers(&bridge, &signers, &template);

    // Should only have ONE identity entry (Alice) despite TWO device signers
    assert_eq!(grouped.len(), 1);
    assert!(grouped.contains_key(&IdentityDid::new(controller_did.clone())));

    let results = grouped.get(&IdentityDid::new(controller_did)).unwrap();
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(|r| r.is_allowed()));

    // Threshold of 1 is met
    assert!(meets_threshold(&grouped, 1));
    // Threshold of 2 is NOT met (only one human identity)
    assert!(!meets_threshold(&grouped, 2));
}

#[test]
fn mixed_human_and_node_group() {
    let mut storage = MockStorage::new();
    let alice_did: Did = "did:keri:EAlice".parse().unwrap();
    let bob_did: Did = "did:keri:EBob".parse().unwrap();
    let repo_id = RepoId::from_str("rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5").unwrap();

    let alice_phone = DeviceFixture::new(1);
    let alice_laptop = DeviceFixture::new(2);
    let bob_desktop = DeviceFixture::new(3);

    storage.add_identity(alice_did.clone(), make_key_state("EAlice", 1));
    storage.add_identity(bob_did.clone(), make_key_state("EBob", 1));

    register_device(&mut storage, &alice_phone, &alice_did, &repo_id, false, vec![]);
    register_device(&mut storage, &alice_laptop, &alice_did, &repo_id, false, vec![]);
    register_device(&mut storage, &bob_desktop, &bob_did, &repo_id, false, vec![]);

    let bridge = DefaultBridge::with_storage(storage);

    // Scenario: Alice signs with 2 devices, Bob signs with 1
    let signers = vec![
        SignerInput::NeedsBridgeVerification(alice_phone.key),
        SignerInput::NeedsBridgeVerification(alice_laptop.key),
        SignerInput::NeedsBridgeVerification(bob_desktop.key),
    ];
    let template = VerifyRequest {
        signer_key: &alice_phone.key,
        repo_id: &repo_id,
        now: Utc::now(),
        mode: EnforcementMode::Enforce,
        known_remote_tip: None,
        min_kel_seq: None,
        required_capability: None,
    };

    let grouped = verify_multiple_signers(&bridge, &signers, &template);

    // Should have 2 identities (Alice, Bob)
    assert_eq!(grouped.len(), 2);
    assert!(meets_threshold(&grouped, 2));
}

#[test]
fn mixed_keri_and_legacy_delegates() {
    let mut storage = MockStorage::new();
    let controller_did: Did = "did:keri:EHuman".parse().unwrap();
    let repo_id = RepoId::from_str("rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5").unwrap();

    let alice_laptop = DeviceFixture::new(1);
    let bob_desktop = DeviceFixture::new(2);

    storage.add_identity(controller_did.clone(), make_key_state("EHuman", 1));
    register_device(&mut storage, &alice_laptop, &controller_did, &repo_id, false, vec![]);
    register_device(&mut storage, &bob_desktop, &controller_did, &repo_id, false, vec![]);

    let bridge = DefaultBridge::with_storage(storage);

    // Pre-verified legacy node (not using KERI)
    let legacy_node_did: Did = "did:key:z6Mkt67GdsW7715MEfRuP4pSZxT3tgCHHnQqBjgJs2ovUoND".parse().unwrap();

    // Alice and Bob both signed (same identity), PLUS a legacy node signed.
    let signers = vec![
        SignerInput::PreVerified {
            did: legacy_node_did.clone(),
            result: VerifyResult::Verified { reason: "ok".into() },
        },
        SignerInput::NeedsBridgeVerification(alice_laptop.key),
        SignerInput::NeedsBridgeVerification(bob_desktop.key),
    ];

    let template = VerifyRequest {
        signer_key: &alice_laptop.key,
        repo_id: &repo_id,
        now: Utc::now(),
        mode: EnforcementMode::Enforce,
        known_remote_tip: None,
        min_kel_seq: None,
        required_capability: None,
    };

    let grouped = verify_multiple_signers(&bridge, &signers, &template);

    // Should have 2 identity entries: legacy node AND the KERI identity
    assert_eq!(grouped.len(), 2);
    assert!(grouped.contains_key(&IdentityDid::new(legacy_node_did)));
    assert!(grouped.contains_key(&IdentityDid::new(controller_did)));

    assert!(meets_threshold(&grouped, 2));
}

#[test]
fn find_identity_for_device() {
    let mut storage = MockStorage::new();
    let controller_did: Did = "did:keri:EAlice".parse().unwrap();
    let repo_id = RepoId::from_str("rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5").unwrap();

    let device_a = DeviceFixture::new(1);
    let device_b = DeviceFixture::new(2);
    let unregistered = DeviceFixture::new(3);

    register_device(&mut storage, &device_a, &controller_did, &repo_id, false, vec![]);
    register_device(&mut storage, &device_b, &controller_did, &repo_id, false, vec![]);

    let bridge = DefaultBridge::with_storage(storage);

    // Registered devices should return Alice's DID
    let found_a = bridge
        .find_identity_for_device(&device_a.did, &repo_id)
        .unwrap();
    assert_eq!(found_a, Some(controller_did.clone()));

    let found_b = bridge
        .find_identity_for_device(&device_b.did, &repo_id)
        .unwrap();
    assert_eq!(found_b, Some(controller_did));

    // Unregistered device should return None
    let found_none = bridge
        .find_identity_for_device(&unregistered.did, &repo_id)
        .unwrap();
    assert!(found_none.is_none());
}
