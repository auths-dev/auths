//! Multi-device lifecycle E2E test.
//!
//! Walks through the complete Radicle-Auths lifecycle with multiple devices
//! and identities: authorization, revocation, re-authorization, capability
//! gating, staleness detection, and threshold verification.

use chrono::Utc;

use auths_id::policy::PolicyBuilder;
use auths_radicle::bridge::{
    EnforcementMode, RadicleAuthsBridge, SignerInput, VerifyRequest, VerifyResult,
};
use auths_radicle::verify::{DefaultBridge, meets_threshold, verify_multiple_signers};
use auths_verifier::core::Capability;

use super::helpers::{DeviceFixture, MockStorage, make_key_state, register_device};

#[test]
fn multi_device_lifecycle() {
    let alice_did = "did:keri:EAlice";
    let bob_did = "did:keri:EBob";
    let repo_id = "rad:zSharedProject";

    let alice_laptop = DeviceFixture::new(0x10);
    let alice_phone = DeviceFixture::new(0x11);
    let bob_desktop = DeviceFixture::new(0x20);

    // ── Phase 1: All devices authorized ──────────────────────────────────

    let mut storage = MockStorage::new();
    storage
        .key_states
        .insert(alice_did.to_string(), make_key_state("EAlice", 2));
    storage
        .key_states
        .insert(bob_did.to_string(), make_key_state("EBob", 1));
    storage
        .identity_tips
        .insert(alice_did.to_string(), [0xAA; 20]);
    storage
        .identity_tips
        .insert(bob_did.to_string(), [0xBB; 20]);

    register_device(
        &mut storage,
        &alice_laptop,
        alice_did,
        repo_id,
        false,
        vec![Capability::sign_commit()],
    );
    register_device(
        &mut storage,
        &alice_phone,
        alice_did,
        repo_id,
        false,
        vec![Capability::sign_commit()],
    );
    register_device(
        &mut storage,
        &bob_desktop,
        bob_did,
        repo_id,
        false,
        vec![Capability::sign_commit()],
    );

    let policy = PolicyBuilder::new().not_revoked().not_expired().build();
    let bridge = DefaultBridge::new(storage, policy);

    for (label, device) in [
        ("alice-laptop", &alice_laptop),
        ("alice-phone", &alice_phone),
        ("bob-desktop", &bob_desktop),
    ] {
        let request = VerifyRequest {
            signer_key: &device.key,
            repo_id,
            now: Utc::now(),
            mode: EnforcementMode::Enforce,
            known_remote_tip: None,
            min_kel_seq: None,
            required_capability: None,
        };
        let result = bridge.verify_signer(&request).unwrap();
        assert!(result.is_allowed(), "phase 1: {label} should be Verified");
    }

    // ── Phase 2: Revoke Alice's phone ────────────────────────────────────

    let mut storage = MockStorage::new();
    storage
        .key_states
        .insert(alice_did.to_string(), make_key_state("EAlice", 3));
    storage
        .key_states
        .insert(bob_did.to_string(), make_key_state("EBob", 1));
    storage
        .identity_tips
        .insert(alice_did.to_string(), [0xAA; 20]);
    storage
        .identity_tips
        .insert(bob_did.to_string(), [0xBB; 20]);

    register_device(
        &mut storage,
        &alice_laptop,
        alice_did,
        repo_id,
        false,
        vec![Capability::sign_commit()],
    );
    register_device(
        &mut storage,
        &alice_phone,
        alice_did,
        repo_id,
        true, // revoked
        vec![Capability::sign_commit()],
    );
    register_device(
        &mut storage,
        &bob_desktop,
        bob_did,
        repo_id,
        false,
        vec![Capability::sign_commit()],
    );

    let bridge = DefaultBridge::with_storage(storage);

    let phone_request = VerifyRequest {
        signer_key: &alice_phone.key,
        repo_id,
        now: Utc::now(),
        mode: EnforcementMode::Enforce,
        known_remote_tip: None,
        min_kel_seq: None,
        required_capability: None,
    };
    assert!(
        bridge.verify_signer(&phone_request).unwrap().is_rejected(),
        "phase 2: alice-phone should be Rejected after revocation"
    );

    let laptop_request = VerifyRequest {
        signer_key: &alice_laptop.key,
        repo_id,
        now: Utc::now(),
        mode: EnforcementMode::Enforce,
        known_remote_tip: None,
        min_kel_seq: None,
        required_capability: None,
    };
    assert!(
        bridge.verify_signer(&laptop_request).unwrap().is_allowed(),
        "phase 2: alice-laptop should still be Verified"
    );

    let bob_request = VerifyRequest {
        signer_key: &bob_desktop.key,
        repo_id,
        now: Utc::now(),
        mode: EnforcementMode::Enforce,
        known_remote_tip: None,
        min_kel_seq: None,
        required_capability: None,
    };
    assert!(
        bridge.verify_signer(&bob_request).unwrap().is_allowed(),
        "phase 2: bob-desktop should still be Verified"
    );

    // ── Phase 3: Re-authorize Alice's phone ──────────────────────────────

    let mut storage = MockStorage::new();
    storage
        .key_states
        .insert(alice_did.to_string(), make_key_state("EAlice", 4));
    storage
        .key_states
        .insert(bob_did.to_string(), make_key_state("EBob", 1));
    storage
        .identity_tips
        .insert(alice_did.to_string(), [0xAA; 20]);
    storage
        .identity_tips
        .insert(bob_did.to_string(), [0xBB; 20]);

    register_device(
        &mut storage,
        &alice_laptop,
        alice_did,
        repo_id,
        false,
        vec![Capability::sign_commit()],
    );
    register_device(
        &mut storage,
        &alice_phone,
        alice_did,
        repo_id,
        false, // re-authorized with fresh attestation
        vec![Capability::sign_commit()],
    );
    register_device(
        &mut storage,
        &bob_desktop,
        bob_did,
        repo_id,
        false,
        vec![Capability::sign_commit()],
    );

    let bridge = DefaultBridge::with_storage(storage);

    let phone_request = VerifyRequest {
        signer_key: &alice_phone.key,
        repo_id,
        now: Utc::now(),
        mode: EnforcementMode::Enforce,
        known_remote_tip: None,
        min_kel_seq: None,
        required_capability: None,
    };
    assert!(
        bridge.verify_signer(&phone_request).unwrap().is_allowed(),
        "phase 3: alice-phone should be Verified after re-authorization"
    );

    // ── Phase 4: Capability gating ───────────────────────────────────────

    let mut storage = MockStorage::new();
    storage
        .key_states
        .insert(bob_did.to_string(), make_key_state("EBob", 1));
    storage
        .identity_tips
        .insert(bob_did.to_string(), [0xBB; 20]);

    register_device(
        &mut storage,
        &bob_desktop,
        bob_did,
        repo_id,
        false,
        vec![Capability::sign_release()], // Bob only has sign_release
    );

    let bridge = DefaultBridge::with_storage(storage);

    let bob_commit_request = VerifyRequest {
        signer_key: &bob_desktop.key,
        repo_id,
        now: Utc::now(),
        mode: EnforcementMode::Enforce,
        known_remote_tip: None,
        min_kel_seq: None,
        required_capability: Some("sign_commit"),
    };
    assert!(
        bridge
            .verify_signer(&bob_commit_request)
            .unwrap()
            .is_rejected(),
        "phase 4: bob should be Rejected for sign_commit (only has sign_release)"
    );

    let bob_no_cap_request = VerifyRequest {
        signer_key: &bob_desktop.key,
        repo_id,
        now: Utc::now(),
        mode: EnforcementMode::Enforce,
        known_remote_tip: None,
        min_kel_seq: None,
        required_capability: None,
    };
    assert!(
        bridge
            .verify_signer(&bob_no_cap_request)
            .unwrap()
            .is_allowed(),
        "phase 4: bob should be Verified when no capability required"
    );

    // ── Phase 5: Staleness detection ─────────────────────────────────────

    let mut storage = MockStorage::new();
    storage
        .key_states
        .insert(alice_did.to_string(), make_key_state("EAlice", 4));
    storage
        .identity_tips
        .insert(alice_did.to_string(), [0xAA; 20]);

    register_device(
        &mut storage,
        &alice_laptop,
        alice_did,
        repo_id,
        false,
        vec![Capability::sign_commit()],
    );

    let bridge = DefaultBridge::with_storage(storage);

    // Gossip tip differs from local → Quarantine
    let stale_request = VerifyRequest {
        signer_key: &alice_laptop.key,
        repo_id,
        now: Utc::now(),
        mode: EnforcementMode::Enforce,
        known_remote_tip: Some([0xCC; 20]), // differs from local [0xAA; 20]
        min_kel_seq: None,
        required_capability: None,
    };
    let result = bridge.verify_signer(&stale_request).unwrap();
    assert!(
        matches!(result, VerifyResult::Quarantine { .. }),
        "phase 5: stale tip mismatch should produce Quarantine"
    );

    // After "sync" — tips now match
    let mut synced_storage = MockStorage::new();
    synced_storage
        .key_states
        .insert(alice_did.to_string(), make_key_state("EAlice", 5));
    synced_storage
        .identity_tips
        .insert(alice_did.to_string(), [0xCC; 20]); // now matches remote

    register_device(
        &mut synced_storage,
        &alice_laptop,
        alice_did,
        repo_id,
        false,
        vec![Capability::sign_commit()],
    );

    let synced_bridge = DefaultBridge::with_storage(synced_storage);

    let synced_request = VerifyRequest {
        signer_key: &alice_laptop.key,
        repo_id,
        now: Utc::now(),
        mode: EnforcementMode::Enforce,
        known_remote_tip: Some([0xCC; 20]),
        min_kel_seq: None,
        required_capability: None,
    };
    assert!(
        synced_bridge
            .verify_signer(&synced_request)
            .unwrap()
            .is_allowed(),
        "phase 5: after sync, alice-laptop should be Verified"
    );

    // ── Phase 6: Threshold verification ──────────────────────────────────

    let mut storage = MockStorage::new();
    storage
        .key_states
        .insert(alice_did.to_string(), make_key_state("EAlice", 5));
    storage
        .key_states
        .insert(bob_did.to_string(), make_key_state("EBob", 1));
    storage
        .identity_tips
        .insert(alice_did.to_string(), [0xCC; 20]);
    storage
        .identity_tips
        .insert(bob_did.to_string(), [0xBB; 20]);

    register_device(
        &mut storage,
        &alice_laptop,
        alice_did,
        repo_id,
        false,
        vec![],
    );
    register_device(
        &mut storage,
        &bob_desktop,
        bob_did,
        repo_id,
        false,
        vec![],
    );

    let bridge = DefaultBridge::with_storage(storage);

    let signers = vec![
        // Did::Key delegate pre-verified by Heartwood
        SignerInput::PreVerified(VerifyResult::Verified {
            reason: "did:key delegate ok".into(),
        }),
        // Did::Keri signers verified through bridge
        SignerInput::NeedsBridgeVerification(alice_laptop.key),
        SignerInput::NeedsBridgeVerification(bob_desktop.key),
    ];

    let template = VerifyRequest {
        signer_key: &alice_laptop.key,
        repo_id,
        now: Utc::now(),
        mode: EnforcementMode::Enforce,
        known_remote_tip: None,
        min_kel_seq: None,
        required_capability: None,
    };
    let results = verify_multiple_signers(&bridge, &signers, &template);

    assert_eq!(results.len(), 3);
    assert!(
        meets_threshold(&results, 2),
        "phase 6: 3 verified signers should meet 2-of-3 threshold"
    );
    assert!(
        meets_threshold(&results, 3),
        "phase 6: 3 verified signers should meet 3-of-3 threshold"
    );
}
