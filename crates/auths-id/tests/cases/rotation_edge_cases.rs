use std::ops::ControlFlow;

use auths_id::keri::{
    Event, GitKel, RotationError, anchor_attestation, create_keri_identity,
    create_keri_identity_with_backend, get_key_state, rotate_keys,
    rotate_keys_with_backend, validate_kel,
};
use auths_id::storage::registry::backend::RegistryBackend;
use auths_test_utils::fakes::registry::FakeRegistryBackend;
use ring::signature::Ed25519KeyPair;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct TestAttestation {
    issuer: String,
    subject: String,
    capabilities: Vec<String>,
}

fn make_test_attestation(issuer: &str, subject: &str) -> TestAttestation {
    TestAttestation {
        issuer: issuer.to_string(),
        subject: subject.to_string(),
        capabilities: vec!["sign-commit".to_string()],
    }
}

// =========================================================================
// Double rotation: replaying a consumed next-key must fail
// =========================================================================

#[test]
fn double_rotation_with_consumed_next_key_fails() {
    let backend = FakeRegistryBackend::new();

    let init = create_keri_identity_with_backend(&backend, None).unwrap();

    // First rotation succeeds using the pre-committed next key
    let rot1 =
        rotate_keys_with_backend(&backend, &init.prefix, &init.next_keypair_pkcs8, None).unwrap();
    assert_eq!(rot1.sequence, 1);

    // Second rotation with the SAME consumed key must fail
    let result =
        rotate_keys_with_backend(&backend, &init.prefix, &init.next_keypair_pkcs8, None);
    assert!(
        matches!(result, Err(RotationError::CommitmentMismatch)),
        "Replaying a consumed next-key must fail with CommitmentMismatch, got: {:?}",
        result
    );

    // But rotating with the NEW next key from rot1 succeeds
    let rot2 =
        rotate_keys_with_backend(&backend, &init.prefix, &rot1.new_next_keypair_pkcs8, None)
            .unwrap();
    assert_eq!(rot2.sequence, 2);
}

#[test]
fn double_rotation_does_not_corrupt_kel() {
    let backend = FakeRegistryBackend::new();

    let init = create_keri_identity_with_backend(&backend, None).unwrap();

    let rot1 =
        rotate_keys_with_backend(&backend, &init.prefix, &init.next_keypair_pkcs8, None).unwrap();

    // Failed double-rotation attempt
    let _ = rotate_keys_with_backend(&backend, &init.prefix, &init.next_keypair_pkcs8, None);

    // KEL should still be valid with exactly 2 events (ICP + ROT)
    let mut events = Vec::new();
    backend
        .visit_events(&init.prefix, 0, &mut |e| {
            events.push(e.clone());
            ControlFlow::Continue(())
        })
        .unwrap();
    assert_eq!(events.len(), 2, "Failed rotation must not append to KEL");

    let state = validate_kel(&events).unwrap();
    assert_eq!(state.sequence, 1);
    assert!(!state.is_abandoned);

    // Legitimate next rotation still works
    let rot2 =
        rotate_keys_with_backend(&backend, &init.prefix, &rot1.new_next_keypair_pkcs8, None)
            .unwrap();
    assert_eq!(rot2.sequence, 2);
}

// =========================================================================
// Rotation after interaction events (IXN interleaved with ROT)
// =========================================================================

#[test]
fn rotation_after_interaction_events_preserves_kel_integrity() {
    let (_dir, repo) = auths_test_utils::git::init_test_repo();

    let init = create_keri_identity(&repo, None).unwrap();
    let identity_did = format!("did:keri:{}", init.prefix);
    let current_kp = Ed25519KeyPair::from_pkcs8(&init.current_keypair_pkcs8).unwrap();

    // IXN at seq 1
    let att1 = make_test_attestation(&identity_did, "did:key:device1");
    anchor_attestation(&repo, &init.prefix, &att1, &current_kp).unwrap();

    // IXN at seq 2
    let att2 = make_test_attestation(&identity_did, "did:key:device2");
    anchor_attestation(&repo, &init.prefix, &att2, &current_kp).unwrap();

    // ROT at seq 3 (using pre-committed next key)
    let rot1 = rotate_keys(&repo, &init.prefix, &init.next_keypair_pkcs8, None).unwrap();
    assert_eq!(rot1.sequence, 3);

    // Verify KEL: ICP(0) + IXN(1) + IXN(2) + ROT(3)
    let kel = GitKel::new(&repo, init.prefix.as_str());
    let events = kel.get_events().unwrap();
    assert_eq!(events.len(), 4);
    assert!(matches!(events[0], Event::Icp(_)));
    assert!(matches!(events[1], Event::Ixn(_)));
    assert!(matches!(events[2], Event::Ixn(_)));
    assert!(matches!(events[3], Event::Rot(_)));

    let state = validate_kel(&events).unwrap();
    assert_eq!(state.sequence, 3);
    assert!(!state.is_abandoned);
    assert!(state.can_rotate());
}

#[test]
fn anchoring_works_with_rotated_key_after_ixn() {
    let (_dir, repo) = auths_test_utils::git::init_test_repo();

    let init = create_keri_identity(&repo, None).unwrap();
    let identity_did = format!("did:keri:{}", init.prefix);
    let current_kp = Ed25519KeyPair::from_pkcs8(&init.current_keypair_pkcs8).unwrap();

    // IXN with inception key
    let att1 = make_test_attestation(&identity_did, "did:key:device1");
    anchor_attestation(&repo, &init.prefix, &att1, &current_kp).unwrap();

    // Rotate
    let rot1 = rotate_keys(&repo, &init.prefix, &init.next_keypair_pkcs8, None).unwrap();
    let rotated_kp = Ed25519KeyPair::from_pkcs8(&rot1.new_current_keypair_pkcs8).unwrap();

    // IXN with rotated key
    let att2 = make_test_attestation(&identity_did, "did:key:device2");
    anchor_attestation(&repo, &init.prefix, &att2, &rotated_kp).unwrap();

    // KEL: ICP(0) + IXN(1) + ROT(2) + IXN(3)
    let kel = GitKel::new(&repo, init.prefix.as_str());
    let events = kel.get_events().unwrap();
    assert_eq!(events.len(), 4);
    assert!(matches!(events[0], Event::Icp(_)));
    assert!(matches!(events[1], Event::Ixn(_)));
    assert!(matches!(events[2], Event::Rot(_)));
    assert!(matches!(events[3], Event::Ixn(_)));

    let state = validate_kel(&events).unwrap();
    assert_eq!(state.sequence, 3);
}

#[test]
fn multiple_rotations_interleaved_with_ixn() {
    let (_dir, repo) = auths_test_utils::git::init_test_repo();

    let init = create_keri_identity(&repo, None).unwrap();
    let identity_did = format!("did:keri:{}", init.prefix);
    let kp0 = Ed25519KeyPair::from_pkcs8(&init.current_keypair_pkcs8).unwrap();

    // IXN(1) with inception key
    let att1 = make_test_attestation(&identity_did, "did:key:device1");
    anchor_attestation(&repo, &init.prefix, &att1, &kp0).unwrap();

    // ROT(2)
    let rot1 = rotate_keys(&repo, &init.prefix, &init.next_keypair_pkcs8, None).unwrap();
    assert_eq!(rot1.sequence, 2);
    let kp1 = Ed25519KeyPair::from_pkcs8(&rot1.new_current_keypair_pkcs8).unwrap();

    // IXN(3) with rotated key
    let att2 = make_test_attestation(&identity_did, "did:key:device2");
    anchor_attestation(&repo, &init.prefix, &att2, &kp1).unwrap();

    // ROT(4)
    let rot2 = rotate_keys(&repo, &init.prefix, &rot1.new_next_keypair_pkcs8, None).unwrap();
    assert_eq!(rot2.sequence, 4);
    let kp2 = Ed25519KeyPair::from_pkcs8(&rot2.new_current_keypair_pkcs8).unwrap();

    // IXN(5) with second-rotated key
    let att3 = make_test_attestation(&identity_did, "did:key:device3");
    anchor_attestation(&repo, &init.prefix, &att3, &kp2).unwrap();

    // KEL: ICP(0) IXN(1) ROT(2) IXN(3) ROT(4) IXN(5)
    let kel = GitKel::new(&repo, init.prefix.as_str());
    let events = kel.get_events().unwrap();
    assert_eq!(events.len(), 6);

    let state = validate_kel(&events).unwrap();
    assert_eq!(state.sequence, 5);
    assert!(!state.is_abandoned);
    assert!(state.can_rotate());

    // Key state should reflect the latest rotation
    let key_state = get_key_state(&repo, &init.prefix).unwrap();
    assert_eq!(key_state.sequence, 5);
}
