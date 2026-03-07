use std::ops::ControlFlow;

use auths_id::keri::{
    InceptionResult, RotationError, create_keri_identity_with_backend, get_key_state_with_backend,
    rotate_keys_with_backend, validate_kel,
};
use auths_id::storage::registry::backend::RegistryBackend;
use auths_id::testing::fakes::FakeRegistryBackend;
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;

/// Attacker has the current key but NOT the pre-committed next key.
/// Rotation must fail with CommitmentMismatch.
#[test]
fn attacker_cannot_rotate_without_precommitted_key() {
    let backend = FakeRegistryBackend::new();

    let init: InceptionResult = create_keri_identity_with_backend(&backend, None).unwrap();

    // Attacker generates their own key and tries to rotate
    let rng = SystemRandom::new();
    let attacker_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let attacker_pkcs8 = auths_crypto::Pkcs8Der::new(attacker_pkcs8.as_ref());

    let result = rotate_keys_with_backend(
        &backend,
        &init.prefix,
        &attacker_pkcs8,
        chrono::Utc::now(),
        None,
    );

    // Must fail: blake3(attacker_key) != stored commitment
    assert!(
        matches!(result, Err(RotationError::CommitmentMismatch)),
        "Attacker rotation should fail with CommitmentMismatch, got: {:?}",
        result
    );

    // Legitimate holder rotates successfully with the pre-committed key
    let rot = rotate_keys_with_backend(
        &backend,
        &init.prefix,
        &init.next_keypair_pkcs8,
        chrono::Utc::now(),
        None,
    )
    .unwrap();
    assert_eq!(rot.sequence, 1);

    // Verify KEL integrity after recovery
    let mut events = Vec::new();
    backend
        .visit_events(&init.prefix, 0, &mut |e| {
            events.push(e.clone());
            ControlFlow::Continue(())
        })
        .unwrap();
    let state = validate_kel(&events).unwrap();
    assert_eq!(state.sequence, 1);
    assert!(!state.is_abandoned);
}

/// Full recovery flow: create -> compromise -> rotate -> rotate again -> verify.
/// Simulates an identity that rotates twice after compromise, proving continued
/// control through the pre-rotation chain.
#[test]
fn full_recovery_flow_end_to_end() {
    let backend = FakeRegistryBackend::new();

    // Step 1: Create identity
    let init = create_keri_identity_with_backend(&backend, None).unwrap();
    let state = get_key_state_with_backend(&backend, &init.prefix).unwrap();
    assert_eq!(state.sequence, 0);
    assert!(state.can_rotate());

    // Step 2: First rotation (recovery from compromise)
    let rot1 = rotate_keys_with_backend(
        &backend,
        &init.prefix,
        &init.next_keypair_pkcs8,
        chrono::Utc::now(),
        None,
    )
    .unwrap();
    assert_eq!(rot1.sequence, 1);

    // Verify state after first rotation
    let state = get_key_state_with_backend(&backend, &init.prefix).unwrap();
    assert_eq!(state.sequence, 1);
    assert!(state.can_rotate());

    // Step 3: Second rotation (demonstrates continued control)
    let rot2 = rotate_keys_with_backend(
        &backend,
        &init.prefix,
        &rot1.new_next_keypair_pkcs8,
        chrono::Utc::now(),
        None,
    )
    .unwrap();
    assert_eq!(rot2.sequence, 2);

    // Step 4: Verify full KEL integrity
    let mut events = Vec::new();
    backend
        .visit_events(&init.prefix, 0, &mut |e| {
            events.push(e.clone());
            ControlFlow::Continue(())
        })
        .unwrap();
    assert_eq!(events.len(), 3); // ICP + ROT + ROT

    let state = validate_kel(&events).unwrap();
    assert_eq!(state.sequence, 2);
    assert!(!state.is_abandoned);
    assert!(state.can_rotate());
}

/// After recovery, the old (compromised) key must not work for rotation.
#[test]
fn compromised_key_cannot_rotate_after_recovery() {
    let backend = FakeRegistryBackend::new();

    let init = create_keri_identity_with_backend(&backend, None).unwrap();

    // Legitimate rotation (recovery)
    let _rot = rotate_keys_with_backend(
        &backend,
        &init.prefix,
        &init.next_keypair_pkcs8,
        chrono::Utc::now(),
        None,
    )
    .unwrap();

    // Attacker still has the original current key PKCS8 -- try to rotate with it
    let result = rotate_keys_with_backend(
        &backend,
        &init.prefix,
        &init.current_keypair_pkcs8,
        chrono::Utc::now(),
        None,
    );

    assert!(
        matches!(result, Err(RotationError::CommitmentMismatch)),
        "Old compromised key should not work after rotation, got: {:?}",
        result
    );
}
