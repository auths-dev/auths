use auths_core::crypto::said::compute_said;
use auths_id::keri::{
    Event, GitKel, InceptionResult, RotationResult, anchor_attestation,
    create_keri_identity_with_curve, get_key_state, rotate_keys, verify_anchor,
    verify_anchor_by_digest,
};
use auths_id::keri::{
    parse_did_keri, resolve_did_keri, resolve_did_keri_at_sequence, validate_kel,
};
use ring::signature::Ed25519KeyPair;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct TestAttestation {
    issuer: String,
    subject: String,
    device_public_key: Vec<u8>,
    capabilities: Vec<String>,
}

fn make_test_attestation(issuer: &str, subject: &str) -> TestAttestation {
    TestAttestation {
        issuer: issuer.to_string(),
        subject: subject.to_string(),
        device_public_key: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        capabilities: vec!["sign-commit".to_string()],
    }
}

/// Tests the full KERI lifecycle: inception -> rotation -> rotation -> resolution
#[test]
fn full_keri_lifecycle() {
    let (_dir, repo) = auths_test_utils::git::init_test_repo();

    // === Phase 1: Inception ===
    let init: InceptionResult = create_keri_identity_with_curve(
        &repo,
        None,
        chrono::Utc::now(),
        auths_crypto::CurveType::Ed25519,
    )
    .unwrap();

    // Verify KEL has one event
    let kel = GitKel::new(&repo, init.prefix.as_str());
    let events = kel.get_events().unwrap();
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], Event::Icp(_)));

    // Verify DID resolves to inception key
    let did = format!("did:keri:{}", init.prefix);
    let resolved = resolve_did_keri(&repo, &did).unwrap();
    assert_eq!(resolved.public_key, init.current_public_key);
    assert_eq!(resolved.sequence, 0);
    assert!(resolved.can_rotate);
    assert!(!resolved.is_abandoned);

    // === Phase 2: First Rotation ===
    let rot1: RotationResult = rotate_keys(
        &repo,
        &init.prefix,
        &init.next_keypair_pkcs8,
        None,
        chrono::Utc::now(),
    )
    .unwrap();
    assert_eq!(rot1.sequence, 1);

    // Verify KEL now has 2 events
    let events = kel.get_events().unwrap();
    assert_eq!(events.len(), 2);
    assert!(matches!(events[1], Event::Rot(_)));

    // Verify resolution returns new key
    let resolved = resolve_did_keri(&repo, &did).unwrap();
    assert_eq!(resolved.public_key, rot1.new_current_public_key);
    assert_eq!(resolved.sequence, 1);

    // Verify KEL validation passes
    let state = validate_kel(&events).unwrap();
    assert_eq!(state.sequence, 1);

    // === Phase 3: Second Rotation ===
    let rot2 = rotate_keys(
        &repo,
        &init.prefix,
        &rot1.new_next_keypair_pkcs8,
        None,
        chrono::Utc::now(),
    )
    .unwrap();
    assert_eq!(rot2.sequence, 2);

    let events = kel.get_events().unwrap();
    assert_eq!(events.len(), 3);
    let state = validate_kel(&events).unwrap();
    assert_eq!(state.sequence, 2);

    // === Phase 4: Historical Resolution ===

    // Resolve at sequence 0 should return inception key
    let resolved_s0 = resolve_did_keri_at_sequence(&repo, &did, 0).unwrap();
    assert_eq!(resolved_s0.public_key, init.current_public_key);
    assert_eq!(resolved_s0.sequence, 0);

    // Resolve at sequence 1 should return first rotation key
    let resolved_s1 = resolve_did_keri_at_sequence(&repo, &did, 1).unwrap();
    assert_eq!(resolved_s1.public_key, rot1.new_current_public_key);
    assert_eq!(resolved_s1.sequence, 1);

    // Resolve at sequence 2 should return second rotation key
    let resolved_s2 = resolve_did_keri_at_sequence(&repo, &did, 2).unwrap();
    assert_eq!(resolved_s2.public_key, rot2.new_current_public_key);
    assert_eq!(resolved_s2.sequence, 2);
}

/// Tests device attestation anchoring via IXN events
#[test]
fn device_enrollment_with_anchoring() {
    let (_dir, repo) = auths_test_utils::git::init_test_repo();

    // Create identity
    let init = create_keri_identity_with_curve(
        &repo,
        None,
        chrono::Utc::now(),
        auths_crypto::CurveType::Ed25519,
    )
    .unwrap();
    let identity_did = format!("did:keri:{}", init.prefix);
    let current_keypair = Ed25519KeyPair::from_pkcs8(init.current_keypair_pkcs8.as_ref()).unwrap();

    // Create device attestation
    let device_did = "did:key:z6MknSLrJoTcukLrE435hVNQT4JUhbvWLX4kUzqkEStBU8Vi";
    let attestation = make_test_attestation(&identity_did, device_did);

    // Anchor attestation in KEL
    let anchor_said = anchor_attestation(
        &repo,
        &init.prefix,
        &attestation,
        &current_keypair,
        chrono::Utc::now(),
    )
    .unwrap();

    // Verify KEL has ICP + IXN
    let kel = GitKel::new(&repo, init.prefix.as_str());
    let events = kel.get_events().unwrap();
    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], Event::Icp(_)));
    assert!(matches!(events[1], Event::Ixn(_)));

    // Verify anchor can be found
    let verification = verify_anchor(&repo, &init.prefix, &attestation).unwrap();
    assert!(verification.anchored);
    assert_eq!(verification.anchor_said, Some(anchor_said));
    assert_eq!(verification.anchor_sequence, Some(1));
    assert!(verification.signing_key.is_some());
}

/// Tests that multiple attestations can be anchored
#[test]
fn multiple_device_attestations() {
    let (_dir, repo) = auths_test_utils::git::init_test_repo();

    let init = create_keri_identity_with_curve(
        &repo,
        None,
        chrono::Utc::now(),
        auths_crypto::CurveType::Ed25519,
    )
    .unwrap();
    let identity_did = format!("did:keri:{}", init.prefix);
    let current_keypair = Ed25519KeyPair::from_pkcs8(init.current_keypair_pkcs8.as_ref()).unwrap();

    // Anchor multiple attestations
    let att1 = make_test_attestation(&identity_did, "did:key:device1");
    let att2 = make_test_attestation(&identity_did, "did:key:device2");
    let att3 = make_test_attestation(&identity_did, "did:key:device3");

    let said1 = anchor_attestation(
        &repo,
        &init.prefix,
        &att1,
        &current_keypair,
        chrono::Utc::now(),
    )
    .unwrap();
    let said2 = anchor_attestation(
        &repo,
        &init.prefix,
        &att2,
        &current_keypair,
        chrono::Utc::now(),
    )
    .unwrap();
    let said3 = anchor_attestation(
        &repo,
        &init.prefix,
        &att3,
        &current_keypair,
        chrono::Utc::now(),
    )
    .unwrap();

    // All SAIDs should be different
    assert_ne!(said1, said2);
    assert_ne!(said2, said3);
    assert_ne!(said1, said3);

    // Verify KEL has 4 events (ICP + 3 IXN)
    let kel = GitKel::new(&repo, init.prefix.as_str());
    let events = kel.get_events().unwrap();
    assert_eq!(events.len(), 4);

    // Verify all anchors can be found
    let v1 = verify_anchor(&repo, &init.prefix, &att1).unwrap();
    let v2 = verify_anchor(&repo, &init.prefix, &att2).unwrap();
    let v3 = verify_anchor(&repo, &init.prefix, &att3).unwrap();

    assert!(v1.anchored);
    assert!(v2.anchored);
    assert!(v3.anchored);

    assert_eq!(v1.anchor_sequence, Some(1));
    assert_eq!(v2.anchor_sequence, Some(2));
    assert_eq!(v3.anchor_sequence, Some(3));
}

/// Tests that rotation invalidates without proper commitment
#[test]
fn rotation_requires_commitment() {
    let (_dir, repo) = auths_test_utils::git::init_test_repo();

    let init = create_keri_identity_with_curve(
        &repo,
        None,
        chrono::Utc::now(),
        auths_crypto::CurveType::Ed25519,
    )
    .unwrap();

    // Try to rotate with a wrong key (not the committed one)
    let wrong_key = auths_crypto::Pkcs8Der::new([99u8; 85].to_vec());

    let result = rotate_keys(&repo, &init.prefix, &wrong_key, None, chrono::Utc::now());
    assert!(result.is_err());
}

/// Tests KEL validation detects sequence tampering
#[test]
fn kel_validation_rejects_sequence_tampering() {
    let (_dir, repo) = auths_test_utils::git::init_test_repo();

    let init = create_keri_identity_with_curve(
        &repo,
        None,
        chrono::Utc::now(),
        auths_crypto::CurveType::Ed25519,
    )
    .unwrap();
    let _rot = rotate_keys(
        &repo,
        &init.prefix,
        &init.next_keypair_pkcs8,
        None,
        chrono::Utc::now(),
    )
    .unwrap();

    // Get events
    let kel = GitKel::new(&repo, init.prefix.as_str());
    let mut events = kel.get_events().unwrap();

    // Tamper with sequence number
    if let Event::Rot(ref mut rot) = events[1] {
        rot.s = auths_id::keri::KeriSequence::new(999);
    }

    // Validation should fail due to sequence mismatch
    let result = validate_kel(&events);
    assert!(result.is_err());
}

/// Tests that unanchored attestations are not found
#[test]
fn unanchored_attestation_not_found() {
    let (_dir, repo) = auths_test_utils::git::init_test_repo();

    let init = create_keri_identity_with_curve(
        &repo,
        None,
        chrono::Utc::now(),
        auths_crypto::CurveType::Ed25519,
    )
    .unwrap();
    let identity_did = format!("did:keri:{}", init.prefix);

    let attestation = make_test_attestation(&identity_did, "did:key:device");
    // Don't anchor it

    let verification = verify_anchor(&repo, &init.prefix, &attestation).unwrap();
    assert!(!verification.anchored);
    assert!(verification.anchor_said.is_none());
}

/// Tests that key state is correct after operations
#[test]
fn key_state_reflects_operations() {
    let (_dir, repo) = auths_test_utils::git::init_test_repo();

    let init = create_keri_identity_with_curve(
        &repo,
        None,
        chrono::Utc::now(),
        auths_crypto::CurveType::Ed25519,
    )
    .unwrap();

    // Initial state
    let state = get_key_state(&repo, &init.prefix).unwrap();
    assert_eq!(state.sequence, 0);
    assert!(state.can_rotate());
    assert!(!state.is_abandoned);

    // After rotation
    rotate_keys(
        &repo,
        &init.prefix,
        &init.next_keypair_pkcs8,
        None,
        chrono::Utc::now(),
    )
    .unwrap();
    let state = get_key_state(&repo, &init.prefix).unwrap();
    assert_eq!(state.sequence, 1);
    assert!(state.can_rotate());
}

/// Tests that did:keri parsing works correctly
#[test]
fn did_keri_parsing() {
    let (_dir, repo) = auths_test_utils::git::init_test_repo();

    let init = create_keri_identity_with_curve(
        &repo,
        None,
        chrono::Utc::now(),
        auths_crypto::CurveType::Ed25519,
    )
    .unwrap();
    let did = format!("did:keri:{}", init.prefix);

    let parsed_prefix = parse_did_keri(&did).unwrap();
    assert_eq!(parsed_prefix, init.prefix);

    // Invalid format should fail
    assert!(parse_did_keri("did:key:z6MkTest").is_err());
    assert!(parse_did_keri("did:keri:").is_err());
    assert!(parse_did_keri("not-a-did").is_err());
}

/// Tests anchor verification by digest
#[test]
fn verify_anchor_by_digest_works() {
    let (_dir, repo) = auths_test_utils::git::init_test_repo();

    let init = create_keri_identity_with_curve(
        &repo,
        None,
        chrono::Utc::now(),
        auths_crypto::CurveType::Ed25519,
    )
    .unwrap();
    let identity_did = format!("did:keri:{}", init.prefix);
    let current_keypair = Ed25519KeyPair::from_pkcs8(init.current_keypair_pkcs8.as_ref()).unwrap();

    let attestation = make_test_attestation(&identity_did, "did:key:device");
    anchor_attestation(
        &repo,
        &init.prefix,
        &attestation,
        &current_keypair,
        chrono::Utc::now(),
    )
    .unwrap();

    // Compute digest
    let att_value = serde_json::to_value(&attestation).unwrap();
    let digest = compute_said(&att_value).unwrap();

    // Verify by digest
    let verification = verify_anchor_by_digest(&repo, &init.prefix, digest.as_str()).unwrap();
    assert!(verification.anchored);
}

/// Regression test: default identity uses P-256 (key prefix "1AAJ"), not Ed25519 ("D").
#[test]
fn default_identity_uses_p256() {
    use auths_id::keri::create_keri_identity;

    let (_dir, repo) = auths_test_utils::git::init_test_repo();

    let init = create_keri_identity(&repo, None, chrono::Utc::now()).unwrap();

    let kel = GitKel::new(&repo, init.prefix.as_str());
    let events = kel.get_events().unwrap();
    let icp = match &events[0] {
        Event::Icp(icp) => icp,
        other => panic!("expected inception event, got {:?}", other),
    };

    let key_str = icp.k[0].as_str();
    assert!(
        key_str.starts_with("1AAJ"),
        "default identity should use P-256 (1AAJ prefix), got: {}",
        &key_str[..4.min(key_str.len())]
    );

    assert_eq!(
        init.current_public_key.len(),
        33,
        "P-256 key should be 33 bytes"
    );
}

/// Explicit Ed25519 identity uses "D" prefix.
#[test]
fn explicit_ed25519_identity() {
    let (_dir, repo) = auths_test_utils::git::init_test_repo();

    let init = create_keri_identity_with_curve(
        &repo,
        None,
        chrono::Utc::now(),
        auths_crypto::CurveType::Ed25519,
    )
    .unwrap();

    let kel = GitKel::new(&repo, init.prefix.as_str());
    let events = kel.get_events().unwrap();
    let icp = match &events[0] {
        Event::Icp(icp) => icp,
        other => panic!("expected inception event, got {:?}", other),
    };

    let key_str = icp.k[0].as_str();
    assert!(
        key_str.starts_with('D'),
        "Ed25519 identity should use D prefix, got: {}",
        &key_str[..4.min(key_str.len())]
    );

    assert_eq!(
        init.current_public_key.len(),
        32,
        "Ed25519 key should be 32 bytes"
    );
}
