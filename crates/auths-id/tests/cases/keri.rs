use auths_core::crypto::signer::encrypt_keypair;
use auths_core::signing::StorageSigner;
use auths_core::storage::keychain::{IdentityDID, KeyAlias, KeyRole, KeyStorage};
use auths_core::testing::{IsolatedKeychainHandle, TestPassphraseProvider};
use auths_id::keri::{
    Event, GitKel, InceptionResult, RotationResult, anchor_and_persist,
    create_keri_identity_with_curve, get_key_state, rotate_keys, verify_anchor,
    verify_anchor_by_digest,
};
use auths_id::keri::{
    parse_did_keri, resolve_did_keri, resolve_did_keri_at_sequence, validate_kel,
};
use serde::{Deserialize, Serialize};

const TEST_PASSPHRASE: &str = "Test-passphrase1!";

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

struct AnchorTestSetup {
    _dir: tempfile::TempDir,
    repo: git2::Repository,
    init: InceptionResult,
    identity_did: String,
    signer: StorageSigner<IsolatedKeychainHandle>,
    alias: KeyAlias,
    provider: TestPassphraseProvider,
}

fn setup_anchor_test() -> AnchorTestSetup {
    let (_dir, repo) = auths_test_utils::git::init_test_repo();
    let keychain = IsolatedKeychainHandle::new();

    let init = create_keri_identity_with_curve(
        &repo,
        None,
        chrono::Utc::now(),
        auths_crypto::CurveType::default(),
    )
    .unwrap();

    let identity_did = format!("did:keri:{}", init.prefix);
    let alias = KeyAlias::new_unchecked("test-anchor-key");
    let identity_did_typed = IdentityDID::new_unchecked(&identity_did);

    let encrypted = encrypt_keypair(init.current_keypair_pkcs8.as_ref(), TEST_PASSPHRASE)
        .expect("encrypt keypair");
    keychain
        .store_key(&alias, &identity_did_typed, KeyRole::Primary, &encrypted)
        .expect("store key");

    let signer = StorageSigner::new(keychain.clone());
    let provider = TestPassphraseProvider::new(TEST_PASSPHRASE);

    AnchorTestSetup {
        _dir,
        repo,
        init,
        identity_did,
        signer,
        alias,
        provider,
    }
}

fn anchor(s: &AnchorTestSetup, att: &TestAttestation) -> auths_id::keri::Said {
    let kel = GitKel::new(&s.repo, s.init.prefix.as_str());
    let (said, _ixn) = anchor_and_persist(
        &kel,
        &s.signer,
        &s.alias,
        &s.provider,
        &s.init.prefix,
        att,
        chrono::Utc::now(),
    )
    .unwrap();
    said
}

/// Tests the full KERI lifecycle: inception -> rotation -> rotation -> resolution
#[test]
fn full_keri_lifecycle() {
    let (_dir, repo) = auths_test_utils::git::init_test_repo();

    let init: InceptionResult = create_keri_identity_with_curve(
        &repo,
        None,
        chrono::Utc::now(),
        auths_crypto::CurveType::Ed25519,
    )
    .unwrap();

    let kel = GitKel::new(&repo, init.prefix.as_str());
    let events = kel.get_events().unwrap();
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], Event::Icp(_)));

    let did = format!("did:keri:{}", init.prefix);
    let resolved = resolve_did_keri(&repo, &did).unwrap();
    assert_eq!(resolved.public_key, init.current_public_key);
    assert_eq!(resolved.sequence, 0);
    assert!(resolved.can_rotate);
    assert!(!resolved.is_abandoned);

    let rot1: RotationResult = rotate_keys(
        &repo,
        &init.prefix,
        &init.next_keypair_pkcs8,
        None,
        chrono::Utc::now(),
    )
    .unwrap();
    assert_eq!(rot1.sequence, 1);

    let events = kel.get_events().unwrap();
    assert_eq!(events.len(), 2);
    assert!(matches!(events[1], Event::Rot(_)));

    let resolved = resolve_did_keri(&repo, &did).unwrap();
    assert_eq!(resolved.public_key, rot1.new_current_public_key);
    assert_eq!(resolved.sequence, 1);

    let state = validate_kel(&events).unwrap();
    assert_eq!(state.sequence, 1);

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

    let resolved_s0 = resolve_did_keri_at_sequence(&repo, &did, 0).unwrap();
    assert_eq!(resolved_s0.public_key, init.current_public_key);

    let resolved_s1 = resolve_did_keri_at_sequence(&repo, &did, 1).unwrap();
    assert_eq!(resolved_s1.public_key, rot1.new_current_public_key);

    let resolved_s2 = resolve_did_keri_at_sequence(&repo, &did, 2).unwrap();
    assert_eq!(resolved_s2.public_key, rot2.new_current_public_key);
}

#[test]
fn device_enrollment_with_anchoring() {
    let s = setup_anchor_test();

    let device_did = "did:key:z6MknSLrJoTcukLrE435hVNQT4JUhbvWLX4kUzqkEStBU8Vi";
    let attestation = make_test_attestation(&s.identity_did, device_did);
    let anchor_said = anchor(&s, &attestation);

    let kel = GitKel::new(&s.repo, s.init.prefix.as_str());
    let events = kel.get_events().unwrap();
    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], Event::Icp(_)));
    assert!(matches!(events[1], Event::Ixn(_)));

    let verification = verify_anchor(&s.repo, &s.init.prefix, &attestation).unwrap();
    assert_eq!(verification.status, auths_id::keri::AnchorStatus::Anchored);
    assert!(verification.anchor_said.is_some());
    assert_eq!(verification.anchor_sequence, Some(1));
    assert!(verification.signing_key.is_some());

    // attestation SAID (returned by anchor) != ixn SAID (in verification)
    // — the ixn wraps the attestation digest as a seal, so they're different by design
    let _ = anchor_said;
}

#[test]
fn multiple_device_attestations() {
    let s = setup_anchor_test();

    let att1 = make_test_attestation(&s.identity_did, "did:key:device1");
    let att2 = make_test_attestation(&s.identity_did, "did:key:device2");
    let att3 = make_test_attestation(&s.identity_did, "did:key:device3");

    let said1 = anchor(&s, &att1);
    let said2 = anchor(&s, &att2);
    let said3 = anchor(&s, &att3);

    assert_ne!(said1, said2);
    assert_ne!(said2, said3);
    assert_ne!(said1, said3);

    let kel = GitKel::new(&s.repo, s.init.prefix.as_str());
    let events = kel.get_events().unwrap();
    assert_eq!(events.len(), 4);

    let v1 = verify_anchor(&s.repo, &s.init.prefix, &att1).unwrap();
    let v2 = verify_anchor(&s.repo, &s.init.prefix, &att2).unwrap();
    let v3 = verify_anchor(&s.repo, &s.init.prefix, &att3).unwrap();

    assert_eq!(v1.status, auths_id::keri::AnchorStatus::Anchored);
    assert_eq!(v2.status, auths_id::keri::AnchorStatus::Anchored);
    assert_eq!(v3.status, auths_id::keri::AnchorStatus::Anchored);

    assert_eq!(v1.anchor_sequence, Some(1));
    assert_eq!(v2.anchor_sequence, Some(2));
    assert_eq!(v3.anchor_sequence, Some(3));
}

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

    let wrong_key = auths_crypto::Pkcs8Der::new([99u8; 85].to_vec());
    let result = rotate_keys(&repo, &init.prefix, &wrong_key, None, chrono::Utc::now());
    assert!(result.is_err());
}

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

    let kel = GitKel::new(&repo, init.prefix.as_str());
    let mut events = kel.get_events().unwrap();

    if let Event::Rot(ref mut rot) = events[1] {
        rot.s = auths_id::keri::KeriSequence::new(999);
    }

    let result = validate_kel(&events);
    assert!(result.is_err());
}

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

    let verification = verify_anchor(&repo, &init.prefix, &attestation).unwrap();
    assert_eq!(
        verification.status,
        auths_id::keri::AnchorStatus::NotAnchored
    );
    assert!(verification.anchor_said.is_none());
}

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

    let state = get_key_state(&repo, &init.prefix).unwrap();
    assert_eq!(state.sequence, 0);
    assert!(state.can_rotate());
    assert!(!state.is_abandoned);

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

    assert!(parse_did_keri("did:key:z6MkTest").is_err());
    assert!(parse_did_keri("did:keri:").is_err());
    assert!(parse_did_keri("not-a-did").is_err());
}

#[test]
fn verify_anchor_by_digest_works() {
    let s = setup_anchor_test();

    let attestation = make_test_attestation(&s.identity_did, "did:key:device");
    let anchor_said = anchor(&s, &attestation);

    let verification =
        verify_anchor_by_digest(&s.repo, &s.init.prefix, anchor_said.as_str()).unwrap();
    assert_eq!(verification.status, auths_id::keri::AnchorStatus::Anchored);
}

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
        key_str.starts_with("1AAI"),
        "default identity should use P-256 (1AAJ prefix), got: {}",
        &key_str[..4.min(key_str.len())]
    );

    assert_eq!(
        init.current_public_key.len(),
        33,
        "P-256 key should be 33 bytes"
    );
}

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
