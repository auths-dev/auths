//! Full anchor lifecycle: icp → ixn(link) → rot → ixn(link2) → ixn(revoke) → verify all.

use auths_core::crypto::signer::encrypt_keypair;
use auths_core::signing::StorageSigner;
use auths_core::storage::keychain::{IdentityDID, KeyAlias, KeyRole, KeyStorage};
use auths_core::testing::{IsolatedKeychainHandle, TestPassphraseProvider};
use auths_id::keri::{
    AnchorStatus, Event, GitKel, anchor_and_persist, create_keri_identity_with_curve, rotate_keys,
    validate_kel, verify_anchor, verify_anchor_by_digest,
};
use serde::{Deserialize, Serialize};

const TEST_PASSPHRASE: &str = "Test-passphrase1!";

#[derive(Debug, Serialize, Deserialize)]
struct DeviceLinkAttestation {
    issuer: String,
    subject: String,
    action: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DeviceRevokeAttestation {
    issuer: String,
    subject: String,
    action: String,
    reason: String,
}

fn store_key(keychain: &IsolatedKeychainHandle, pkcs8: &[u8], alias: &str, did: &str) -> KeyAlias {
    let alias = KeyAlias::new_unchecked(alias);
    let did = IdentityDID::new_unchecked(did);
    let encrypted = encrypt_keypair(pkcs8, TEST_PASSPHRASE).expect("encrypt");
    keychain
        .store_key(&alias, &did, KeyRole::Primary, &encrypted)
        .expect("store");
    alias
}

#[test]
fn full_anchor_lifecycle_with_rotation() {
    let (_dir, repo) = auths_test_utils::git::init_test_repo();
    let keychain = IsolatedKeychainHandle::new();
    let provider = TestPassphraseProvider::new(TEST_PASSPHRASE);

    // ICP(0) — Ed25519 because rotate_keys is still Ed25519-only
    let init = create_keri_identity_with_curve(
        &repo,
        None,
        chrono::Utc::now(),
        auths_crypto::CurveType::Ed25519,
    )
    .unwrap();
    let did = format!("did:keri:{}", init.prefix);

    let alias0 = store_key(
        &keychain,
        init.current_keypair_pkcs8.as_ref(),
        "key-0",
        &did,
    );

    // IXN(1) — link device A
    let link_a = DeviceLinkAttestation {
        issuer: did.clone(),
        subject: "did:key:deviceA".into(),
        action: "link".into(),
    };
    let kel = GitKel::new(&repo, init.prefix.as_str());
    let signer = StorageSigner::new(keychain.clone());
    let (said_a, ixn_a) = anchor_and_persist(
        &kel,
        &signer,
        &alias0,
        &provider,
        &init.prefix,
        &link_a,
        chrono::Utc::now(),
    )
    .unwrap();
    assert_eq!(ixn_a.s.value(), 1);

    // ROT(2) — rotate key
    let rot1 = rotate_keys(
        &repo,
        &init.prefix,
        &init.next_keypair_pkcs8,
        None,
        chrono::Utc::now(),
    )
    .unwrap();
    assert_eq!(rot1.sequence, 2);

    let alias1 = store_key(
        &keychain,
        rot1.new_current_keypair_pkcs8.as_ref(),
        "key-1",
        &did,
    );

    // IXN(3) — link device B with rotated key
    let link_b = DeviceLinkAttestation {
        issuer: did.clone(),
        subject: "did:key:deviceB".into(),
        action: "link".into(),
    };
    let signer = StorageSigner::new(keychain.clone());
    let (said_b, ixn_b) = anchor_and_persist(
        &kel,
        &signer,
        &alias1,
        &provider,
        &init.prefix,
        &link_b,
        chrono::Utc::now(),
    )
    .unwrap();
    assert_eq!(ixn_b.s.value(), 3);

    // IXN(4) — revoke device A
    let revoke_a = DeviceRevokeAttestation {
        issuer: did.clone(),
        subject: "did:key:deviceA".into(),
        action: "revoke".into(),
        reason: "lost device".into(),
    };
    let (said_revoke, ixn_revoke) = anchor_and_persist(
        &kel,
        &signer,
        &alias1,
        &provider,
        &init.prefix,
        &revoke_a,
        chrono::Utc::now(),
    )
    .unwrap();
    assert_eq!(ixn_revoke.s.value(), 4);

    // Verify KEL structure: ICP(0) IXN(1) ROT(2) IXN(3) IXN(4)
    let events = kel.get_events().unwrap();
    assert_eq!(events.len(), 5);
    assert!(matches!(events[0], Event::Icp(_)));
    assert!(matches!(events[1], Event::Ixn(_)));
    assert!(matches!(events[2], Event::Rot(_)));
    assert!(matches!(events[3], Event::Ixn(_)));
    assert!(matches!(events[4], Event::Ixn(_)));

    let state = validate_kel(&events).unwrap();
    assert_eq!(state.sequence, 4);
    assert!(!state.is_abandoned);
    assert!(state.can_rotate());

    // Verify all anchors can be found
    let v_a = verify_anchor(&repo, &init.prefix, &link_a).unwrap();
    assert_eq!(v_a.status, AnchorStatus::Anchored);
    assert_eq!(v_a.anchor_sequence, Some(1));

    let v_b = verify_anchor(&repo, &init.prefix, &link_b).unwrap();
    assert_eq!(v_b.status, AnchorStatus::Anchored);
    assert_eq!(v_b.anchor_sequence, Some(3));

    let v_revoke = verify_anchor(&repo, &init.prefix, &revoke_a).unwrap();
    assert_eq!(v_revoke.status, AnchorStatus::Anchored);
    assert_eq!(v_revoke.anchor_sequence, Some(4));

    // Verify by digest too
    let v_by_digest = verify_anchor_by_digest(&repo, &init.prefix, said_a.as_str()).unwrap();
    assert_eq!(v_by_digest.status, AnchorStatus::Anchored);

    // Unanchored data returns NotAnchored
    let unlinked = DeviceLinkAttestation {
        issuer: did.clone(),
        subject: "did:key:deviceC".into(),
        action: "link".into(),
    };
    let v_missing = verify_anchor(&repo, &init.prefix, &unlinked).unwrap();
    assert_eq!(v_missing.status, AnchorStatus::NotAnchored);

    // All SAIDs are unique
    assert_ne!(said_a, said_b);
    assert_ne!(said_b, said_revoke);
    assert_ne!(said_a, said_revoke);
}
