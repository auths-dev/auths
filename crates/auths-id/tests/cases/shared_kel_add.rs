//! Append a provided (paired-device) controller to a shared identity KEL.
//!
//! A growth rotation must place a *caller-supplied* verkey into `k[]` and the
//! caller's next-key commitment into `n[]` without generating or storing any
//! local key material for that slot — the paired device holds its own private
//! key. (The local-generate path, `add_devices`, is covered elsewhere.)

use std::sync::Arc;

use auths_core::storage::keychain::{IdentityDID, KeyAlias, KeyStorage};
use auths_core::testing::{IsolatedKeychainHandle, TestPassphraseProvider};
use auths_crypto::CurveType;
use auths_id::identity::initialize::initialize_registry_identity_multi;
use auths_id::identity::rotate::{ProvidedController, RotationShape, rotate_registry_identity_multi};
use auths_id::keri::Threshold;
use auths_id::keri::shared_kel::{ControllerDescriptor, controller_from_parts};
use auths_id::keri::types::Prefix;
use auths_id::storage::layout::StorageLayoutConfig;
use auths_id::storage::registry::backend::RegistryBackend;
use auths_id::testing::fakes::FakeRegistryBackend;
use auths_keri::{KeriPublicKey, compute_next_commitment};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

const TEST_PASSPHRASE: &str = "Test-passphrase1!";

fn prefix_of(did: &IdentityDID) -> Prefix {
    Prefix::new_unchecked(
        did.as_str()
            .strip_prefix("did:keri:")
            .expect("did:keri prefix")
            .to_string(),
    )
}

#[allow(clippy::disallowed_methods)]
fn remote_did(s: &str) -> IdentityDID {
    IdentityDID::new_unchecked(s.to_string())
}

fn ed25519() -> Ed25519KeyPair {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
}

fn vk(kp: &Ed25519KeyPair) -> KeriPublicKey {
    KeriPublicKey::ed25519(kp.public_key().as_ref()).unwrap()
}

/// A paired remote device: its current verkey + a commitment to its next key.
/// The private keys belong to the remote and are never placed in the keychain.
fn remote_ed25519(did: &str) -> (ProvidedController, KeriPublicKey) {
    let cur = vk(&ed25519());
    let next_commitment = compute_next_commitment(&vk(&ed25519()));
    let provided = ProvidedController {
        descriptor: ControllerDescriptor {
            identity_did: remote_did(did),
            current_verkey: cur.clone(),
        },
        next_commitment,
    };
    (provided, cur)
}

fn incept_single(
    backend: &Arc<dyn RegistryBackend + Send + Sync>,
    keychain: &IsolatedKeychainHandle,
    provider: &TestPassphraseProvider,
    curve: CurveType,
) -> (IdentityDID, KeyAlias) {
    initialize_registry_identity_multi(
        backend.clone(),
        &KeyAlias::new_unchecked("shared"),
        provider,
        keychain,
        None,
        &[curve],
        Threshold::Simple(1),
        Threshold::Simple(1),
    )
    .expect("single-controller inception")
}

#[test]
fn shared_kel_adds_controller_one_to_two() {
    let backend: Arc<dyn RegistryBackend + Send + Sync> = Arc::new(FakeRegistryBackend::new());
    let keychain = IsolatedKeychainHandle::new();
    let provider = TestPassphraseProvider::new(TEST_PASSPHRASE);

    let (did, current_alias) = incept_single(&backend, &keychain, &provider, CurveType::Ed25519);
    let prefix = prefix_of(&did);
    assert_eq!(
        backend.get_key_state(&prefix).unwrap().current_keys.len(),
        1
    );

    let (provided, remote_vk) = remote_ed25519("did:keri:ERemotePhoneAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    rotate_registry_identity_multi(
        backend.clone(),
        &current_alias,
        &KeyAlias::new_unchecked("shared-r1"),
        &provider,
        &StorageLayoutConfig::default(),
        &keychain,
        None,
        RotationShape {
            add_controllers: vec![provided],
            ..Default::default()
        },
    )
    .expect("growth rotation with a provided controller must author and replay");

    let state = backend.get_key_state(&prefix).expect("post-add key state replays");
    assert_eq!(
        state.current_keys.len(),
        2,
        "growth must append the provided controller"
    );
    assert_eq!(
        state.current_keys[1].as_str(),
        remote_vk.to_qb64().unwrap(),
        "k[1] must be the provided device's verkey"
    );
    assert_eq!(state.sequence, 1, "the growth is the sn=1 rotation");

    // No local key material was generated or stored for the provided slot.
    assert!(
        keychain
            .load_key(&KeyAlias::new_unchecked("shared-r1--1"))
            .is_err(),
        "the provided controller's slot must hold NO local private key"
    );
    // The surviving controller's own slot IS stored locally.
    assert!(
        keychain
            .load_key(&KeyAlias::new_unchecked("shared-r1--0"))
            .is_ok(),
        "the surviving local controller's slot must be present"
    );
}

#[test]
fn shared_kel_adds_controller_mixed_curve() {
    let backend: Arc<dyn RegistryBackend + Send + Sync> = Arc::new(FakeRegistryBackend::new());
    let keychain = IsolatedKeychainHandle::new();
    let provider = TestPassphraseProvider::new(TEST_PASSPHRASE);

    // Ed25519 identity, P-256 provided controller — a heterogeneous controller set.
    let (did, current_alias) = incept_single(&backend, &keychain, &provider, CurveType::Ed25519);
    let prefix = prefix_of(&did);

    let p256_cur = controller_from_parts(
        remote_did("did:keri:ERemoteP256AAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        vec![2u8; 33],
        CurveType::P256,
    )
    .expect("p256 controller");
    let next_commitment = compute_next_commitment(&p256_cur.current_verkey);
    let provided = ProvidedController {
        descriptor: p256_cur,
        next_commitment,
    };

    rotate_registry_identity_multi(
        backend.clone(),
        &current_alias,
        &KeyAlias::new_unchecked("shared-r1"),
        &provider,
        &StorageLayoutConfig::default(),
        &keychain,
        None,
        RotationShape {
            add_controllers: vec![provided],
            ..Default::default()
        },
    )
    .expect("heterogeneous-curve growth must author and replay");

    let state = backend.get_key_state(&prefix).expect("replay");
    assert_eq!(state.current_keys.len(), 2, "mixed-curve set must replay to 2");
}

#[test]
fn shared_kel_add_controller_rejects_duplicate_verkey() {
    let backend: Arc<dyn RegistryBackend + Send + Sync> = Arc::new(FakeRegistryBackend::new());
    let keychain = IsolatedKeychainHandle::new();
    let provider = TestPassphraseProvider::new(TEST_PASSPHRASE);

    let (_did, current_alias) = incept_single(&backend, &keychain, &provider, CurveType::Ed25519);

    let (provided, _vk) = remote_ed25519("did:keri:ERemoteDupAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    // The same verkey supplied twice must be rejected (no duplicate k[] slot).
    let err = rotate_registry_identity_multi(
        backend.clone(),
        &current_alias,
        &KeyAlias::new_unchecked("shared-r1"),
        &provider,
        &StorageLayoutConfig::default(),
        &keychain,
        None,
        RotationShape {
            add_controllers: vec![provided.clone(), provided],
            ..Default::default()
        },
    );
    assert!(
        err.is_err(),
        "appending the same verkey twice must be a typed error"
    );
}
