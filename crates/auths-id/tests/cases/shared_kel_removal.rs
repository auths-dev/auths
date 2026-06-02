//! B.5 — true-remove a controller from a shared identity KEL.
//!
//! A 3-controller shared KEL (kt=1) rotates to 2 by dropping a slot. The
//! authoring path emits a shrink-`k` `rot` whose surviving signer reveals its
//! prior commitment (dual-index); the result must replay to a 2-controller key
//! state. (The dual-index signature binding itself is covered by auths-keri's
//! `dual_index` cases; here we exercise the auths-id authoring end-to-end.)

use std::sync::Arc;

use auths_core::storage::keychain::KeyAlias;
use auths_core::testing::{IsolatedKeychainHandle, TestPassphraseProvider};
use auths_crypto::CurveType;
use auths_id::identity::initialize::initialize_registry_identity_multi;
use auths_id::identity::rotate::{RotationShape, rotate_registry_identity_multi};
use auths_id::keri::Threshold;
use auths_id::keri::types::Prefix;
use auths_id::storage::layout::StorageLayoutConfig;
use auths_id::storage::registry::backend::RegistryBackend;
use auths_id::testing::fakes::FakeRegistryBackend;

const TEST_PASSPHRASE: &str = "Test-passphrase1!";

fn prefix_of(did: &auths_core::storage::keychain::IdentityDID) -> Prefix {
    Prefix::new_unchecked(
        did.as_str()
            .strip_prefix("did:keri:")
            .expect("did:keri prefix")
            .to_string(),
    )
}

#[test]
fn shared_kel_removes_controller_three_to_two() {
    let backend: Arc<dyn RegistryBackend + Send + Sync> = Arc::new(FakeRegistryBackend::new());
    let keychain = IsolatedKeychainHandle::new();
    let provider = TestPassphraseProvider::new(TEST_PASSPHRASE);
    let alias = KeyAlias::new_unchecked("shared");

    // Incept a 3-controller shared KEL (kt=1 / nt=1).
    let (did, current_alias) = initialize_registry_identity_multi(
        backend.clone(),
        &alias,
        &provider,
        &keychain,
        None,
        &[CurveType::Ed25519, CurveType::Ed25519, CurveType::Ed25519],
        Threshold::Simple(1),
        Threshold::Simple(1),
    )
    .expect("multi-controller inception");

    let prefix = prefix_of(&did);
    assert_eq!(
        backend.get_key_state(&prefix).unwrap().current_keys.len(),
        3,
        "inception must record 3 controllers"
    );

    // Rotate 3 -> 2 by removing the controller at slot 2 (pure removal).
    rotate_registry_identity_multi(
        backend.clone(),
        &current_alias,
        &KeyAlias::new_unchecked("shared-r1"),
        &provider,
        &StorageLayoutConfig::default(),
        &keychain,
        None,
        RotationShape {
            remove_indices: vec![2],
            ..Default::default()
        },
    )
    .expect("pure-removal rotation must author and validate");

    // The KEL replays to a 2-controller state.
    let state = backend
        .get_key_state(&prefix)
        .expect("post-removal key state must replay");
    assert_eq!(
        state.current_keys.len(),
        2,
        "removal must shrink the controller set 3 -> 2"
    );
    assert_eq!(state.sequence, 1, "removal is the sn=1 rotation");
}
