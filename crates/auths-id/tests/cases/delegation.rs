//! A device as a KERI delegated identifier of the root identity.
//!
//! `incept_delegated_device` must author the device's `dip` AND the root's
//! anchoring `ixn`, so the existing `validate_delegation` confirms the root
//! delegated the device. The device holds its own key (never under the root
//! alias) — keripy-native, single-author, device-bound membership.

use std::sync::Arc;

use auths_core::storage::keychain::{IdentityDID, KeyAlias, KeyStorage};
use auths_core::testing::{IsolatedKeychainHandle, TestPassphraseProvider};
use auths_crypto::CurveType;
use auths_id::identity::initialize::initialize_registry_identity;
use auths_id::keri::delegation::{anchor_received_dip, build_device_dip, incept_delegated_device};
use auths_id::keri::types::Prefix;
use auths_id::keri::{Event, serialize_for_signing, validate_delegation};
use auths_id::storage::registry::backend::RegistryBackend;
use auths_id::testing::fakes::FakeRegistryBackend;
use auths_keri::parse_attachment;

const TEST_PASSPHRASE: &str = "Test-passphrase1!";

fn prefix_of(did: &IdentityDID) -> Prefix {
    Prefix::new_unchecked(
        did.as_str()
            .strip_prefix("did:keri:")
            .expect("did:keri prefix")
            .to_string(),
    )
}

#[test]
fn delegated_device_is_anchored_by_root() {
    let backend: Arc<dyn RegistryBackend + Send + Sync> = Arc::new(FakeRegistryBackend::new());
    let keychain = IsolatedKeychainHandle::new();
    let provider = TestPassphraseProvider::new(TEST_PASSPHRASE);

    // Root identity (single-controller).
    let root_alias = KeyAlias::new_unchecked("root");
    let (root_did, _) = initialize_registry_identity(
        backend.clone(),
        &root_alias,
        &provider,
        &keychain,
        None,
        CurveType::Ed25519,
    )
    .expect("root inception");
    let root_prefix = prefix_of(&root_did);

    // Delegate a device: the device gets its own KEL (a dip), the root anchors it.
    let device_alias = KeyAlias::new_unchecked("device-laptop");
    let dev = incept_delegated_device(
        backend.clone(),
        &root_prefix,
        &root_alias,
        CurveType::Ed25519,
        &device_alias,
        CurveType::Ed25519,
        &provider,
        &keychain,
    )
    .expect("delegate a device");

    // The root anchored the device's dip → the existing validator confirms it.
    let dip = backend
        .get_event(&dev.device_prefix, 0)
        .expect("device dip stored");
    let root_kel = vec![
        backend.get_event(&root_prefix, 0).expect("root icp"),
        backend
            .get_event(&root_prefix, 1)
            .expect("root anchoring ixn"),
    ];
    validate_delegation(&dip, &root_kel).expect("root must have anchored the delegation");

    // The device key is a DISTINCT AID stored under the device alias — the root
    // never holds it (true device-bound custody).
    let (root_key_did, _, _) = keychain.load_key(&root_alias).expect("root key present");
    let (dev_key_did, _, _) = keychain.load_key(&device_alias).expect("device key present");
    assert_ne!(
        root_key_did.as_str(),
        dev_key_did.as_str(),
        "the delegated device must be a distinct identifier from the root"
    );
    assert_eq!(
        dev_key_did.as_str(),
        dev.device_did.as_str(),
        "device key is bound to the device's own DID"
    );
}

#[test]
fn build_device_dip_is_backend_free_and_anchor_received_dip_delegates() {
    let backend: Arc<dyn RegistryBackend + Send + Sync> = Arc::new(FakeRegistryBackend::new());
    let keychain = IsolatedKeychainHandle::new();
    let provider = TestPassphraseProvider::new(TEST_PASSPHRASE);

    let root_alias = KeyAlias::new_unchecked("root");
    let (root_did, _) = initialize_registry_identity(
        backend.clone(),
        &root_alias,
        &provider,
        &keychain,
        None,
        CurveType::Ed25519,
    )
    .expect("root inception");
    let root_prefix = prefix_of(&root_did);

    // Joiner half: build + self-sign the device dip with NO backend and NO keychain.
    let bundle = build_device_dip(&root_prefix, CurveType::Ed25519).expect("build device dip");

    // The dip is genuinely signed by the device's own key — verifiable offline,
    // before any anchoring touches a registry.
    let sigs = parse_attachment(&bundle.attachment).expect("parse dip attachment");
    assert_eq!(sigs.len(), 1, "device self-signs its dip once");
    let canonical =
        serialize_for_signing(&Event::Dip(bundle.dip.clone())).expect("canonical dip bytes");
    let device_key = bundle.dip.k[0].parse().expect("device verkey");
    device_key
        .verify_signature(&canonical, &sigs[0].sig)
        .expect("the dip carries the device's own valid signature");

    // Initiator half: anchor the received dip on the root's registry. No device
    // private key is needed here — the dip is already signed.
    let (device_did, anchor_ixn) = anchor_received_dip(
        backend.as_ref(),
        &root_prefix,
        &root_alias,
        CurveType::Ed25519,
        &bundle.dip,
        &bundle.attachment,
        &provider,
        &keychain,
    )
    .expect("anchor the received dip");
    assert_eq!(device_did.as_str(), bundle.device_did.as_str());

    // The returned ixn is the root's anchor — it authors over the root prefix and
    // carries the delegation seal for this dip.
    assert_eq!(anchor_ixn.i, root_prefix);
    validate_delegation(&Event::Dip(bundle.dip.clone()), &[Event::Ixn(anchor_ixn)])
        .expect("the returned ixn alone proves the delegation");

    // Same outcome as a same-host add: the root anchored the delegation.
    let dip = backend
        .get_event(&bundle.device_prefix, 0)
        .expect("device dip stored");
    let root_kel = vec![
        backend.get_event(&root_prefix, 0).expect("root icp"),
        backend
            .get_event(&root_prefix, 1)
            .expect("root anchoring ixn"),
    ];
    validate_delegation(&dip, &root_kel).expect("root must have anchored the split delegation");
}
