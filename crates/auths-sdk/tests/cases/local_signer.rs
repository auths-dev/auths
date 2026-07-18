//! Local signer-identity resolution across root + delegate machines.
//!
//! The commit-signing trailer needs "who am I (signer) + what root do I chain to".
//! A root machine signs as its controller; a delegate machine (post-pairing) holds
//! only its own `dip`-rooted KEL and must resolve its device AID + the delegator.

use std::sync::Arc;

use auths_core::testing::IsolatedKeychainHandle;
use auths_crypto::CurveType;
use auths_id::keri::Event;
use auths_id::keri::delegation::build_device_dip;
use auths_id::keri::parse_did_keri;
use auths_id::storage::registry::backend::RegistryBackend;
use auths_sdk::domains::identity::local::resolve_local_signer;

use crate::cases::helpers::{build_test_context, setup_signed_artifact_context};

#[test]
fn resolve_local_signer_on_root_machine_signs_as_delegated_device() {
    let (_tmp, _alias, ctx) = setup_signed_artifact_context();

    let signer = resolve_local_signer(&ctx).expect("a root machine resolves its signer");

    // A fresh developer identity delegates device #0; the root machine signs as that
    // device (its own delegated AID), distinct from the root it chains to.
    assert!(signer.signer_did.starts_with("did:keri:"));
    assert!(signer.root_did.starts_with("did:keri:"));
    assert_ne!(
        signer.signer_did, signer.root_did,
        "the root machine signs as delegated device #0, not directly as the root"
    );
    assert!(signer.is_delegated());
}

#[test]
fn resolve_local_signer_on_delegate_machine_returns_device_and_root() {
    // A root identity, only to source a valid delegator prefix.
    let (_root_tmp, _alias, root_ctx) = setup_signed_artifact_context();
    let root_did = root_ctx
        .identity_storage
        .load_identity()
        .expect("root identity")
        .controller_did
        .to_string();
    let root_prefix = parse_did_keri(&root_did).expect("root prefix");

    // A delegated device's self-signed dip (delegator = root).
    let bundle = build_device_dip(&root_prefix, CurveType::Ed25519).expect("build device dip");

    // A fresh DELEGATE machine: its registry holds ONLY this device's dip — no icp root.
    let delegate_tmp = tempfile::TempDir::new().expect("temp dir");
    let delegate_path = delegate_tmp.path().join(".auths-delegate");
    let delegate_ctx = build_test_context(&delegate_path, Arc::new(IsolatedKeychainHandle::new()));
    delegate_ctx
        .registry
        .init_if_needed()
        .expect("init delegate registry");
    delegate_ctx
        .registry
        .append_signed_event(
            &bundle.device_prefix,
            &Event::Dip(bundle.dip.clone()),
            &bundle.attachment,
        )
        .expect("append the device dip to the delegate registry");

    let signer =
        resolve_local_signer(&delegate_ctx).expect("a delegate machine resolves its signer");

    assert_eq!(
        signer.signer_did.as_str(),
        bundle.device_did.as_str(),
        "the signer is this device's own AID"
    );
    assert_eq!(signer.root_did, root_did, "the root is the dip's delegator");
    assert!(signer.is_delegated());
}
