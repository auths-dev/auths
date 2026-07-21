//! Witness-set declaration: the set's content SAID is anchored in the
//! identity's KEL by one `ixn`, resolvable with the same seal walker
//! verifiers use — and an undeclared set is NOT resolvable.

use std::ops::ControlFlow;
use std::sync::Arc;

use auths_core::PrefilledPassphraseProvider;
use auths_core::signing::PassphraseProvider;
use auths_core::storage::keychain::KeyAlias;
use auths_core::testing::IsolatedKeychainHandle;
use auths_crypto::CurveType;
use auths_id::keri::parse_did_keri;
use auths_id::ports::registry::RegistryBackend;
use auths_sdk::context::AuthsContext;
use auths_sdk::identity::initialize_registry_identity;
use auths_sdk::witness::WitnessParams;
use auths_sdk::workflows::witness_set::{build_witness_set, declare_witness_set};

use crate::cases::helpers::build_test_context_with_provider;

const PASS: &str = "Test-passphrase1!";

fn member_spec(name: &str, byte: u8) -> String {
    format!("{name}={}", hex::encode([byte; 32]))
}

/// `(ctx, signing alias, tmp)` for a fresh registry identity.
fn setup() -> (AuthsContext, KeyAlias, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let keychain = IsolatedKeychainHandle::new();
    let provider: Arc<dyn PassphraseProvider + Send + Sync> =
        Arc::new(PrefilledPassphraseProvider::new(PASS));
    let ctx =
        build_test_context_with_provider(tmp.path(), Arc::new(keychain.clone()), Some(provider));
    let (_did, alias) = initialize_registry_identity(
        Arc::clone(&ctx.registry),
        &KeyAlias::new_unchecked("main"),
        &PrefilledPassphraseProvider::new(PASS),
        &keychain,
        WitnessParams::Disabled,
        CurveType::default(),
        chrono::Utc::now(),
    )
    .expect("init registry identity");
    (ctx, alias, tmp)
}

/// Replay the managed identity's KEL and collect its `ixn` digest seals —
/// exactly what a verifier resolves a declaration from.
fn kel_digest_seals(ctx: &AuthsContext) -> Vec<String> {
    let managed = ctx.identity_storage.load_identity().expect("identity");
    let prefix = parse_did_keri(&managed.controller_did.to_string()).expect("prefix");
    let mut events = Vec::new();
    ctx.registry
        .visit_events(&prefix, 0, &mut |event| {
            events.push(event.clone());
            ControlFlow::Continue(())
        })
        .expect("replay KEL");
    auths_anchor::ixn_digest_seals(&events)
}

#[test]
fn declared_witness_set_is_anchored_in_the_kel() {
    let (ctx, alias, _tmp) = setup();

    let set = build_witness_set(&[member_spec("w1", 1), member_spec("w2", 2)], 2).expect("set");
    let declared = declare_witness_set(&ctx, &alias, &set).expect("declare");

    assert_eq!(declared.set_said, set.said);
    assert!(declared.ixn_said.starts_with('E'));
    assert!(declared.sequence >= 1);

    let seals = kel_digest_seals(&ctx);
    assert_eq!(
        auths_anchor::find_witness_set_seal(&seals, &set.said),
        Some(set.said.as_str()),
        "the declared set SAID must be resolvable from the KEL's ixn digest seals"
    );
}

#[test]
fn an_undeclared_set_is_not_resolvable_from_the_kel() {
    let (ctx, alias, _tmp) = setup();

    let declared_set =
        build_witness_set(&[member_spec("w1", 1), member_spec("w2", 2)], 2).expect("set");
    declare_witness_set(&ctx, &alias, &declared_set).expect("declare");

    let other_set =
        build_witness_set(&[member_spec("w1", 1), member_spec("w3", 3)], 1).expect("set");
    assert_ne!(other_set.said, declared_set.said);

    let seals = kel_digest_seals(&ctx);
    assert_eq!(
        auths_anchor::find_witness_set_seal(&seals, &other_set.said),
        None,
        "a set never declared must not resolve from the KEL"
    );
}
