use std::sync::Arc;

use auths_core::PrefilledPassphraseProvider;
use auths_core::ports::clock::SystemClock;
use auths_core::signing::{PassphraseProvider, StorageSigner};
use auths_core::storage::keychain::KeyAlias;
use auths_core::testing::IsolatedKeychainHandle;
use auths_sdk::domains::device::error::DeviceExtensionError;
use auths_sdk::domains::device::service::{extend_device, link_device};
use auths_sdk::domains::device::types::{DeviceExtensionConfig, DeviceLinkConfig};
use auths_sdk::domains::identity::service::initialize;
use auths_sdk::domains::identity::types::InitializeResult;
use auths_sdk::domains::identity::types::{CreateDeveloperIdentityConfig, IdentityConfig};
use auths_sdk::domains::signing::types::GitSigningScope;

use crate::cases::helpers::{build_test_context, build_test_context_with_provider};

use std::ops::ControlFlow;

use auths_crypto::CurveType;
use auths_id::keri::Seal;
use auths_id::keri::types::Prefix;
use auths_id::keri::validate_delegation;
use auths_id::storage::registry::backend::RegistryBackend;
use auths_sdk::domains::device::{add_device, list_delegated_devices, remove_device};

fn setup_test_identity(registry_path: &std::path::Path) -> (KeyAlias, IsolatedKeychainHandle) {
    let keychain = IsolatedKeychainHandle::new();
    let signer = StorageSigner::new(keychain.clone());
    let provider = PrefilledPassphraseProvider::new("Test-passphrase1!");
    let config = CreateDeveloperIdentityConfig::builder(KeyAlias::new_unchecked("test-key"))
        .with_git_signing_scope(GitSigningScope::Skip)
        .build();
    let ctx = build_test_context(registry_path, Arc::new(keychain.clone()));
    let result = match initialize(
        IdentityConfig::Developer(config),
        &ctx,
        Arc::new(keychain.clone()),
        &signer,
        &provider,
        None,
    )
    .unwrap()
    {
        InitializeResult::Developer(r) => r,
        _ => unreachable!(),
    };
    (result.key_alias, keychain)
}

#[test]
fn add_device_delegates_and_root_anchors() {
    let tmp = tempfile::tempdir().unwrap();
    let (root_alias, keychain) = setup_test_identity(tmp.path());
    let provider: Arc<dyn PassphraseProvider + Send + Sync> =
        Arc::new(PrefilledPassphraseProvider::new("Test-passphrase1!"));
    let ctx =
        build_test_context_with_provider(tmp.path(), Arc::new(keychain.clone()), Some(provider));

    // Capture the root prefix BEFORE adding the device — `load_identity` would be
    // ambiguous once a second (delegated) KEL exists.
    let root_prefix = {
        let managed = ctx
            .identity_storage
            .load_identity()
            .expect("root identity loads");
        Prefix::new_unchecked(
            managed
                .controller_did
                .as_str()
                .strip_prefix("did:keri:")
                .unwrap()
                .to_string(),
        )
    };

    // Add a device as a delegated identifier of the root.
    let device_alias = KeyAlias::new_unchecked("laptop");
    let dev = add_device(&ctx, &root_alias, &device_alias, CurveType::Ed25519)
        .expect("add a delegated device");
    assert!(dev.device_did.starts_with("did:keri:"));

    // The root anchored the device's dip → the validator confirms the delegation.
    // Walk the whole root KEL (the anchoring ixn isn't at a fixed sequence).
    let device_prefix = Prefix::new_unchecked(dev.device_prefix.clone());
    let dip = ctx
        .registry
        .get_event(&device_prefix, 0)
        .expect("device dip stored");
    let mut root_kel = Vec::new();
    ctx.registry
        .visit_events(&root_prefix, 0, &mut |e| {
            root_kel.push(e.clone());
            ControlFlow::Continue(())
        })
        .expect("walk root KEL");
    validate_delegation(&dip, &root_kel).expect("root must have anchored the delegated device");
}

#[test]
fn remove_device_revokes_the_delegation() {
    let tmp = tempfile::tempdir().unwrap();
    let (root_alias, keychain) = setup_test_identity(tmp.path());
    let provider: Arc<dyn PassphraseProvider + Send + Sync> =
        Arc::new(PrefilledPassphraseProvider::new("Test-passphrase1!"));
    let ctx =
        build_test_context_with_provider(tmp.path(), Arc::new(keychain.clone()), Some(provider));

    let root_prefix = {
        let managed = ctx
            .identity_storage
            .load_identity()
            .expect("root identity loads");
        Prefix::new_unchecked(
            managed
                .controller_did
                .as_str()
                .strip_prefix("did:keri:")
                .unwrap()
                .to_string(),
        )
    };
    let dev = add_device(
        &ctx,
        &root_alias,
        &KeyAlias::new_unchecked("laptop"),
        CurveType::Ed25519,
    )
    .expect("add a delegated device");

    // Revoke it: the root anchors a revocation marker.
    remove_device(&ctx, &root_alias, &dev.device_did).expect("revoke the device");

    let mut revoked = false;
    ctx.registry
        .visit_events(&root_prefix, 0, &mut |e| {
            if e.anchors()
                .iter()
                .any(|s| matches!(s, Seal::Digest { d } if d.as_str() == dev.device_prefix))
            {
                revoked = true;
            }
            ControlFlow::Continue(())
        })
        .expect("walk root KEL");
    assert!(
        revoked,
        "a revocation marker (digest seal of the device prefix) must be anchored"
    );

    // Revoking an unknown device, or the root identity itself, is a typed error.
    assert!(
        remove_device(
            &ctx,
            &root_alias,
            "did:keri:EUnknownDeviceAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        .is_err()
    );
    let root_did = format!("did:keri:{}", root_prefix.as_str());
    assert!(remove_device(&ctx, &root_alias, &root_did).is_err());
}

#[test]
fn list_delegated_devices_reflects_revocation() {
    let tmp = tempfile::tempdir().unwrap();
    let (root_alias, keychain) = setup_test_identity(tmp.path());
    let provider: Arc<dyn PassphraseProvider + Send + Sync> =
        Arc::new(PrefilledPassphraseProvider::new("Test-passphrase1!"));
    let ctx =
        build_test_context_with_provider(tmp.path(), Arc::new(keychain.clone()), Some(provider));

    let d1 = add_device(
        &ctx,
        &root_alias,
        &KeyAlias::new_unchecked("laptop"),
        CurveType::Ed25519,
    )
    .expect("add laptop");
    let d2 = add_device(
        &ctx,
        &root_alias,
        &KeyAlias::new_unchecked("phone"),
        CurveType::Ed25519,
    )
    .expect("add phone");

    // Two delegated devices, none revoked yet.
    let listed = list_delegated_devices(&ctx).expect("list devices");
    assert_eq!(listed.len(), 2, "both delegations are recorded");
    assert_eq!(listed.iter().filter(|d| !d.revoked).count(), 2);

    // Revoke one → the live set drops to one (the revoked delegation is still recorded).
    remove_device(&ctx, &root_alias, &d1.device_did).expect("revoke laptop");
    let listed = list_delegated_devices(&ctx).expect("list after revoke");
    assert_eq!(listed.len(), 2);
    assert_eq!(
        listed.iter().filter(|d| !d.revoked).count(),
        1,
        "only one device is live after revocation"
    );
    assert!(
        listed
            .iter()
            .any(|d| d.device_did == d2.device_did && !d.revoked)
    );
    assert!(
        listed
            .iter()
            .any(|d| d.device_did == d1.device_did && d.revoked)
    );
}

#[test]
fn delegated_device_rotates_its_own_key() {
    let tmp = tempfile::tempdir().unwrap();
    let (root_alias, keychain) = setup_test_identity(tmp.path());
    let provider: Arc<dyn PassphraseProvider + Send + Sync> =
        Arc::new(PrefilledPassphraseProvider::new("Test-passphrase1!"));
    let ctx =
        build_test_context_with_provider(tmp.path(), Arc::new(keychain.clone()), Some(provider));

    let root_prefix = {
        let m = ctx.identity_storage.load_identity().expect("root identity");
        Prefix::new_unchecked(
            m.controller_did
                .as_str()
                .strip_prefix("did:keri:")
                .unwrap()
                .to_string(),
        )
    };
    let (_pk, root_curve) = auths_core::storage::keychain::extract_public_key_bytes(
        ctx.key_storage.as_ref(),
        &root_alias,
        ctx.passphrase_provider.as_ref(),
    )
    .expect("root curve");

    let device_alias = KeyAlias::new_unchecked("laptop");
    let dev = add_device(&ctx, &root_alias, &device_alias, CurveType::Ed25519).expect("add device");
    let device_prefix = Prefix::new_unchecked(dev.device_prefix.clone());
    let before = ctx
        .registry
        .get_key_state(&device_prefix)
        .expect("device state")
        .current_keys[0]
        .as_str()
        .to_string();

    // The device rotates its OWN key; the root anchors the drt.
    auths_id::keri::delegation::rotate_delegated_device(
        ctx.registry.as_ref(),
        &root_prefix,
        &root_alias,
        root_curve,
        &device_prefix,
        &device_alias,
        CurveType::Ed25519,
        ctx.passphrase_provider.as_ref(),
        ctx.key_storage.as_ref(),
    )
    .expect("rotate the delegated device's key");

    let after = ctx
        .registry
        .get_key_state(&device_prefix)
        .expect("device state after");
    assert_eq!(after.sequence, 1, "the drt is the sn=1 event");
    assert_ne!(
        after.current_keys[0].as_str(),
        before,
        "the device's current key rotated"
    );

    // The root anchored the drt → validate_delegation passes for the drt.
    let drt = ctx
        .registry
        .get_event(&device_prefix, 1)
        .expect("drt event");
    let mut root_kel = Vec::new();
    ctx.registry
        .visit_events(&root_prefix, 0, &mut |e| {
            root_kel.push(e.clone());
            ControlFlow::Continue(())
        })
        .expect("walk root KEL");
    validate_delegation(&drt, &root_kel).expect("root must have anchored the drt");
}

fn link_test_device(
    registry_path: &std::path::Path,
    key_alias: &KeyAlias,
    keychain: &IsolatedKeychainHandle,
) -> String {
    let signer = StorageSigner::new(keychain.clone());
    let provider = PrefilledPassphraseProvider::new("Test-passphrase1!");
    let config = CreateDeveloperIdentityConfig::builder(KeyAlias::new_unchecked("device-key"))
        .with_git_signing_scope(GitSigningScope::Skip)
        .with_conflict_policy(auths_sdk::domains::identity::types::IdentityConflictPolicy::ForceNew)
        .build();
    let ctx = build_test_context(registry_path, Arc::new(keychain.clone()));
    initialize(
        IdentityConfig::Developer(config),
        &ctx,
        Arc::new(keychain.clone()),
        &signer,
        &provider,
        None,
    )
    .unwrap();

    let link_config = DeviceLinkConfig {
        identity_key_alias: key_alias.clone(),
        device_key_alias: Some(KeyAlias::new_unchecked("device-key")),
        device_did: None,
        expires_in: Some(2_592_000),
        note: Some("test device".into()),
        payload: None,
    };

    let link_ctx = build_test_context_with_provider(
        registry_path,
        Arc::new(keychain.clone()),
        Some(
            Arc::new(PrefilledPassphraseProvider::new("Test-passphrase1!"))
                as Arc<dyn PassphraseProvider + Send + Sync>,
        ),
    );
    let link_result = link_device(link_config, &link_ctx, &SystemClock).unwrap();
    link_result.device_did.to_string()
}

#[test]
fn extend_device_updates_expiry() {
    let tmp = tempfile::tempdir().unwrap();
    let registry_path = tmp.path().join(".auths");

    let (key_alias, keychain) = setup_test_identity(&registry_path);
    let device_did = link_test_device(&registry_path, &key_alias, &keychain);

    let ctx = build_test_context_with_provider(
        &registry_path,
        Arc::new(keychain.clone()),
        Some(
            Arc::new(PrefilledPassphraseProvider::new("Test-passphrase1!"))
                as Arc<dyn PassphraseProvider + Send + Sync>,
        ),
    );
    let config = DeviceExtensionConfig {
        repo_path: registry_path,
        device_did: auths_verifier::types::CanonicalDid::new_unchecked(device_did.clone()),
        expires_in: 31_536_000,
        identity_key_alias: key_alias.clone(),
        device_key_alias: Some(KeyAlias::new_unchecked("device-key")),
    };

    let result = extend_device(config, &ctx, &SystemClock).unwrap();

    assert_eq!(result.device_did.to_string(), device_did);
    let now = chrono::Utc::now();
    let diff = result.new_expires_at - now;
    assert!(
        diff.num_days() >= 364,
        "Expected ~365 days, got {}",
        diff.num_days()
    );
}

#[test]
fn extend_device_nonexistent_device_returns_error() {
    let tmp = tempfile::tempdir().unwrap();
    let registry_path = tmp.path().join(".auths");

    let (key_alias, keychain) = setup_test_identity(&registry_path);

    let ctx = build_test_context_with_provider(
        &registry_path,
        Arc::new(keychain.clone()),
        Some(
            Arc::new(PrefilledPassphraseProvider::new("Test-passphrase1!"))
                as Arc<dyn PassphraseProvider + Send + Sync>,
        ),
    );
    let config = DeviceExtensionConfig {
        repo_path: registry_path,
        device_did: auths_verifier::types::CanonicalDid::new_unchecked("did:key:zDoesNotExist"),
        expires_in: 2_592_000,
        identity_key_alias: key_alias,
        device_key_alias: Some(KeyAlias::new_unchecked("device-key")),
    };

    let result = extend_device(config, &ctx, &SystemClock);

    assert!(
        matches!(result, Err(DeviceExtensionError::NoAttestationFound { .. })),
        "Expected NoAttestationFound, got: {:?}",
        result.unwrap_err()
    );
}
