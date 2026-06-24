//! Epic E.3 — agent as a KERI `dip`-delegated identifier (SDK `agents::add`).

use std::ops::ControlFlow;
use std::sync::Arc;

use auths_core::PrefilledPassphraseProvider;
use auths_core::signing::{PassphraseProvider, StorageSigner};
use auths_core::storage::keychain::{KeyAlias, extract_public_key_bytes};
use auths_core::testing::IsolatedKeychainHandle;
use auths_crypto::CurveType;
use auths_id::keri::Event;
use auths_id::keri::delegation::mark_agent_scope;
use auths_id::keri::types::Prefix;
use auths_id::keri::validate_delegation;
use auths_id::storage::registry::backend::RegistryBackend;
use auths_keri::{AgentScope, Capability};
use auths_sdk::context::AuthsContext;
use auths_sdk::domains::agents::{AgentError, add, add_scoped, list, revoke, rotate};
use auths_sdk::domains::device::{add_device, list_delegated_devices, remove_device};
use auths_sdk::domains::identity::service::initialize;
use auths_sdk::domains::identity::types::{
    CreateDeveloperIdentityConfig, IdentityConfig, InitializeResult,
};
use auths_sdk::domains::signing::types::GitSigningScope;

use crate::cases::helpers::{build_test_context, build_test_context_with_provider};

const PASS: &str = "Test-passphrase1!";

fn setup_test_identity(registry_path: &std::path::Path) -> (KeyAlias, IsolatedKeychainHandle) {
    let keychain = IsolatedKeychainHandle::new();
    let signer = StorageSigner::new(keychain.clone());
    let provider = PrefilledPassphraseProvider::new(PASS);
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

/// (ctx, root signing alias, root prefix) for a fresh delegating identity.
fn setup() -> (AuthsContext, KeyAlias, Prefix, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let (root_alias, keychain) = setup_test_identity(tmp.path());
    let provider: Arc<dyn PassphraseProvider + Send + Sync> =
        Arc::new(PrefilledPassphraseProvider::new(PASS));
    let ctx =
        build_test_context_with_provider(tmp.path(), Arc::new(keychain.clone()), Some(provider));
    let managed = ctx.identity_storage.load_identity().expect("root identity");
    let root_prefix = Prefix::new_unchecked(
        managed
            .controller_did
            .as_str()
            .strip_prefix("did:keri:")
            .unwrap()
            .to_string(),
    );
    (ctx, root_alias, root_prefix, tmp)
}

fn collect_kel(backend: &(dyn RegistryBackend + Send + Sync), prefix: &Prefix) -> Vec<Event> {
    let mut events = Vec::new();
    backend
        .visit_events(prefix, 0, &mut |e| {
            events.push(e.clone());
            ControlFlow::Continue(())
        })
        .expect("walk KEL");
    events
}

#[test]
fn agents_add_returns_anchored_dip() {
    let (ctx, root_alias, root_prefix, _tmp) = setup();
    let agent_alias = KeyAlias::new_unchecked("deploy-bot");

    let agent = add(&ctx, &root_alias, &agent_alias, CurveType::Ed25519).expect("delegate agent");
    assert!(agent.agent_did.starts_with("did:keri:"));

    // The root anchored the agent's dip → validate_delegation confirms it bilaterally.
    let agent_prefix = Prefix::new_unchecked(agent.agent_prefix.clone());
    let dip = ctx
        .registry
        .get_event(&agent_prefix, 0)
        .expect("agent dip stored");
    let root_kel = collect_kel(ctx.registry.as_ref(), &root_prefix);
    validate_delegation(&dip, &root_kel).expect("root anchored the agent bilaterally");
}

#[test]
fn agent_did_derives_from_dip_said() {
    let (ctx, root_alias, _root_prefix, _tmp) = setup();
    let agent_alias = KeyAlias::new_unchecked("derive-bot");

    let agent = add(&ctx, &root_alias, &agent_alias, CurveType::Ed25519).expect("delegate agent");
    let agent_prefix = Prefix::new_unchecked(agent.agent_prefix.clone());
    let dip = ctx
        .registry
        .get_event(&agent_prefix, 0)
        .expect("agent dip stored");

    // A dip is self-addressing: prefix == SAID, and the did:keri wraps that prefix.
    assert_eq!(agent.agent_prefix, dip.said().as_str());
    assert_eq!(agent.agent_did, format!("did:keri:{}", dip.said()));
}

#[test]
fn agents_add_rejects_duplicate_key() {
    let (ctx, root_alias, _root_prefix, _tmp) = setup();
    let agent_alias = KeyAlias::new_unchecked("dup-bot");

    add(&ctx, &root_alias, &agent_alias, CurveType::Ed25519).expect("first delegation");
    let err = add(&ctx, &root_alias, &agent_alias, CurveType::Ed25519)
        .expect_err("re-delegating an existing alias must be rejected");
    assert!(
        matches!(err, AgentError::AlreadyDelegated { .. }),
        "expected AlreadyDelegated, got {err:?}"
    );
}

#[test]
fn agents_rotate_advances_kel() {
    let (ctx, root_alias, _root, _tmp) = setup();
    let agent_alias = KeyAlias::new_unchecked("rot-bot");
    let agent = add(&ctx, &root_alias, &agent_alias, CurveType::Ed25519).expect("delegate agent");
    let agent_prefix = Prefix::new_unchecked(agent.agent_prefix.clone());

    rotate(&ctx, &root_alias, &agent.agent_did).expect("rotate agent");

    let drt = ctx
        .registry
        .get_event(&agent_prefix, 1)
        .expect("drt at sequence 1");
    assert!(matches!(drt, Event::Drt(_)), "rotation authors a drt");
    assert_eq!(drt.sequence().value(), 1);
}

#[test]
fn old_key_stops_verifying_after_rotate() {
    let (ctx, root_alias, _root, _tmp) = setup();
    let agent_alias = KeyAlias::new_unchecked("oldkey-bot");
    let agent = add(&ctx, &root_alias, &agent_alias, CurveType::Ed25519).expect("delegate agent");
    let agent_prefix = Prefix::new_unchecked(agent.agent_prefix.clone());

    let dip = ctx.registry.get_event(&agent_prefix, 0).expect("dip");
    let old_key = dip.keys().expect("dip keys")[0].clone();

    rotate(&ctx, &root_alias, &agent.agent_did).expect("rotate agent");

    let drt = ctx.registry.get_event(&agent_prefix, 1).expect("drt");
    let new_key = drt.keys().expect("drt keys")[0].clone();
    assert_ne!(
        old_key, new_key,
        "rotation must replace the agent's current key (the old key no longer verifies)"
    );
}

#[test]
fn rotate_revoked_agent_rejected() {
    let (ctx, root_alias, _root, _tmp) = setup();
    let agent_alias = KeyAlias::new_unchecked("rev-bot");
    let agent = add(&ctx, &root_alias, &agent_alias, CurveType::Ed25519).expect("delegate agent");

    // Revoke via the shared delegation engine (revoking a delegated AID is curve-
    // and role-agnostic — agents and devices share it).
    remove_device(&ctx, &root_alias, &agent.agent_did).expect("revoke agent");

    let err =
        rotate(&ctx, &root_alias, &agent.agent_did).expect_err("a revoked agent must not rotate");
    assert!(
        matches!(err, AgentError::Revoked { .. }),
        "expected Revoked, got {err:?}"
    );
}

#[test]
fn drt_chain_validates_after_rotate() {
    let (ctx, root_alias, root_prefix, _tmp) = setup();
    let agent_alias = KeyAlias::new_unchecked("chain-bot");
    let agent = add(&ctx, &root_alias, &agent_alias, CurveType::Ed25519).expect("delegate agent");
    let agent_prefix = Prefix::new_unchecked(agent.agent_prefix.clone());

    rotate(&ctx, &root_alias, &agent.agent_did).expect("rotate agent");

    let dip = ctx.registry.get_event(&agent_prefix, 0).expect("dip");
    let drt = ctx.registry.get_event(&agent_prefix, 1).expect("drt");
    // The drt chains onto the dip, and is bilaterally anchored by the delegator.
    assert_eq!(
        drt.previous().expect("drt has prior").as_str(),
        dip.said().as_str()
    );
    let root_kel = collect_kel(ctx.registry.as_ref(), &root_prefix);
    validate_delegation(&dip, &root_kel).expect("dip bilateral binding holds");
    validate_delegation(&drt, &root_kel)
        .expect("drt bilateral binding holds against the delegator");
}

#[test]
fn agents_revoke_marks_revoked() {
    let (ctx, root_alias, _root, _tmp) = setup();
    let agent = add(
        &ctx,
        &root_alias,
        &KeyAlias::new_unchecked("revoke-bot"),
        CurveType::Ed25519,
    )
    .expect("delegate agent");

    revoke(&ctx, &root_alias, &agent.agent_did).expect("revoke agent");

    let agents = list(&ctx).expect("list agents");
    let entry = agents
        .iter()
        .find(|a| a.agent_did == agent.agent_did)
        .expect("agent still in the full set");
    assert!(entry.revoked, "revoked agent must be flagged revoked");
}

#[test]
fn revoked_agent_excluded_from_list() {
    let (ctx, root_alias, _root, _tmp) = setup();
    let agent = add(
        &ctx,
        &root_alias,
        &KeyAlias::new_unchecked("excluded-bot"),
        CurveType::Ed25519,
    )
    .expect("delegate agent");

    revoke(&ctx, &root_alias, &agent.agent_did).expect("revoke agent");

    // The live set (non-revoked) excludes it.
    let live = list(&ctx)
        .expect("list agents")
        .into_iter()
        .filter(|a| !a.revoked)
        .count();
    assert_eq!(live, 0, "revoked agent must drop out of the live set");
}

#[test]
fn agent_list_excludes_devices() {
    let (ctx, root_alias, _root, _tmp) = setup();
    let agent = add(
        &ctx,
        &root_alias,
        &KeyAlias::new_unchecked("only-agent"),
        CurveType::Ed25519,
    )
    .expect("delegate agent");
    let device = add_device(
        &ctx,
        &root_alias,
        &KeyAlias::new_unchecked("only-device"),
        CurveType::Ed25519,
    )
    .expect("delegate device");

    // `agent list` shows the agent, never the device.
    let agents = list(&ctx).expect("list agents");
    assert_eq!(agents.len(), 1, "exactly one agent");
    assert_eq!(agents[0].agent_did, agent.agent_did);

    // `device list` shows the device, never the agent.
    let devices = list_delegated_devices(&ctx).expect("list devices");
    assert_eq!(devices.len(), 1, "exactly one device");
    assert_eq!(devices[0].device_did, device.device_did);
}

#[test]
fn revoke_already_revoked_idempotent() {
    let (ctx, root_alias, _root, _tmp) = setup();
    let agent = add(
        &ctx,
        &root_alias,
        &KeyAlias::new_unchecked("idem-bot"),
        CurveType::Ed25519,
    )
    .expect("delegate agent");

    revoke(&ctx, &root_alias, &agent.agent_did).expect("first revoke");
    revoke(&ctx, &root_alias, &agent.agent_did).expect("re-revoking is idempotent (Ok)");
}

#[test]
fn scope_cannot_exceed_delegator() {
    let (ctx, root_alias, root_prefix, _tmp) = setup();

    // Give the delegator (root) a scope of [read, write] (using its actual curve).
    let (_pk, root_curve) = extract_public_key_bytes(
        ctx.key_storage.as_ref(),
        &root_alias,
        ctx.passphrase_provider.as_ref(),
    )
    .expect("root curve");
    mark_agent_scope(
        ctx.registry.as_ref(),
        &root_prefix,
        &root_alias,
        root_curve,
        &root_prefix,
        &AgentScope {
            capabilities: vec![
                Capability::parse("read").unwrap(),
                Capability::parse("write").unwrap(),
            ],
            expires_at: None,
        },
        ctx.passphrase_provider.as_ref(),
        ctx.key_storage.as_ref(),
    )
    .expect("anchor delegator scope");

    // Delegating an agent with [read, admin] must be rejected — admin exceeds the
    // delegator's own scope (a delegate can only narrow, never widen).
    let err = add_scoped(
        &ctx,
        &root_alias,
        &KeyAlias::new_unchecked("scoped-bot"),
        CurveType::Ed25519,
        &[
            auths_keri::Capability::parse("read").unwrap(),
            auths_keri::Capability::parse("admin").unwrap(),
        ],
        None,
    )
    .expect_err("scope exceeding the delegator must be rejected");
    assert!(
        matches!(err, AgentError::OutsideDelegatorScope { ref capability } if capability == "admin"),
        "got {err:?}"
    );
}

#[test]
fn scoped_agent_may_narrow_the_delegator_scope() {
    let (ctx, root_alias, root_prefix, _tmp) = setup();

    // Give the delegator [read, write], so the subset check actually runs (not the
    // unconstrained-root path).
    let (_pk, root_curve) = extract_public_key_bytes(
        ctx.key_storage.as_ref(),
        &root_alias,
        ctx.passphrase_provider.as_ref(),
    )
    .expect("root curve");
    mark_agent_scope(
        ctx.registry.as_ref(),
        &root_prefix,
        &root_alias,
        root_curve,
        &root_prefix,
        &AgentScope {
            capabilities: vec![
                Capability::parse("read").unwrap(),
                Capability::parse("write").unwrap(),
            ],
            expires_at: None,
        },
        ctx.passphrase_provider.as_ref(),
        ctx.key_storage.as_ref(),
    )
    .expect("anchor delegator scope");

    // Delegating [read] — a strict subset of [read, write] — must be allowed. The subset
    // rule narrows; it must not reject a legitimate narrowing (a false-reject would be a
    // usability regression and push callers toward over-broad grants).
    let agent = add_scoped(
        &ctx,
        &root_alias,
        &KeyAlias::new_unchecked("narrowed-bot"),
        CurveType::Ed25519,
        &[Capability::parse("read").unwrap()],
        None,
    )
    .expect("narrowing the delegator's scope to a subset must be allowed");
    assert!(agent.agent_did.starts_with("did:keri:"));
}

#[test]
fn scoped_agent_with_empty_scope_is_allowed() {
    let (ctx, root_alias, _root_prefix, _tmp) = setup();

    // An empty scope is a subset of any delegator scope — a capability-less, anchor-only
    // agent (e.g. an identity placeholder) is valid, not an error.
    let agent = add_scoped(
        &ctx,
        &root_alias,
        &KeyAlias::new_unchecked("no-scope-bot"),
        CurveType::Ed25519,
        &[],
        None,
    )
    .expect("an empty scope is a valid (capability-less) delegation");
    assert!(agent.agent_did.starts_with("did:keri:"));
}
