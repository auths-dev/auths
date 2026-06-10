//! Epic E1.3 — org policy enforced on the commit verify path. Exercises the policy
//! layer (`evaluate_commit_policy`) directly: caps + signer-type gating against a
//! verified signer's grant, and the no-policy (legacy allow) path. The cryptographic
//! verdict is covered separately; this validates the policy decision the commit path
//! layers on a `Valid` verdict.

use std::sync::Arc;

use auths_core::PrefilledPassphraseProvider;
use auths_core::signing::{PassphraseProvider, StorageSigner};
use auths_core::storage::keychain::KeyAlias;
use auths_core::testing::IsolatedKeychainHandle;
use auths_crypto::CurveType;
use auths_id::policy::Outcome;
use auths_sdk::context::AuthsContext;
use auths_sdk::domains::agents::add_scoped;
use auths_sdk::domains::identity::service::initialize;
use auths_sdk::domains::identity::types::{
    CreateDeveloperIdentityConfig, IdentityConfig, InitializeResult,
};
use auths_sdk::domains::org::add_member;
use auths_sdk::domains::org::policy::{Expr, set_org_policy};
use auths_sdk::domains::signing::types::GitSigningScope;
use auths_sdk::workflows::commit_trust::{PolicyOutcome, evaluate_commit_policy};
use auths_verifier::Prefix;
use auths_verifier::core::Role;

const PASS: &str = "Test-passphrase1!";

fn setup() -> (AuthsContext, KeyAlias, Prefix, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let keychain = IsolatedKeychainHandle::new();
    let signer = StorageSigner::new(keychain.clone());
    let provider = PrefilledPassphraseProvider::new(PASS);
    let config = CreateDeveloperIdentityConfig::builder(KeyAlias::new_unchecked("org-key"))
        .with_git_signing_scope(GitSigningScope::Skip)
        .build();
    let boot_ctx =
        crate::cases::helpers::build_test_context(tmp.path(), Arc::new(keychain.clone()));
    let result = match initialize(
        IdentityConfig::Developer(config),
        &boot_ctx,
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
    let arc_provider: Arc<dyn PassphraseProvider + Send + Sync> =
        Arc::new(PrefilledPassphraseProvider::new(PASS));
    let ctx = crate::cases::helpers::build_test_context_with_provider(
        tmp.path(),
        Arc::new(keychain.clone()),
        Some(arc_provider),
    );
    let managed = ctx.identity_storage.load_identity().expect("org identity");
    let org_prefix = Prefix::new_unchecked(
        managed
            .controller_did
            .as_str()
            .strip_prefix("did:keri:")
            .unwrap()
            .to_string(),
    );
    (ctx, result.key_alias, org_prefix, tmp)
}

fn policy_bytes(expr: &Expr) -> Vec<u8> {
    serde_json::to_vec(expr).unwrap()
}

fn root_did(prefix: &Prefix) -> String {
    format!("did:keri:{}", prefix.as_str())
}

fn evaluated(outcome: PolicyOutcome) -> Outcome {
    match outcome {
        PolicyOutcome::Evaluated(d) => d.outcome,
        other => panic!("expected an evaluated policy decision, got {other:?}"),
    }
}

#[test]
fn no_policy_is_legacy_allow() {
    let (ctx, org_alias, org_prefix, _tmp) = setup();
    let agent = add_scoped(
        &ctx,
        &org_alias,
        &KeyAlias::new_unchecked("agent-1"),
        CurveType::Ed25519,
        &[auths_keri::Capability::sign_commit()],
        None,
    )
    .expect("add agent");

    // No policy anchored → NoPolicy (pre-policy behavior preserved).
    let now = chrono::Utc::now();
    let outcome = evaluate_commit_policy(&ctx, &root_did(&org_prefix), &agent.agent_did, now)
        .expect("evaluate");
    assert!(matches!(outcome, PolicyOutcome::NoPolicy));
}

#[test]
fn capability_policy_gates_the_signer_grant() {
    let (ctx, org_alias, org_prefix, _tmp) = setup();
    let agent = add_scoped(
        &ctx,
        &org_alias,
        &KeyAlias::new_unchecked("agent-1"),
        CurveType::Ed25519,
        &[auths_keri::Capability::sign_commit()],
        None,
    )
    .expect("add agent");
    let now = chrono::Utc::now();

    // Grant includes sign_commit → Allow.
    set_org_policy(
        &ctx,
        &org_prefix,
        &org_alias,
        &policy_bytes(&Expr::And(vec![
            Expr::NotRevoked,
            Expr::HasCapability("sign_commit".into()),
        ])),
    )
    .expect("set policy");
    assert_eq!(
        evaluated(
            evaluate_commit_policy(&ctx, &root_did(&org_prefix), &agent.agent_did, now).unwrap()
        ),
        Outcome::Allow
    );

    // Grant lacks deploy → Deny.
    set_org_policy(
        &ctx,
        &org_prefix,
        &org_alias,
        &policy_bytes(&Expr::HasCapability("deploy".into())),
    )
    .expect("set policy");
    assert_eq!(
        evaluated(
            evaluate_commit_policy(&ctx, &root_did(&org_prefix), &agent.agent_did, now).unwrap()
        ),
        Outcome::Deny
    );
}

#[test]
fn signer_type_distinguishes_agent_from_human() {
    let (ctx, org_alias, org_prefix, _tmp) = setup();
    let agent = add_scoped(
        &ctx,
        &org_alias,
        &KeyAlias::new_unchecked("agent-1"),
        CurveType::Ed25519,
        &[auths_keri::Capability::sign_commit()],
        None,
    )
    .expect("add agent");
    let human = add_member(
        &ctx,
        &org_prefix,
        &org_alias,
        &KeyAlias::new_unchecked("human-1"),
        CurveType::Ed25519,
        Role::Member,
        &[auths_keri::Capability::sign_commit()],
        None,
    )
    .expect("add member");
    let now = chrono::Utc::now();

    // "Only agents" — the agent is allowed, the human (a device) is denied.
    set_org_policy(&ctx, &org_prefix, &org_alias, &policy_bytes(&Expr::IsAgent))
        .expect("set policy");
    let r = root_did(&org_prefix);
    assert_eq!(
        evaluated(evaluate_commit_policy(&ctx, &r, &agent.agent_did, now).unwrap()),
        Outcome::Allow,
        "agent satisfies IsAgent"
    );
    assert_eq!(
        evaluated(evaluate_commit_policy(&ctx, &r, &human.member_did, now).unwrap()),
        Outcome::Deny,
        "human does not satisfy IsAgent"
    );

    // "Only humans" — flips.
    set_org_policy(&ctx, &org_prefix, &org_alias, &policy_bytes(&Expr::IsHuman))
        .expect("set policy");
    assert_eq!(
        evaluated(evaluate_commit_policy(&ctx, &r, &human.member_did, now).unwrap()),
        Outcome::Allow,
        "human satisfies IsHuman"
    );
    assert_eq!(
        evaluated(evaluate_commit_policy(&ctx, &r, &agent.agent_did, now).unwrap()),
        Outcome::Deny,
        "agent does not satisfy IsHuman"
    );
}

#[test]
fn unknown_signer_fails_closed_under_capability_policy() {
    let (ctx, org_alias, org_prefix, _tmp) = setup();
    set_org_policy(
        &ctx,
        &org_prefix,
        &org_alias,
        &policy_bytes(&Expr::HasCapability("sign_commit".into())),
    )
    .expect("set policy");

    // A signer the root never delegated has no grant → empty caps → Deny.
    let now = chrono::Utc::now();
    let bogus = "did:keri:Eunknownsigner000000000000000000000000000000";
    assert_eq!(
        evaluated(evaluate_commit_policy(&ctx, &root_did(&org_prefix), bogus, now).unwrap()),
        Outcome::Deny
    );
}
