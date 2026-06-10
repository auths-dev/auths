//! Epic E1 D1 — multi-hop delegation chain walker, point-in-time + fail-closed.
//!
//! Builds a real org → human → agent chain and asserts: the chain reconstructs to
//! the root; the leaf→immediate hop is ordered by KEL position; and revoking an
//! intermediate authority rejects the leaf (any upstream revocation fails closed).

use std::sync::Arc;

use auths_core::PrefilledPassphraseProvider;
use auths_core::signing::{PassphraseProvider, StorageSigner};
use auths_core::storage::keychain::KeyAlias;
use auths_core::testing::IsolatedKeychainHandle;
use auths_crypto::CurveType;
use auths_sdk::context::AuthsContext;
use auths_sdk::domains::identity::service::initialize;
use auths_sdk::domains::identity::types::{
    CreateDeveloperIdentityConfig, IdentityConfig, InitializeResult,
};
use auths_sdk::domains::org::audit::AuthorityAtSigning;
use auths_sdk::domains::org::trace::walk_delegation_chain;
use auths_sdk::domains::org::{add_member, revoke_member};
use auths_sdk::domains::signing::types::GitSigningScope;
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

/// Delegate `child_alias` under `delegator_prefix`/`delegator_alias`; return the new
/// child's `(did, prefix, alias)`.
fn delegate(
    ctx: &AuthsContext,
    delegator_prefix: &Prefix,
    delegator_alias: &KeyAlias,
    child_alias: &str,
    role: Role,
) -> (String, Prefix, KeyAlias) {
    let alias = KeyAlias::new_unchecked(child_alias.to_string());
    let member = add_member(
        ctx,
        delegator_prefix,
        delegator_alias,
        &alias,
        CurveType::Ed25519,
        role,
        &[auths_keri::Capability::sign_commit()],
        None,
    )
    .expect("delegate member");
    let prefix = Prefix::new_unchecked(member.member_prefix.clone());
    (member.member_did, prefix, alias)
}

#[test]
fn walks_three_hop_chain_to_root_when_all_live() {
    let (ctx, org_alias, org_prefix, _tmp) = setup();
    let (_human_did, human_prefix, human_alias) =
        delegate(&ctx, &org_prefix, &org_alias, "human-1", Role::Admin);
    let (_agent_did, agent_prefix, _agent_alias) =
        delegate(&ctx, &human_prefix, &human_alias, "agent-1", Role::Member);

    let chain = walk_delegation_chain(&ctx, &agent_prefix, Some(u128::MAX)).expect("walk");
    assert_eq!(chain.depth, 2, "agent → human → org is two hops");
    assert_eq!(chain.root_did, format!("did:keri:{}", org_prefix.as_str()));
    assert_eq!(
        chain.hops[0].delegator_did,
        format!("did:keri:{}", human_prefix.as_str())
    );
    assert_eq!(
        chain.hops[1].delegator_did,
        format!("did:keri:{}", org_prefix.as_str())
    );
    assert!(chain.live_at_signing, "all links live → chain live");
}

#[test]
fn revoking_the_middle_of_the_chain_rejects_the_leaf() {
    let (ctx, org_alias, org_prefix, _tmp) = setup();
    let (human_did, human_prefix, human_alias) =
        delegate(&ctx, &org_prefix, &org_alias, "human-1", Role::Admin);
    let (_agent_did, agent_prefix, _agent_alias) =
        delegate(&ctx, &human_prefix, &human_alias, "agent-1", Role::Member);

    // The org revokes the human (the middle of the chain).
    revoke_member(&ctx, &org_prefix, &org_alias, &human_did, None).expect("revoke human");

    let chain = walk_delegation_chain(&ctx, &agent_prefix, Some(u128::MAX)).expect("walk");
    assert!(
        !chain.live_at_signing,
        "a revoked intermediate authority must reject the leaf (fail-closed upstream)"
    );
    // The agent→human hop is still authorized; the human→org hop is the rejection.
    assert!(matches!(
        chain.hops[1].authority_at_signing,
        AuthorityAtSigning::RejectedRevokedPositionUnknown { .. }
    ));
}

#[test]
fn immediate_hop_is_ordered_by_kel_position() {
    let (ctx, org_alias, org_prefix, _tmp) = setup();
    let (human_did, human_prefix, _human_alias) =
        delegate(&ctx, &org_prefix, &org_alias, "human-1", Role::Admin);

    revoke_member(&ctx, &org_prefix, &org_alias, &human_did, None).expect("revoke human");

    // Signed before any revocation position → authorized (positional).
    let before = walk_delegation_chain(&ctx, &human_prefix, Some(0)).expect("walk");
    assert!(matches!(
        before.hops[0].authority_at_signing,
        AuthorityAtSigning::AuthorizedBeforeRevocation
    ));
    assert!(before.live_at_signing);

    // Signed at/after the revocation position → rejected (positional).
    let after = walk_delegation_chain(&ctx, &human_prefix, Some(u128::MAX)).expect("walk");
    assert!(matches!(
        after.hops[0].authority_at_signing,
        AuthorityAtSigning::RejectedAfterRevocation { .. }
    ));
    assert!(!after.live_at_signing);
}

#[test]
fn root_signer_has_no_hops_and_is_live() {
    let (ctx, _org_alias, org_prefix, _tmp) = setup();
    let chain = walk_delegation_chain(&ctx, &org_prefix, None).expect("walk");
    assert_eq!(chain.depth, 0, "a root identity has no delegators");
    assert_eq!(chain.leaf_did, chain.root_did);
    assert!(
        chain.live_at_signing,
        "a root is self-authorized (no delegation to revoke)"
    );
}
