//! Epic E1.1 — org-wide authorization policy: KEL-anchored storage + load + the
//! fail-closed gate. Policy source lives in a content-addressed blob; only its
//! BLAKE3 hash rides the org KEL (a `policy:` seal), tamper-evident on load.

use std::sync::Arc;

use auths_core::PrefilledPassphraseProvider;
use auths_core::signing::PassphraseProvider;
use auths_core::storage::keychain::KeyAlias;
use auths_core::testing::IsolatedKeychainHandle;
use auths_crypto::CurveType;
use auths_id::keri::Said;
use auths_id::policy::Outcome;
use auths_sdk::context::AuthsContext;
use auths_sdk::identity::initialize_registry_identity;
use auths_sdk::domains::org::error::OrgError;
use auths_sdk::domains::org::policy::{
    Expr, evaluate_with_org_policy, load_org_policy, set_org_policy,
};
use auths_sdk::domains::org::{add_member, list_members, member_policy_context, revoke_member};
use auths_verifier::Prefix;
use auths_verifier::core::Role;

use crate::cases::helpers::{build_test_context, build_test_context_with_provider};

const PASS: &str = "Test-passphrase1!";

/// `(ctx, org signing alias, org prefix, tmp)` for a fresh org AID.
fn setup() -> (AuthsContext, KeyAlias, Prefix, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let keychain = IsolatedKeychainHandle::new();
    let provider = PrefilledPassphraseProvider::new(PASS);
    let boot_ctx = build_test_context(tmp.path(), Arc::new(keychain.clone()));
    // Bare org root (no delegated device #0) — mirror create_org, whose roster holds only
    // the members it explicitly adds.
    let (_org_did, org_alias) = initialize_registry_identity(
        Arc::clone(&boot_ctx.registry),
        &KeyAlias::new_unchecked("org-key"),
        &provider,
        &keychain,
        None,
        CurveType::default(),
    )
    .expect("init bare org identity");

    let arc_provider: Arc<dyn PassphraseProvider + Send + Sync> =
        Arc::new(PrefilledPassphraseProvider::new(PASS));
    let ctx = build_test_context_with_provider(
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
    (ctx, org_alias, org_prefix, tmp)
}

fn policy_bytes(expr: &Expr) -> Vec<u8> {
    serde_json::to_vec(expr).expect("serialize policy expr")
}

#[test]
fn set_then_load_round_trips_and_latest_wins() {
    let (ctx, org_alias, org_prefix, _tmp) = setup();

    let first = Expr::And(vec![
        Expr::NotRevoked,
        Expr::HasCapability("sign_commit".into()),
    ]);
    let set1 =
        set_org_policy(&ctx, &org_prefix, &org_alias, &policy_bytes(&first)).expect("set policy 1");

    let loaded = load_org_policy(&ctx, &org_prefix)
        .expect("load")
        .expect("a policy is anchored");
    assert_eq!(loaded.policy_hash, set1.policy_hash);
    assert_eq!(
        hex::encode(loaded.compiled.source_hash()),
        set1.policy_hash,
        "loaded blob hashes to the KEL-committed value"
    );

    // Re-set with a different policy — latest anchored wins on load.
    let second = Expr::NotRevoked;
    let set2 = set_org_policy(&ctx, &org_prefix, &org_alias, &policy_bytes(&second))
        .expect("set policy 2");
    assert_ne!(set1.policy_hash, set2.policy_hash);

    let loaded2 = load_org_policy(&ctx, &org_prefix)
        .expect("load")
        .expect("a policy is anchored");
    assert_eq!(loaded2.policy_hash, set2.policy_hash, "latest policy wins");
}

#[test]
fn unparseable_policy_is_rejected_at_set() {
    let (ctx, org_alias, org_prefix, _tmp) = setup();
    let err = set_org_policy(&ctx, &org_prefix, &org_alias, b"{ not valid json")
        .expect_err("garbage must not compile");
    assert!(
        matches!(err, OrgError::PolicyCompile { .. }),
        "expected PolicyCompile, got {err:?}"
    );
    // Nothing anchored — load returns None.
    assert!(load_org_policy(&ctx, &org_prefix).expect("load").is_none());
}

#[test]
fn tampered_blob_fails_integrity_on_load() {
    let (ctx, org_alias, org_prefix, _tmp) = setup();
    let set = set_org_policy(
        &ctx,
        &org_prefix,
        &org_alias,
        &policy_bytes(&Expr::NotRevoked),
    )
    .expect("set policy");

    // Overwrite the content-addressed blob with a different (still-valid) policy whose
    // hash no longer matches the committed seal.
    let key = Said::new_unchecked(format!("policy-{}", set.policy_hash));
    ctx.registry
        .store_credential(&org_prefix, &key, &policy_bytes(&Expr::True))
        .expect("overwrite blob");

    let err = load_org_policy(&ctx, &org_prefix).expect_err("tampered blob must fail closed");
    assert!(
        matches!(err, OrgError::PolicyIntegrity { .. }),
        "expected PolicyIntegrity, got {err:?}"
    );
}

#[test]
fn policy_seal_does_not_collide_with_member_or_revocation_seals() {
    let (ctx, org_alias, org_prefix, _tmp) = setup();

    // Anchor a policy, then a member, then revoke — all three write `Seal::Digest`s.
    set_org_policy(
        &ctx,
        &org_prefix,
        &org_alias,
        &policy_bytes(&Expr::NotRevoked),
    )
    .expect("set policy");

    let member = add_member(
        &ctx,
        &org_prefix,
        &org_alias,
        &KeyAlias::new_unchecked("member-1"),
        CurveType::Ed25519,
        Role::Member,
        &[auths_keri::Capability::sign_commit()],
        None,
    )
    .expect("add member");

    // The policy seal is not read as a member: exactly one member is listed.
    let members = list_members(&ctx, &org_prefix).expect("list members");
    assert_eq!(members.len(), 1, "policy seal must not appear as a member");
    assert_eq!(members[0].member_did, member.member_did);
    assert!(!members[0].revoked);
    // The member's scope is intact (the policy seal didn't shadow the scope read).
    assert_eq!(
        members[0].capabilities,
        vec![auths_keri::Capability::sign_commit()]
    );

    // Re-anchoring a policy after a revocation must not be read as a revocation.
    let member_prefix = Prefix::new_unchecked(
        member
            .member_did
            .strip_prefix("did:keri:")
            .unwrap()
            .to_string(),
    );
    revoke_member(&ctx, &org_prefix, &org_alias, &member.member_did, None).expect("revoke");
    set_org_policy(&ctx, &org_prefix, &org_alias, &policy_bytes(&Expr::True))
        .expect("re-set policy after revoke");

    let after = list_members(&ctx, &org_prefix).expect("list members");
    assert_eq!(
        after.len(),
        1,
        "still exactly one member after policy re-set"
    );
    assert!(
        after[0].revoked,
        "the member stays revoked; the policy seal is not confused for a member or un-revocation"
    );
    // And the policy still loads (its own seal is unaffected by member/revocation seals).
    assert!(load_org_policy(&ctx, &org_prefix).expect("load").is_some());
    let _ = member_prefix;
}

#[test]
fn gate_allows_live_member_and_denies_revoked_with_hash_pinned() {
    let (ctx, org_alias, org_prefix, _tmp) = setup();

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
    let policy = load_org_policy(&ctx, &org_prefix)
        .expect("load")
        .expect("anchored");

    let member = add_member(
        &ctx,
        &org_prefix,
        &org_alias,
        &KeyAlias::new_unchecked("member-1"),
        CurveType::Ed25519,
        Role::Member,
        &[auths_keri::Capability::sign_commit()],
        None,
    )
    .expect("add member");
    let member_prefix = Prefix::new_unchecked(
        member
            .member_did
            .strip_prefix("did:keri:")
            .unwrap()
            .to_string(),
    );

    // Live member with the required capability → Allow, with the policy hash pinned.
    #[allow(clippy::disallowed_methods)]
    let now = chrono::Utc::now();
    let live_ctx = member_policy_context(&ctx, &org_prefix, &member_prefix, now).expect("ctx");
    let allow = evaluate_with_org_policy(&policy, &live_ctx);
    assert_eq!(allow.outcome, Outcome::Allow, "got {allow:?}");
    assert_eq!(
        allow.policy_hash.map(hex::encode),
        Some(policy.policy_hash.clone()),
        "the decision pins the policy hash for audit"
    );

    // Revoke → the KEL-authoritative context is revoked → NotRevoked denies.
    revoke_member(&ctx, &org_prefix, &org_alias, &member.member_did, None).expect("revoke");
    let revoked_ctx = member_policy_context(&ctx, &org_prefix, &member_prefix, now).expect("ctx");
    let deny = evaluate_with_org_policy(&policy, &revoked_ctx);
    assert_eq!(deny.outcome, Outcome::Deny, "revoked member must be denied");
}
