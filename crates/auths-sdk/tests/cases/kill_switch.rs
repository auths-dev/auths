//! Epic E1 B4 — the org-wide kill switch: an atomic-batch revocation anchors every
//! agent's revocation seal in ONE KEL event (same position), and is idempotent.

use std::ops::ControlFlow;
use std::sync::Arc;

use auths_core::PrefilledPassphraseProvider;
use auths_core::signing::{PassphraseProvider, StorageSigner};
use auths_core::storage::keychain::KeyAlias;
use auths_core::testing::IsolatedKeychainHandle;
use auths_crypto::CurveType;
use auths_id::keri::Event;
use auths_id::keri::types::Prefix;
use auths_sdk::context::AuthsContext;
use auths_sdk::domains::agents::{AgentError, add_scoped, list, revoke_batch};
use auths_sdk::domains::identity::service::initialize;
use auths_sdk::domains::identity::types::{
    CreateDeveloperIdentityConfig, IdentityConfig, InitializeResult,
};
use auths_sdk::domains::org::offboarding::find_revocation_event;
use auths_sdk::domains::signing::types::GitSigningScope;
use auths_verifier::Prefix as VPrefix;

const PASS: &str = "Test-passphrase1!";

fn setup() -> (AuthsContext, KeyAlias, VPrefix, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let keychain = IsolatedKeychainHandle::new();
    let signer = StorageSigner::new(keychain.clone());
    let provider = PrefilledPassphraseProvider::new(PASS);
    let config = CreateDeveloperIdentityConfig::builder(KeyAlias::new_unchecked("org-key"))
        .with_git_signing_scope(GitSigningScope::Skip)
        .build();
    let boot = crate::cases::helpers::build_test_context(tmp.path(), Arc::new(keychain.clone()));
    let result = match initialize(
        IdentityConfig::Developer(config),
        &boot,
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
        Arc::new(keychain),
        Some(arc_provider),
    );
    let org_prefix = VPrefix::new_unchecked(
        ctx.identity_storage
            .load_identity()
            .unwrap()
            .controller_did
            .as_str()
            .strip_prefix("did:keri:")
            .unwrap()
            .to_string(),
    );
    (ctx, result.key_alias, org_prefix, tmp)
}

fn collect_kel(ctx: &AuthsContext, prefix: &Prefix) -> Vec<Event> {
    let mut events = Vec::new();
    let _ = ctx.registry.visit_events(prefix, 0, &mut |e| {
        events.push(e.clone());
        ControlFlow::Continue(())
    });
    events
}

fn add_agent(ctx: &AuthsContext, org_alias: &KeyAlias, label: &str) -> String {
    add_scoped(
        ctx,
        org_alias,
        &KeyAlias::new_unchecked(label.to_string()),
        CurveType::Ed25519,
        &[auths_keri::Capability::sign_commit()],
        None,
    )
    .expect("add agent")
    .agent_did
}

#[test]
fn batch_revoke_kills_all_agents_at_one_kel_position() {
    let (ctx, org_alias, org_prefix, _tmp) = setup();
    let a1 = add_agent(&ctx, &org_alias, "agent-1");
    let a2 = add_agent(&ctx, &org_alias, "agent-2");

    let receipt = revoke_batch(&ctx, &org_alias, &[a1.clone(), a2.clone()]).expect("batch revoke");
    let seq = receipt.anchored_at_seq.expect("a batch event was anchored");

    // Both agents are revoked, and BOTH revocation seals sit at the SAME KEL position
    // — proof they were anchored in one atomic event.
    let kel = collect_kel(
        &ctx,
        &Prefix::new_unchecked(org_prefix.as_str().to_string()),
    );
    let p1 = Prefix::new_unchecked(a1.strip_prefix("did:keri:").unwrap().to_string());
    let p2 = Prefix::new_unchecked(a2.strip_prefix("did:keri:").unwrap().to_string());
    let (_s1, seq1) = find_revocation_event(&kel, &p1).expect("a1 revoked");
    let (_s2, seq2) = find_revocation_event(&kel, &p2).expect("a2 revoked");
    assert_eq!(
        seq1, seq2,
        "both revocations share one KEL event (atomic batch)"
    );
    assert_eq!(seq1, seq, "the receipt reports that single position");

    let revoked_now = list(&ctx)
        .expect("list")
        .into_iter()
        .filter(|a| a.revoked)
        .count();
    assert_eq!(revoked_now, 2, "both agents are revoked");
}

#[test]
fn batch_revoke_is_idempotent() {
    let (ctx, org_alias, _org_prefix, _tmp) = setup();
    let a1 = add_agent(&ctx, &org_alias, "agent-1");

    let first = revoke_batch(&ctx, &org_alias, std::slice::from_ref(&a1)).expect("first revoke");
    assert!(
        first.anchored_at_seq.is_some(),
        "first revoke writes an event"
    );

    // Re-revoking the same (already-revoked) agent writes no new event.
    let second = revoke_batch(&ctx, &org_alias, &[a1]).expect("second revoke");
    assert!(
        second.anchored_at_seq.is_none(),
        "already-revoked batch is a no-op (no new event)"
    );
}

#[test]
fn batch_revoke_empty_list_is_a_clean_noop() {
    let (ctx, org_alias, _org_prefix, _tmp) = setup();

    // The kill switch fired with nothing to kill must be a clean no-op, never an error
    // or a spurious KEL event.
    let receipt = revoke_batch(&ctx, &org_alias, &[]).expect("an empty batch is Ok");
    assert!(
        receipt.anchored_at_seq.is_none(),
        "an empty kill-switch writes no KEL event"
    );
    assert!(receipt.revoked.is_empty(), "nothing is reported revoked");
}

#[test]
fn batch_revoke_seals_only_live_agents_but_reports_the_whole_set() {
    let (ctx, org_alias, _org_prefix, _tmp) = setup();
    let a1 = add_agent(&ctx, &org_alias, "agent-1");
    let a2 = add_agent(&ctx, &org_alias, "agent-2");

    // Kill a1 alone, then fire a batch over BOTH. Only a2 is still live, so a new event
    // is anchored — but the receipt reports the full requested set as revoked, and both
    // end up revoked. (A kill switch must not silently drop an already-dead member.)
    revoke_batch(&ctx, &org_alias, std::slice::from_ref(&a1)).expect("kill a1");
    let receipt = revoke_batch(&ctx, &org_alias, &[a1.clone(), a2.clone()]).expect("kill both");

    assert!(
        receipt.anchored_at_seq.is_some(),
        "a still-live member in the set anchors a new event"
    );
    assert_eq!(
        receipt.revoked,
        vec![a1, a2],
        "the full requested set is reported revoked, not just the live one"
    );
    assert_eq!(
        list(&ctx)
            .expect("list")
            .into_iter()
            .filter(|a| a.revoked)
            .count(),
        2,
        "both agents end revoked"
    );
}

#[test]
fn batch_revoke_rejects_an_unparseable_did() {
    let (ctx, org_alias, _org_prefix, _tmp) = setup();

    // A malformed agent did in the set must abort the batch (fail-closed), not be silently
    // skipped — otherwise a typo could leave a targeted agent alive.
    let err = revoke_batch(&ctx, &org_alias, &["not-a-did:keri".to_string()])
        .expect_err("a malformed agent did must be rejected");
    assert!(
        matches!(err, AgentError::AgentNotFound { ref did } if did == "not-a-did:keri"),
        "expected AgentNotFound, got {err:?}"
    );
}
