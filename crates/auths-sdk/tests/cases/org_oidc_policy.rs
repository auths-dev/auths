//! KEL-anchored OIDC-subject policy: anchor + resolve, with the org's witnessed
//! log as the policy's source of truth. Policy source lives in a
//! content-addressed blob; only its SHA-256 digest rides the org KEL (an
//! `oidcpolicy:` seal), tamper-evident on load.

use std::sync::Arc;

use auths_core::PrefilledPassphraseProvider;
use auths_core::signing::{PassphraseProvider, StorageSigner};
use auths_core::storage::keychain::KeyAlias;
use auths_core::testing::IsolatedKeychainHandle;
use auths_id::keri::Said;
use auths_sdk::context::AuthsContext;
use auths_sdk::domains::identity::service::initialize;
use auths_sdk::domains::identity::types::{
    CreateDeveloperIdentityConfig, IdentityConfig, InitializeResult,
};
use auths_sdk::domains::org::error::OrgError;
use auths_sdk::domains::org::oidc_policy::{load_org_oidc_policy, set_org_oidc_policy};
use auths_sdk::domains::org::policy::{Expr, load_org_policy, set_org_policy};
use auths_sdk::domains::signing::types::GitSigningScope;
use auths_verifier::Prefix;

use crate::cases::helpers::{build_test_context, build_test_context_with_provider};

const PASS: &str = "Test-passphrase1!";

const GOOD_POLICY: &str = r#"{
  "issuer": "https://token.actions.githubusercontent.com",
  "repository": "acme/widget"
}"#;

const ROTATED_POLICY: &str = r#"{
  "issuer": "https://token.actions.githubusercontent.com",
  "repository": "acme/widget",
  "workflow_ref": "acme/widget/.github/workflows/release.yml"
}"#;

/// `(ctx, org signing alias, org prefix, tmp)` for a fresh org AID.
fn setup() -> (AuthsContext, KeyAlias, Prefix, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let keychain = IsolatedKeychainHandle::new();
    let signer = StorageSigner::new(keychain.clone());
    let provider = PrefilledPassphraseProvider::new(PASS);
    let config = CreateDeveloperIdentityConfig::builder(KeyAlias::new_unchecked("org-key"))
        .with_git_signing_scope(GitSigningScope::Skip)
        .build();
    let boot_ctx = build_test_context(tmp.path(), Arc::new(keychain.clone()));
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
    (ctx, result.key_alias, org_prefix, tmp)
}

#[test]
fn anchor_then_resolve_round_trips_and_latest_wins() {
    let (ctx, org_alias, org_prefix, _tmp) = setup();

    let set1 = set_org_oidc_policy(&ctx, &org_prefix, &org_alias, GOOD_POLICY.as_bytes())
        .expect("anchor policy 1");
    assert_eq!(set1.policy.repository(), "acme/widget");

    let loaded = load_org_oidc_policy(ctx.registry.as_ref(), &org_prefix)
        .expect("load")
        .expect("a policy is anchored");
    assert_eq!(loaded.policy_digest, set1.policy_digest);
    assert_eq!(
        loaded.policy, set1.policy,
        "the resolved policy is the anchored one, parsed"
    );

    // Rotation is a KEL event: re-anchor — the latest seal wins on load.
    let set2 = set_org_oidc_policy(&ctx, &org_prefix, &org_alias, ROTATED_POLICY.as_bytes())
        .expect("anchor policy 2");
    assert_ne!(set1.policy_digest, set2.policy_digest);

    let loaded2 = load_org_oidc_policy(ctx.registry.as_ref(), &org_prefix)
        .expect("load")
        .expect("a policy is anchored");
    assert_eq!(
        loaded2.policy_digest, set2.policy_digest,
        "latest anchored policy wins"
    );
}

#[test]
fn unparseable_policy_is_rejected_at_anchor() {
    let (ctx, org_alias, org_prefix, _tmp) = setup();
    let err = set_org_oidc_policy(&ctx, &org_prefix, &org_alias, b"{ not valid json")
        .expect_err("garbage must not anchor");
    assert!(
        matches!(err, OrgError::OidcPolicyInvalid { .. }),
        "expected OidcPolicyInvalid, got {err:?}"
    );
    // An empty required field is also invalid — parse, don't validate.
    let err = set_org_oidc_policy(
        &ctx,
        &org_prefix,
        &org_alias,
        br#"{"issuer":" ","repository":"acme/widget"}"#,
    )
    .expect_err("empty issuer must not anchor");
    assert!(matches!(err, OrgError::OidcPolicyInvalid { .. }));
    // Nothing anchored — load returns None.
    assert!(
        load_org_oidc_policy(ctx.registry.as_ref(), &org_prefix)
            .expect("load")
            .is_none()
    );
}

#[test]
fn tampered_blob_fails_integrity_on_load() {
    let (ctx, org_alias, org_prefix, _tmp) = setup();
    let set = set_org_oidc_policy(&ctx, &org_prefix, &org_alias, GOOD_POLICY.as_bytes())
        .expect("anchor policy");

    // Overwrite the content-addressed blob with a different (still-valid) policy
    // whose digest no longer matches the sealed value.
    let key = Said::new_unchecked(format!("oidcpolicy-{}", set.policy_digest));
    ctx.registry
        .store_credential(&org_prefix, &key, ROTATED_POLICY.as_bytes())
        .expect("overwrite blob");

    let err = load_org_oidc_policy(ctx.registry.as_ref(), &org_prefix)
        .expect_err("tampered blob must fail closed");
    assert!(
        matches!(err, OrgError::PolicyIntegrity { .. }),
        "expected PolicyIntegrity, got {err:?}"
    );
}

#[test]
fn oidc_policy_seal_does_not_shadow_the_authorization_policy_seal() {
    let (ctx, org_alias, org_prefix, _tmp) = setup();

    // Both policy kinds anchored on the same KEL — each marker resolves its own.
    set_org_policy(
        &ctx,
        &org_prefix,
        &org_alias,
        &serde_json::to_vec(&Expr::NotRevoked).unwrap(),
    )
    .expect("set authorization policy");
    let set = set_org_oidc_policy(&ctx, &org_prefix, &org_alias, GOOD_POLICY.as_bytes())
        .expect("anchor OIDC policy");

    let authz = load_org_policy(&ctx, &org_prefix)
        .expect("load authz")
        .expect("authz policy anchored");
    let oidc = load_org_oidc_policy(ctx.registry.as_ref(), &org_prefix)
        .expect("load oidc")
        .expect("oidc policy anchored");
    assert_ne!(
        authz.policy_hash, oidc.policy_digest,
        "the two seals are distinct documents"
    );
    assert_eq!(oidc.policy_digest, set.policy_digest);
}
