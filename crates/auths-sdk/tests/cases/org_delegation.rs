//! Epic E.8 — KERI-native org membership: a member as a `dip` delegated by the
//! org AID, with KEL-authoritative, fail-closed authority reads.

use std::ops::ControlFlow;
use std::sync::Arc;

use auths_core::PrefilledPassphraseProvider;
use auths_core::ports::clock::SystemClock;
use auths_core::signing::{PassphraseProvider, StorageSigner};
use auths_core::storage::keychain::KeyAlias;
use auths_core::testing::IsolatedKeychainHandle;
use auths_crypto::CurveType;
use auths_id::keri::types::Prefix;
use auths_id::keri::validate_delegation;
use auths_id::keri::{CesrKey, Event, IcpEvent, KeriSequence, Said, Threshold, VersionString};
use auths_id::policy::{Outcome, PolicyBuilder, evaluate_strict};
use auths_id::ports::registry::RegistryBackend;
use auths_id::testing::fakes::{
    FakeAttestationSink, FakeAttestationSource, FakeIdentityStorage, FakeRegistryBackend,
};
use auths_sdk::context::AuthsContext;
use auths_sdk::domains::identity::service::initialize;
use auths_sdk::domains::identity::types::{
    CreateDeveloperIdentityConfig, IdentityConfig, InitializeResult,
};
use auths_sdk::domains::org::error::OrgError;
use auths_sdk::domains::org::{
    add_member, list_members, member_policy_context, resolve_member_authority, revoke_member,
};
use auths_sdk::domains::signing::types::GitSigningScope;
use auths_verifier::AttestationBuilder;
use auths_verifier::core::{Ed25519PublicKey, Role};
use auths_verifier::types::CanonicalDid;

use crate::cases::helpers::{build_test_context, build_test_context_with_provider};

const PASS: &str = "Test-passphrase1!";

/// Initialize a developer identity to act as the **org** AID (the delegator).
fn setup_org_identity(registry_path: &std::path::Path) -> (KeyAlias, IsolatedKeychainHandle) {
    let keychain = IsolatedKeychainHandle::new();
    let signer = StorageSigner::new(keychain.clone());
    let provider = PrefilledPassphraseProvider::new(PASS);
    let config = CreateDeveloperIdentityConfig::builder(KeyAlias::new_unchecked("org-key"))
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

/// `(ctx, org signing alias, org prefix, tmp)` for a fresh org AID delegator.
fn setup() -> (AuthsContext, KeyAlias, Prefix, tempfile::TempDir) {
    let tmp = tempfile::tempdir().unwrap();
    let (org_alias, keychain) = setup_org_identity(tmp.path());
    let provider: Arc<dyn PassphraseProvider + Send + Sync> =
        Arc::new(PrefilledPassphraseProvider::new(PASS));
    let ctx =
        build_test_context_with_provider(tmp.path(), Arc::new(keychain.clone()), Some(provider));
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
fn org_member_is_dip_delegated_by_org() {
    let (ctx, org_alias, org_prefix, _tmp) = setup();
    let member_alias = KeyAlias::new_unchecked("alice");

    let member = add_member(
        &ctx,
        &org_prefix,
        &org_alias,
        &member_alias,
        CurveType::Ed25519,
        Role::Member,
        &["sign_commit".to_string()],
        None,
    )
    .expect("delegate org member");

    assert!(member.member_did.starts_with("did:keri:"));

    // The member's KEL begins with a `dip`; the org anchored it, so
    // validate_delegation confirms the bilateral binding against the org KEL.
    let member_prefix = Prefix::new_unchecked(member.member_prefix.clone());
    let dip = ctx
        .registry
        .get_event(&member_prefix, 0)
        .expect("member dip stored");
    assert!(matches!(dip, Event::Dip(_)), "member is incepted via dip");

    let org_kel = collect_kel(ctx.registry.as_ref(), &org_prefix);
    validate_delegation(&dip, &org_kel).expect("org anchored the member bilaterally");

    // KEL-authoritative authority resolves with the member's role + capabilities.
    let authority = resolve_member_authority(&ctx, &org_prefix, &member_prefix)
        .expect("resolve authority")
        .expect("member is delegated by the org");
    assert!(!authority.revoked);
    assert_eq!(authority.role, Some(Role::Member));
    assert_eq!(authority.capabilities, vec!["sign_commit".to_string()]);
    assert_eq!(
        authority.delegated_by_org,
        format!("did:keri:{}", org_prefix.as_str())
    );
}

#[test]
fn revoked_org_member_unauthorized_despite_stale_attestation() {
    let (ctx, org_alias, org_prefix, _tmp) = setup();
    let member_alias = KeyAlias::new_unchecked("bob");

    let member = add_member(
        &ctx,
        &org_prefix,
        &org_alias,
        &member_alias,
        CurveType::Ed25519,
        Role::Member,
        &["sign_commit".to_string()],
        None,
    )
    .expect("delegate org member");
    let member_prefix = Prefix::new_unchecked(member.member_prefix.clone());

    // Plant a stale, *non-revoked* org-member attestation for this member — a naive
    // attestation reader would treat it as authorized.
    let org_did = format!("did:keri:{}", org_prefix.as_str());
    let stale = AttestationBuilder::default()
        .rid("stale-rid")
        .issuer(org_did.as_str())
        .subject(member.member_did.as_str())
        .device_public_key(Ed25519PublicKey::from_bytes([7u8; 32]))
        .delegated_by(Some(CanonicalDid::new_unchecked(org_did.clone())))
        .build();
    ctx.registry
        .store_org_member(org_prefix.as_str(), &stale)
        .expect("store stale attestation");
    assert!(!stale.is_revoked(), "the stale attestation claims validity");

    // The org revokes the member on its KEL.
    revoke_member(&ctx, &org_prefix, &org_alias, &member.member_did).expect("revoke member");

    // Fail-closed: the KEL is authoritative, so the member reads as revoked even
    // though the stale attestation is still present and claims validity.
    let authority = resolve_member_authority(&ctx, &org_prefix, &member_prefix)
        .expect("resolve authority")
        .expect("member still appears in the delegation set");
    assert!(
        authority.revoked,
        "KEL revocation must win over a stale non-revoked attestation"
    );

    // And the stale attestation really is still readable from the registry.
    let mut found_stale = false;
    ctx.registry
        .visit_org_member_attestations(org_prefix.as_str(), &mut |entry| {
            if entry.did.as_str() == member.member_did
                && let Ok(att) = &entry.attestation
                && !att.is_revoked()
            {
                found_stale = true;
            }
            ControlFlow::Continue(())
        })
        .expect("visit org members");
    assert!(
        found_stale,
        "the stale non-revoked attestation is present yet ignored by the KEL-authoritative read"
    );
}

#[test]
fn org_kt2_delegation_rejected_typed() {
    // A `kt≥2` (multi-signature) org cannot single-author its anchoring ixn.
    let backend = Arc::new(FakeRegistryBackend::new());
    let org_prefix =
        Prefix::new_unchecked("EKt2Org000000000000000000000000000000000000".to_string());

    let icp = IcpEvent {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: org_prefix.clone(),
        s: KeriSequence::new(0),
        kt: Threshold::Simple(2),
        k: vec![
            CesrKey::new_unchecked("DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()),
            CesrKey::new_unchecked("DBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string()),
        ],
        nt: Threshold::Simple(2),
        n: vec![
            Said::new_unchecked("EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()),
            Said::new_unchecked("EBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string()),
        ],
        bt: Threshold::Simple(0),
        b: vec![],
        c: vec![],
        a: vec![],
    };
    backend
        .append_event(&org_prefix, &Event::Icp(icp))
        .expect("seed kt=2 org KEL");

    let ctx = AuthsContext::builder()
        .registry(backend)
        .key_storage(Arc::new(IsolatedKeychainHandle::new()))
        .clock(Arc::new(SystemClock))
        .identity_storage(Arc::new(FakeIdentityStorage::new()))
        .attestation_sink(Arc::new(FakeAttestationSink::new()))
        .attestation_source(Arc::new(FakeAttestationSource::new()))
        .passphrase_provider(Arc::new(PrefilledPassphraseProvider::new(PASS)))
        .build();

    let err = add_member(
        &ctx,
        &org_prefix,
        &KeyAlias::new_unchecked("org-key"),
        &KeyAlias::new_unchecked("carol"),
        CurveType::Ed25519,
        Role::Member,
        &[],
        None,
    )
    .expect_err("kt≥2 org delegation must be rejected");

    assert!(
        matches!(err, OrgError::OrgThresholdDelegationUnsupported { .. }),
        "expected OrgThresholdDelegationUnsupported, got {err:?}"
    );
}

#[test]
fn policy_reads_org_authority_from_kel() {
    let (ctx, org_alias, org_prefix, _tmp) = setup();
    let member_alias = KeyAlias::new_unchecked("dave");
    let org_did = format!("did:keri:{}", org_prefix.as_str());

    let member = add_member(
        &ctx,
        &org_prefix,
        &org_alias,
        &member_alias,
        CurveType::Ed25519,
        Role::Admin,
        &["manage_members".to_string()],
        None,
    )
    .expect("delegate org admin member");
    let member_prefix = Prefix::new_unchecked(member.member_prefix.clone());

    let policy = PolicyBuilder::new()
        .not_revoked()
        .require_delegated_by(org_did.clone())
        .require_capability("manage_members")
        .build();

    // Authority read from the org KEL → the admin member is allowed.
    #[allow(clippy::disallowed_methods)]
    let now = chrono::Utc::now();
    let ctx_eval = member_policy_context(&ctx, &org_prefix, &member_prefix, now)
        .expect("build policy context from KEL");
    assert_eq!(
        evaluate_strict(&policy, &ctx_eval).outcome,
        Outcome::Allow,
        "delegated, not-revoked admin member must be allowed"
    );

    // After the org revokes on the KEL, the same policy denies — read fail-closed.
    revoke_member(&ctx, &org_prefix, &org_alias, &member.member_did).expect("revoke member");
    let ctx_eval_revoked = member_policy_context(&ctx, &org_prefix, &member_prefix, now)
        .expect("rebuild policy context from KEL");
    assert_eq!(
        evaluate_strict(&policy, &ctx_eval_revoked).outcome,
        Outcome::Deny,
        "revoked-on-KEL member must be denied"
    );

    // And the live set excludes the revoked member.
    let live = list_members(&ctx, &org_prefix)
        .expect("list members")
        .into_iter()
        .filter(|m| !m.revoked)
        .count();
    assert_eq!(live, 0, "revoked member drops out of the live set");
}
