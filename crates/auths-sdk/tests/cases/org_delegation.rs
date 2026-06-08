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
use auths_id::keri::delegation::build_device_dip;
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
    AuthorityAtSigning, add_existing_member, add_member, classify_authority_at_signing, create_org,
    list_members, list_offboarding_records, load_offboarding_record, member_policy_context,
    resolve_member_authority, revoke_member, verify_offboarding_record,
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
fn create_org_round_trips_through_add_and_list_members() {
    let tmp = tempfile::tempdir().unwrap();
    let keychain = IsolatedKeychainHandle::new();
    let provider: Arc<dyn PassphraseProvider + Send + Sync> =
        Arc::new(PrefilledPassphraseProvider::new(PASS));
    let ctx =
        build_test_context_with_provider(tmp.path(), Arc::new(keychain.clone()), Some(provider));

    let org_alias = KeyAlias::new_unchecked("org-key");
    let created = create_org(&ctx, "Acme Security", &org_alias, CurveType::Ed25519, None)
        .expect("create org identity via the extracted SDK workflow");

    assert!(created.org_did.starts_with("did:keri:"));
    assert_eq!(
        created.admin_did, created.org_did,
        "the admin self-attestation subject is the org itself"
    );
    assert_eq!(created.metadata["type"], "org");
    assert_eq!(created.metadata["name"], "Acme Security");

    // Fail closed: a second create over the same registry must not clobber the org.
    let dup = create_org(&ctx, "Acme Two", &org_alias, CurveType::Ed25519, None);
    assert!(
        matches!(dup, Err(OrgError::IdentityExists { .. })),
        "second create over an existing identity must fail closed, got {dup:?}"
    );

    // The extracted org is byte-compatible with the shipped membership workflows:
    // add_member → list_members round-trips with no CLI/subprocess.
    let org_prefix = Prefix::new_unchecked(created.org_prefix.clone());
    let member = add_member(
        &ctx,
        &org_prefix,
        &org_alias,
        &KeyAlias::new_unchecked("alice"),
        CurveType::Ed25519,
        Role::Member,
        &["sign_commit".to_string()],
        None,
    )
    .expect("add a member to the extracted org");

    let live: Vec<_> = list_members(&ctx, &org_prefix)
        .expect("list members")
        .into_iter()
        .filter(|m| !m.revoked)
        .collect();
    assert_eq!(live.len(), 1, "the single added member is live");
    assert_eq!(live[0].member_did, member.member_did);
    assert_eq!(live[0].role, Some(Role::Member));
    assert_eq!(live[0].capabilities, vec!["sign_commit".to_string()]);
}

#[test]
fn add_existing_member_delegates_to_members_own_aid() {
    let (ctx, org_alias, org_prefix, _tmp) = setup();

    // The member generates their OWN key and builds a delegated dip naming this org
    // as delegator — the org never holds the member's private key.
    let bundle = build_device_dip(&org_prefix, CurveType::Ed25519).expect("member builds own dip");
    let member_prefix = bundle.device_prefix.clone();

    let result = add_existing_member(
        &ctx,
        &org_prefix,
        &org_alias,
        &bundle.dip,
        &bundle.attachment,
        Role::Member,
        &["sign_commit".to_string()],
        None,
    )
    .expect("delegate to the member's existing AID");
    assert_eq!(result.member_prefix, member_prefix.as_str());

    // The member's own-signed dip is now anchored by the org (bilateral binding).
    let dip = ctx
        .registry
        .get_event(&member_prefix, 0)
        .expect("member dip anchored on the registry");
    assert!(matches!(dip, Event::Dip(_)));
    validate_delegation(&dip, &collect_kel(ctx.registry.as_ref(), &org_prefix))
        .expect("org anchored the member's own dip bilaterally");

    let authority = resolve_member_authority(&ctx, &org_prefix, &member_prefix)
        .expect("resolve authority")
        .expect("member is delegated");
    assert!(!authority.revoked);
    assert_eq!(authority.role, Some(Role::Member));
    assert_eq!(authority.capabilities, vec!["sign_commit".to_string()]);

    // Idempotent: re-delegating a live member is a no-op Ok (no duplicate dip append).
    add_existing_member(
        &ctx,
        &org_prefix,
        &org_alias,
        &bundle.dip,
        &bundle.attachment,
        Role::Member,
        &["sign_commit".to_string()],
        None,
    )
    .expect("idempotent re-add is Ok");
    let live = list_members(&ctx, &org_prefix)
        .expect("list members")
        .into_iter()
        .filter(|m| !m.revoked)
        .count();
    assert_eq!(live, 1, "idempotent re-add must not duplicate the member");
}

#[test]
fn add_existing_member_rejects_foreign_delegator() {
    let (ctx, org_alias, org_prefix, _tmp) = setup();

    // A dip naming a DIFFERENT org as delegator cannot be off-boarded by this org.
    let other_org =
        Prefix::new_unchecked("EOtherOrg0000000000000000000000000000000000".to_string());
    let bundle = build_device_dip(&other_org, CurveType::Ed25519).expect("dip for another org");

    let err = add_existing_member(
        &ctx,
        &org_prefix,
        &org_alias,
        &bundle.dip,
        &bundle.attachment,
        Role::Member,
        &[],
        None,
    )
    .expect_err("a dip delegated by another org must be rejected");
    assert!(
        matches!(err, OrgError::MemberNotDelegable { .. }),
        "expected MemberNotDelegable, got {err:?}"
    );
}

#[test]
fn revoke_already_revoked_member_is_idempotent() {
    let (ctx, org_alias, org_prefix, _tmp) = setup();
    let member = add_member(
        &ctx,
        &org_prefix,
        &org_alias,
        &KeyAlias::new_unchecked("erin"),
        CurveType::Ed25519,
        Role::Member,
        &[],
        None,
    )
    .expect("mint member");

    revoke_member(&ctx, &org_prefix, &org_alias, &member.member_did, None).expect("first revoke");
    // Revoking an already-revoked member is an Ok no-op.
    let dup = revoke_member(&ctx, &org_prefix, &org_alias, &member.member_did, None)
        .expect("second revoke is an idempotent no-op");
    assert!(
        dup.is_none(),
        "idempotent re-revoke must not write a duplicate record"
    );

    let member_prefix = Prefix::new_unchecked(member.member_prefix.clone());
    let authority = resolve_member_authority(&ctx, &org_prefix, &member_prefix)
        .expect("resolve authority")
        .expect("member present");
    assert!(authority.revoked);
}

#[test]
fn revoke_member_emits_verifiable_offboarding_record() {
    let (ctx, org_alias, org_prefix, _tmp) = setup();
    let member = add_member(
        &ctx,
        &org_prefix,
        &org_alias,
        &KeyAlias::new_unchecked("frank"),
        CurveType::Ed25519,
        Role::Member,
        &["sign_commit".to_string()],
        None,
    )
    .expect("add member");
    let member_prefix = Prefix::new_unchecked(member.member_prefix.clone());

    let signed = revoke_member(
        &ctx,
        &org_prefix,
        &org_alias,
        &member.member_did,
        Some("left the company".to_string()),
    )
    .expect("revoke produces a record")
    .expect("a fresh revoke writes a record");

    // The record carries who/whom/why + the lost role+caps snapshot, bound by KEL position.
    assert_eq!(signed.record.member_did, member.member_did);
    assert_eq!(
        signed.record.org_did,
        format!("did:keri:{}", org_prefix.as_str())
    );
    assert_eq!(signed.record.reason.as_deref(), Some("left the company"));
    assert_eq!(signed.record.prior_role, Some("member".to_string()));
    assert_eq!(signed.record.prior_caps, vec!["sign_commit".to_string()]);
    assert!(!signed.record.revocation_seal_said.is_empty());

    // Persisted and retrievable by (org, member).
    let loaded = load_offboarding_record(&ctx, &org_prefix, &member_prefix)
        .expect("load record")
        .expect("record present");
    assert_eq!(loaded.record, signed.record);

    // Verifies against the org key + the matching on-KEL revocation seal.
    let (org_pk, org_curve) = auths_core::storage::keychain::extract_public_key_bytes(
        ctx.key_storage.as_ref(),
        &org_alias,
        ctx.passphrase_provider.as_ref(),
    )
    .expect("org pubkey");
    let org_kel = collect_kel(ctx.registry.as_ref(), &org_prefix);
    verify_offboarding_record(&loaded, &org_pk, org_curve, &org_kel).expect("record verifies");

    // Tampering the record breaks the org signature.
    let mut tampered = loaded.clone();
    tampered.record.reason = Some("a different reason".to_string());
    assert!(
        verify_offboarding_record(&tampered, &org_pk, org_curve, &org_kel).is_err(),
        "a tampered record must fail verification"
    );
}

#[test]
fn classify_authority_orders_by_kel_position_not_wall_clock() {
    let (ctx, org_alias, org_prefix, _tmp) = setup();
    let member = add_member(
        &ctx,
        &org_prefix,
        &org_alias,
        &KeyAlias::new_unchecked("grace"),
        CurveType::Ed25519,
        Role::Member,
        &["sign_commit".to_string()],
        None,
    )
    .expect("add member");
    let member_prefix = Prefix::new_unchecked(member.member_prefix.clone());

    // Before any revocation, a live member is authorized at every position.
    assert_eq!(
        classify_authority_at_signing(&ctx, &org_prefix, &member_prefix, Some(0)).unwrap(),
        AuthorityAtSigning::AuthorizedBeforeRevocation
    );

    let signed = revoke_member(&ctx, &org_prefix, &org_alias, &member.member_did, None)
        .expect("revoke")
        .expect("record");
    let rev = signed.record.revoked_at_seq;

    // Exactly around the revocation KEL position.
    assert_eq!(
        classify_authority_at_signing(&ctx, &org_prefix, &member_prefix, Some(rev - 1)).unwrap(),
        AuthorityAtSigning::AuthorizedBeforeRevocation,
        "signed strictly before the revocation stays authorized"
    );
    assert_eq!(
        classify_authority_at_signing(&ctx, &org_prefix, &member_prefix, Some(rev)).unwrap(),
        AuthorityAtSigning::RejectedAfterRevocation { revoked_at: rev },
        "signed at the revocation position is rejected"
    );
    assert_eq!(
        classify_authority_at_signing(&ctx, &org_prefix, &member_prefix, Some(rev + 1)).unwrap(),
        AuthorityAtSigning::RejectedAfterRevocation { revoked_at: rev },
        "signed after the revocation position is rejected"
    );

    // No in-band position → conservative reject (never a wall-clock comparison).
    assert_eq!(
        classify_authority_at_signing(&ctx, &org_prefix, &member_prefix, None).unwrap(),
        AuthorityAtSigning::RejectedRevokedPositionUnknown { revoked_at: rev }
    );

    // A never-delegated member is a distinct typed outcome.
    let stranger =
        Prefix::new_unchecked("EStranger000000000000000000000000000000000000".to_string());
    assert_eq!(
        classify_authority_at_signing(&ctx, &org_prefix, &stranger, Some(0)).unwrap(),
        AuthorityAtSigning::NeverDelegated
    );

    // The off-boarding log enumerates the revoked member's durable record.
    let log = list_offboarding_records(&ctx, &org_prefix).expect("list offboarding log");
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].record.member_did, member.member_did);
}

#[test]
fn air_gapped_org_bundle_is_self_contained_and_url_free() {
    use auths_sdk::domains::org::{
        AIR_GAPPED_ORG_BUNDLE_SCHEMA_VERSION, AirGappedOrgBundle, build_org_bundle,
    };

    let (ctx, org_alias, org_prefix, _tmp) = setup();
    let member = add_member(
        &ctx,
        &org_prefix,
        &org_alias,
        &KeyAlias::new_unchecked("heidi"),
        CurveType::Ed25519,
        Role::Member,
        &["sign_commit".to_string()],
        None,
    )
    .expect("add member");
    revoke_member(
        &ctx,
        &org_prefix,
        &org_alias,
        &member.member_did,
        Some("offboarded".to_string()),
    )
    .expect("revoke")
    .expect("record");

    let bundle = build_org_bundle(&ctx, &org_prefix).expect("build bundle");
    assert_eq!(bundle.schema_version, AIR_GAPPED_ORG_BUNDLE_SCHEMA_VERSION);
    assert_eq!(
        bundle.org_did.as_str(),
        format!("did:keri:{}", org_prefix.as_str())
    );
    assert!(
        bundle.built_at_org_seq >= 1,
        "declares the build KEL position"
    );
    assert!(!bundle.org_kel.events.is_empty(), "packs the org KEL");
    assert_eq!(bundle.member_kels.len(), 1, "packs the member KEL");
    assert!(!bundle.member_kels[0].events.is_empty());
    assert_eq!(
        bundle.offboarding_records.len(),
        1,
        "packs the off-boarding record"
    );
    assert_eq!(
        bundle.pinned_roots,
        vec![bundle.org_did.clone()],
        "the org is its own pinned root"
    );

    // Canonical, deterministic, and URL-free (cannot phone home).
    let json = bundle.to_canonical_json().expect("canonical json");
    assert_eq!(
        json,
        bundle.to_canonical_json().expect("again"),
        "canonicalization is deterministic"
    );
    for needle in ["http://", "https://", "oobi", "://", "witness"] {
        assert!(
            !json.contains(needle),
            "air-gapped bundle must be URL-free; found {needle:?}"
        );
    }

    // Round-trips losslessly through the typed parser.
    let parsed = AirGappedOrgBundle::from_json(&json).expect("parse bundle");
    assert_eq!(parsed.org_did.as_str(), bundle.org_did.as_str());
    assert_eq!(parsed.member_kels.len(), bundle.member_kels.len());
    assert_eq!(
        parsed.offboarding_records.len(),
        bundle.offboarding_records.len()
    );
}

#[test]
fn offline_verify_reproduces_live_verdict_and_fails_closed() {
    use auths_sdk::domains::org::{build_org_bundle, verify_org_bundle};
    use auths_verifier::types::IdentityDID;

    let (ctx, org_alias, org_prefix, _tmp) = setup();
    let member = add_member(
        &ctx,
        &org_prefix,
        &org_alias,
        &KeyAlias::new_unchecked("ivan"),
        CurveType::Ed25519,
        Role::Member,
        &["sign_commit".to_string()],
        None,
    )
    .expect("add member");
    let member_prefix = Prefix::new_unchecked(member.member_prefix.clone());

    // Offline classification reproduces the live verdict before revocation.
    let bundle = build_org_bundle(&ctx, &org_prefix).expect("bundle");
    let roots = vec![bundle.org_did.clone()];
    let live_before =
        classify_authority_at_signing(&ctx, &org_prefix, &member_prefix, Some(0)).unwrap();
    let report = verify_org_bundle(&bundle, &roots, Some((&member_prefix, Some(0))))
        .expect("offline verify");
    assert!(report.root_pinned, "the org is a pinned root");
    assert!(!report.duplicity_detected);
    assert_eq!(report.as_of_org_seq, bundle.built_at_org_seq);
    assert_eq!(report.authority.as_ref().unwrap(), &live_before);

    // Revoke, rebuild, and check ordering around the revocation position holds offline.
    let signed = revoke_member(&ctx, &org_prefix, &org_alias, &member.member_did, None)
        .unwrap()
        .unwrap();
    let rev = signed.record.revoked_at_seq;
    let bundle = build_org_bundle(&ctx, &org_prefix).expect("rebuild bundle");
    let roots = vec![bundle.org_did.clone()];

    assert_eq!(
        verify_org_bundle(&bundle, &roots, Some((&member_prefix, Some(rev))))
            .unwrap()
            .authority
            .unwrap(),
        AuthorityAtSigning::RejectedAfterRevocation { revoked_at: rev },
        "signed at/after revocation is rejected offline"
    );
    assert_eq!(
        verify_org_bundle(&bundle, &roots, Some((&member_prefix, Some(rev - 1))))
            .unwrap()
            .authority
            .unwrap(),
        AuthorityAtSigning::AuthorizedBeforeRevocation,
        "signed before revocation stays authorized offline"
    );

    // A non-delegating pinned root → unauthorized (root_pinned=false), not an error.
    let wrong_root =
        vec![IdentityDID::from_prefix("EWrongRoot00000000000000000000000000000000").unwrap()];
    let report =
        verify_org_bundle(&bundle, &wrong_root, None).expect("verify still returns a report");
    assert!(
        !report.root_pinned,
        "an org absent from the pinned roots is unauthorized, not an error"
    );

    // A partial bundle (delegated member's KEL missing) fails closed with a named reason.
    let mut partial = bundle.clone();
    partial.member_kels.clear();
    let err = verify_org_bundle(&partial, &roots, None)
        .expect_err("an incomplete bundle must fail closed, never 'valid'");
    assert!(
        matches!(err, OrgError::BundleMissingMemberKel { .. }),
        "expected BundleMissingMemberKel, got {err:?}"
    );
}

#[test]
fn empty_org_returns_empty_member_list() {
    let (ctx, _org_alias, org_prefix, _tmp) = setup();
    let members = list_members(&ctx, &org_prefix).expect("list members on an org with none");
    assert!(
        members.is_empty(),
        "an org with no delegated members returns an empty list, not an error"
    );
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
    revoke_member(&ctx, &org_prefix, &org_alias, &member.member_did, None).expect("revoke member");

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
    revoke_member(&ctx, &org_prefix, &org_alias, &member.member_did, None).expect("revoke member");
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
