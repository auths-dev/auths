//! Relying-party presentation authentication e2e.
//!
//! Builds a real issuer + delegated subject + issued credential, then runs the full
//! `authenticate_presentation` flow through a green git-backed registry: parse the wire
//! shape, consume the single-use challenge, resolve issuer + subject + delegator KELs,
//! verify, and map to a `VerifiedPrincipal`. Covers the valid path, single-use replay,
//! audience mismatch (server A vs B), and a revoked credential.

use std::path::Path;
use std::sync::Arc;

use auths_core::PrefilledPassphraseProvider;
use auths_core::signing::{PassphraseProvider, StorageSigner};
use auths_core::storage::keychain::KeyAlias;
use auths_core::testing::IsolatedKeychainHandle;
use auths_crypto::CurveType;
use auths_id::keri::parse_did_keri;
use auths_id::keri::types::Prefix;
use auths_rp::{Audience, ChallengeStore, InMemoryChallengeStore, WirePresentation};
use auths_sdk::context::AuthsContext;
use auths_sdk::domains::credentials::{
    PresentationAuthError, PresentationChallenge, authenticate_presentation, issue,
    present_credential, revoke,
};
use auths_sdk::domains::device::add_device;
use auths_sdk::domains::identity::service::initialize;
use auths_sdk::domains::identity::types::{
    CreateDeveloperIdentityConfig, IdentityConfig, InitializeResult,
};
use auths_sdk::domains::org::policy::{Expr, set_org_policy};
use auths_sdk::domains::signing::types::GitSigningScope;

use crate::cases::helpers::build_test_context_with_provider;

const PASS: &str = "Test-passphrase1!";
const AUDIENCE: &str = "api.example.com";

fn setup_test_identity(registry_path: &Path) -> (KeyAlias, IsolatedKeychainHandle) {
    let keychain = IsolatedKeychainHandle::new();
    let signer = StorageSigner::new(keychain.clone());
    let provider = PrefilledPassphraseProvider::new(PASS);
    let config = CreateDeveloperIdentityConfig::builder(KeyAlias::new_unchecked("issuer-key"))
        .with_git_signing_scope(GitSigningScope::Skip)
        .build();
    let ctx = build_test_context_with_provider(registry_path, Arc::new(keychain.clone()), None);
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

struct Harness {
    ctx: AuthsContext,
    issuer_alias: KeyAlias,
    _tmp: tempfile::TempDir,
}

fn setup() -> Harness {
    let tmp = tempfile::tempdir().unwrap();
    let (issuer_alias, keychain) = setup_test_identity(tmp.path());
    let provider: Arc<dyn PassphraseProvider + Send + Sync> =
        Arc::new(PrefilledPassphraseProvider::new(PASS));
    let ctx = build_test_context_with_provider(tmp.path(), Arc::new(keychain), Some(provider));
    Harness {
        ctx,
        issuer_alias,
        _tmp: tmp,
    }
}

/// Delegate a subject device + issue a credential to it; returns `(alias, prefix, said)`.
fn issue_to_subject(h: &Harness, label: &str, curve: CurveType) -> (KeyAlias, Prefix, String) {
    let subject_alias = KeyAlias::new_unchecked(label);
    let device = add_device(&h.ctx, &h.issuer_alias, &subject_alias, curve).expect("delegate");
    let subject_prefix = parse_did_keri(&device.device_did).expect("subject prefix");
    let issued = issue(
        &h.ctx,
        &h.issuer_alias,
        &device.device_did,
        &["sign_commit".to_string()],
        None,
        None,
    )
    .expect("issue credential");
    (subject_alias, subject_prefix, issued.credential_said)
}

/// Issue a challenge from the store, sign a presentation over it, return the wire shape.
fn present_with_store(
    h: &Harness,
    subject_alias: &KeyAlias,
    cred: &str,
    issued_audience: &Audience,
    store: &InMemoryChallengeStore,
    now: chrono::DateTime<chrono::Utc>,
) -> WirePresentation {
    let issued = store.issue(issued_audience, now).expect("issue challenge");
    let envelope = present_credential(
        &h.ctx,
        subject_alias,
        cred,
        AUDIENCE,
        PresentationChallenge::Challenge {
            nonce: issued.nonce.as_bytes().to_vec(),
        },
    )
    .expect("present");
    WirePresentation::from_envelope(&envelope)
}

#[tokio::test]
async fn valid_presentation_authenticates_and_replay_rejected() {
    let h = setup();
    let (subject_alias, subject_prefix, cred) = issue_to_subject(&h, "agent", CurveType::P256);
    let audience = Audience::parse(AUDIENCE).unwrap();
    let store = InMemoryChallengeStore::new(16);
    let now = chrono::Utc::now();

    let wire = present_with_store(&h, &subject_alias, &cred, &audience, &store, now);

    let principal = authenticate_presentation(
        &h.ctx,
        &h.issuer_alias,
        &store,
        &audience,
        wire.clone(),
        now,
    )
    .await
    .expect("valid presentation authenticates");
    assert_eq!(
        principal.subject().as_str(),
        format!("did:keri:{}", subject_prefix.as_str()),
        "the authenticated principal is the delegated subject"
    );

    // Replaying the same wire fails: the single-use nonce was consumed.
    let replay =
        authenticate_presentation(&h.ctx, &h.issuer_alias, &store, &audience, wire, now).await;
    let err = replay.expect_err("replayed presentation must be rejected");
    assert_eq!(err.http_status(), 401);
}

/// The issuer's KEL prefix (it acts as the org/policy authority in this harness).
fn issuer_prefix(h: &Harness) -> Prefix {
    let did = h
        .ctx
        .identity_storage
        .load_identity()
        .expect("issuer identity")
        .controller_did;
    parse_did_keri(did.as_str()).expect("issuer prefix")
}

#[tokio::test]
async fn org_policy_denies_authenticated_presentation_with_403() {
    // E1 A4: a presentation that authenticates cleanly is still denied (403, not 401)
    // when the issuer's org policy is not satisfied by the credential's grant.
    let h = setup();
    let (subject_alias, _p, cred) = issue_to_subject(&h, "agent", CurveType::P256);
    let audience = Audience::parse(AUDIENCE).unwrap();
    let store = InMemoryChallengeStore::new(16);
    let now = chrono::Utc::now();

    // The credential grants `sign_commit`; require a capability it lacks.
    set_org_policy(
        &h.ctx,
        &issuer_prefix(&h),
        &h.issuer_alias,
        &serde_json::to_vec(&Expr::HasCapability("deploy".into())).unwrap(),
    )
    .expect("anchor org policy");

    let wire = present_with_store(&h, &subject_alias, &cred, &audience, &store, now);
    let err = authenticate_presentation(&h.ctx, &h.issuer_alias, &store, &audience, wire, now)
        .await
        .expect_err("org policy must deny");
    assert!(
        matches!(err, PresentationAuthError::PolicyDenied { .. }),
        "expected PolicyDenied, got {err:?}"
    );
    assert_eq!(
        err.http_status(),
        403,
        "an authenticated-but-policy-denied principal is 403, not 401"
    );
}

#[tokio::test]
async fn org_policy_allows_authenticated_presentation_when_satisfied() {
    let h = setup();
    let (subject_alias, _p, cred) = issue_to_subject(&h, "agent", CurveType::P256);
    let audience = Audience::parse(AUDIENCE).unwrap();
    let store = InMemoryChallengeStore::new(16);
    let now = chrono::Utc::now();

    set_org_policy(
        &h.ctx,
        &issuer_prefix(&h),
        &h.issuer_alias,
        &serde_json::to_vec(&Expr::And(vec![
            Expr::NotRevoked,
            Expr::HasCapability("sign_commit".into()),
        ]))
        .unwrap(),
    )
    .expect("anchor org policy");

    let wire = present_with_store(&h, &subject_alias, &cred, &audience, &store, now);
    let principal =
        authenticate_presentation(&h.ctx, &h.issuer_alias, &store, &audience, wire, now)
            .await
            .expect("policy satisfied → authenticates");
    assert!(!principal.capabilities().is_empty());
}

#[tokio::test]
async fn presentation_for_audience_a_rejected_at_server_b() {
    let h = setup();
    let (subject_alias, _subject_prefix, cred) = issue_to_subject(&h, "agent", CurveType::Ed25519);
    let real = Audience::parse(AUDIENCE).unwrap();
    let store = InMemoryChallengeStore::new(16);
    let now = chrono::Utc::now();

    let wire = present_with_store(&h, &subject_alias, &cred, &real, &store, now);

    // The relying party is configured for a DIFFERENT audience — confused-deputy defense.
    let other = Audience::parse("evil.example.com").unwrap();
    let result =
        authenticate_presentation(&h.ctx, &h.issuer_alias, &store, &other, wire, now).await;
    assert!(
        result.is_err(),
        "a presentation bound to audience A must be rejected at server B"
    );
}

#[tokio::test]
async fn revoked_credential_presentation_rejected() {
    let h = setup();
    let (subject_alias, _subject_prefix, cred) = issue_to_subject(&h, "agent", CurveType::P256);
    let audience = Audience::parse(AUDIENCE).unwrap();
    let store = InMemoryChallengeStore::new(16);
    let now = chrono::Utc::now();

    revoke(&h.ctx, &h.issuer_alias, &cred).expect("revoke credential");

    let wire = present_with_store(&h, &subject_alias, &cred, &audience, &store, now);
    let result =
        authenticate_presentation(&h.ctx, &h.issuer_alias, &store, &audience, wire, now).await;
    assert!(
        result.is_err(),
        "a presentation of a revoked credential must be rejected"
    );
}

#[tokio::test]
async fn valid_then_revoked_presentation_transition() {
    let h = setup();
    let (subject_alias, _subject_prefix, cred) = issue_to_subject(&h, "agent", CurveType::P256);
    let audience = Audience::parse(AUDIENCE).unwrap();
    let store = InMemoryChallengeStore::new(16);
    let now = chrono::Utc::now();

    // Before revocation: a fresh presentation authenticates.
    let wire_before = present_with_store(&h, &subject_alias, &cred, &audience, &store, now);
    authenticate_presentation(&h.ctx, &h.issuer_alias, &store, &audience, wire_before, now)
        .await
        .expect("presentation authenticates before revocation");

    // Revoke the credential (anchors a `rev` in the issuer KEL).
    revoke(&h.ctx, &h.issuer_alias, &cred).expect("revoke credential");

    // After revocation: a fresh presentation of the same credential is rejected.
    let wire_after = present_with_store(&h, &subject_alias, &cred, &audience, &store, now);
    let after =
        authenticate_presentation(&h.ctx, &h.issuer_alias, &store, &audience, wire_after, now)
            .await;
    assert!(
        after.is_err(),
        "after revocation, a fresh presentation of the same credential must be rejected"
    );
}
