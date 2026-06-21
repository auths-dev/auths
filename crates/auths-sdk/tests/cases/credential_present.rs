//! Epic F.8 — SDK credential presentation + holder-binding challenge issuance.
//!
//! Exercises `credentials::present_credential` (the subject signs `(cred-SAID ||
//! audience || nonce)` with its current key) and the verifier-held single-use
//! `ChallengeSession`, then runs the produced envelope end-to-end through the pure
//! `auths_verifier::verify_presentation` against a real git-backed subject KEL. The
//! credential is issued by a real issuer; the subject is a delegated device whose KEL
//! (and signing key) live in the test keychain.

use std::ops::ControlFlow;
use std::path::Path;
use std::sync::Arc;

use auths_core::PrefilledPassphraseProvider;
use auths_core::signing::{PassphraseProvider, StorageSigner};
use auths_core::storage::keychain::KeyAlias;
use auths_core::testing::IsolatedKeychainHandle;
use auths_crypto::{CurveType, RingCryptoProvider};
use auths_id::keri::Event;
use auths_id::keri::parse_did_keri;
use auths_id::keri::types::Prefix;
use auths_sdk::context::AuthsContext;
use auths_sdk::domains::credentials::{
    ChallengeSession, PresentationChallenge, VerifierWitnessPolicy, issue, present_credential,
    revoke,
};
use auths_sdk::domains::device::add_device;
use auths_sdk::domains::identity::service::initialize;
use auths_sdk::domains::identity::types::{
    CreateDeveloperIdentityConfig, IdentityConfig, InitializeResult,
};
use auths_sdk::domains::signing::types::GitSigningScope;
use auths_verifier::{PresentationVerdict, SignedAcdc, verify_presentation};

use crate::cases::helpers::build_test_context_with_provider;

const PASS: &str = "Test-passphrase1!";
const AUDIENCE: &str = "audience.example";

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
    issuer_prefix: Prefix,
    _tmp: tempfile::TempDir,
}

fn setup() -> Harness {
    let tmp = tempfile::tempdir().unwrap();
    let (issuer_alias, keychain) = setup_test_identity(tmp.path());
    let provider: Arc<dyn PassphraseProvider + Send + Sync> =
        Arc::new(PrefilledPassphraseProvider::new(PASS));
    let ctx = build_test_context_with_provider(tmp.path(), Arc::new(keychain), Some(provider));
    let managed = ctx
        .identity_storage
        .load_identity()
        .expect("issuer identity");
    let issuer_prefix = Prefix::new_unchecked(
        managed
            .controller_did
            .as_str()
            .strip_prefix("did:keri:")
            .unwrap()
            .to_string(),
    );
    Harness {
        ctx,
        issuer_alias,
        issuer_prefix,
        _tmp: tmp,
    }
}

/// Collect a KEL (oldest first) for a prefix via the registry.
fn collect_kel(ctx: &AuthsContext, prefix: &Prefix) -> Vec<Event> {
    let mut events = Vec::new();
    ctx.registry
        .visit_events(prefix, 0, &mut |e| {
            events.push(e.clone());
            ControlFlow::Continue(())
        })
        .expect("walk KEL");
    events
}

/// The signed ACDC for a credential SAID (the issuer-signed F.5 input).
fn signed_acdc(h: &Harness, credential_said: &str) -> SignedAcdc {
    use auths_sdk::domains::credentials::StoredCredential;
    let blob = h
        .ctx
        .registry
        .load_credential(
            &h.issuer_prefix,
            &auths_id::keri::types::Said::new_unchecked(credential_said.to_string()),
        )
        .expect("load credential")
        .expect("credential blob");
    let stored = StoredCredential::from_bytes(&blob).expect("parse stored credential");
    SignedAcdc {
        acdc: stored.acdc,
        signature: stored.signature,
    }
}

/// Issue a credential to a freshly delegated subject device, returning
/// `(subject_alias, subject_prefix, credential_said)`.
fn issue_to_subject(h: &Harness, label: &str, curve: CurveType) -> (KeyAlias, Prefix, String) {
    let subject_alias = KeyAlias::new_unchecked(label);
    let device = add_device(&h.ctx, &h.issuer_alias, &subject_alias, curve).expect("delegate");
    let subject_prefix = parse_did_keri(&device.device_did).expect("subject prefix");
    let issued = issue(
        &h.ctx,
        &h.issuer_alias,
        &device.device_did,
        &[auths_keri::Capability::parse("sign").unwrap()],
        None,
        None,
    )
    .expect("issue credential to subject");
    (subject_alias, subject_prefix, issued.credential_said)
}

/// Run the pure verifier against a presented envelope using the harness's resolved KELs.
async fn verify(
    h: &Harness,
    envelope: &auths_verifier::PresentationEnvelope,
    credential_said: &str,
    subject_prefix: &Prefix,
    expected_challenge: Option<&[u8]>,
) -> PresentationVerdict {
    let signed = signed_acdc(h, credential_said);
    let issuer_kel = collect_kel(&h.ctx, &h.issuer_prefix);
    let subject_kel = collect_kel(&h.ctx, subject_prefix);

    let registry = auths_id::keri::credential_registry::find_registry(
        h.ctx.registry.as_ref(),
        &h.issuer_prefix,
    )
    .unwrap()
    .expect("registry exists");
    let tel = auths_id::keri::credential_registry::read_credential_tel(
        h.ctx.registry.as_ref(),
        &h.issuer_prefix,
        &registry,
        &auths_id::keri::types::Said::new_unchecked(credential_said.to_string()),
    )
    .expect("read tel");

    // The subject is a delegated device; its delegator is the issuer (root) identity,
    // so the issuer KEL supplies the delegated subject's anchoring seals.
    verify_presentation(
        envelope,
        &signed,
        &issuer_kel,
        &tel,
        &[],
        VerifierWitnessPolicy::Warn,
        &subject_kel,
        &issuer_kel,
        AUDIENCE,
        expected_challenge,
        chrono::Utc::now(),
        &auths_verifier::freshness::FreshnessPolicy::default(),
        None,
        &RingCryptoProvider,
    )
    .await
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn present_challenge_round_trips_and_verifies() {
    for curve in [CurveType::Ed25519, CurveType::P256] {
        let h = setup();
        let label = match curve {
            CurveType::Ed25519 => "subject-ed",
            CurveType::P256 => "subject-p256",
        };
        let (subject_alias, subject_prefix, cred) = issue_to_subject(&h, label, curve);

        // Verifier issues a fresh single-use challenge.
        let mut session = ChallengeSession::issue(AUDIENCE, &cred).expect("issue challenge");
        let nonce = session.nonce().to_vec();

        // Subject signs the presentation with its current key.
        let envelope = present_credential(
            &h.ctx,
            &subject_alias,
            &cred,
            AUDIENCE,
            PresentationChallenge::Challenge {
                nonce: nonce.clone(),
            },
        )
        .expect("present");

        // Verifier consumes the challenge once and checks.
        let expected = session.consume().expect("first consume yields the nonce");
        let verdict = verify(&h, &envelope, &cred, &subject_prefix, Some(&expected)).await;
        assert!(
            verdict.is_honored(),
            "valid challenge presentation must be honored on {curve:?}, got {verdict:?}"
        );

        // Replay with the now-consumed session → no nonce offered → rejected.
        assert!(
            session.consume().is_none(),
            "challenge is single-use (already consumed)"
        );
        let replay = verify(&h, &envelope, &cred, &subject_prefix, None).await;
        assert_eq!(
            replay,
            PresentationVerdict::NonceMismatchOrConsumed,
            "a replayed presentation against a consumed challenge is rejected"
        );
    }
}

#[tokio::test]
async fn present_ttl_within_window_verifies_and_expired_rejected() {
    let h = setup();
    let (subject_alias, subject_prefix, cred) =
        issue_to_subject(&h, "subject-ttl", CurveType::Ed25519);

    // In-window TTL presentation is honored (non-interactive path).
    let not_after = chrono::Utc::now() + chrono::Duration::seconds(300);
    let envelope = present_credential(
        &h.ctx,
        &subject_alias,
        &cred,
        AUDIENCE,
        PresentationChallenge::Ttl { not_after },
    )
    .expect("present ttl");
    let verdict = verify(&h, &envelope, &cred, &subject_prefix, None).await;
    assert!(
        verdict.is_honored(),
        "in-window TTL presentation honored, got {verdict:?}"
    );

    // An already-expired TTL presentation is rejected.
    let past = chrono::Utc::now() - chrono::Duration::seconds(1);
    let expired_envelope = present_credential(
        &h.ctx,
        &subject_alias,
        &cred,
        AUDIENCE,
        PresentationChallenge::Ttl { not_after: past },
    )
    .expect("present expired ttl");
    let expired = verify(&h, &expired_envelope, &cred, &subject_prefix, None).await;
    assert_eq!(expired, PresentationVerdict::Expired);
}

#[tokio::test]
async fn present_of_revoked_credential_rejected() {
    let h = setup();
    let (subject_alias, subject_prefix, cred) =
        issue_to_subject(&h, "subject-rev", CurveType::Ed25519);

    revoke(&h.ctx, &h.issuer_alias, &cred).expect("revoke");

    let mut session = ChallengeSession::issue(AUDIENCE, &cred).expect("issue challenge");
    let nonce = session.nonce().to_vec();
    let envelope = present_credential(
        &h.ctx,
        &subject_alias,
        &cred,
        AUDIENCE,
        PresentationChallenge::Challenge { nonce },
    )
    .expect("present");

    let expected = session.consume().unwrap();
    let verdict = verify(&h, &envelope, &cred, &subject_prefix, Some(&expected)).await;
    match verdict {
        PresentationVerdict::CredentialNotValid(_) => {}
        other => panic!("expected CredentialNotValid for a revoked credential, got {other:?}"),
    }
}
