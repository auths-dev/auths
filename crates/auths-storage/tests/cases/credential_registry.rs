//! Credential registry over the Git-backed `GitRegistryBackend`.
//!
//! The same F.3 flow exercised against the in-memory fake in
//! `auths-id/tests/cases/credential_registry.rs`, here proving the Git backend
//! persists TEL events + ACDC blobs and anchors `vcp`/`iss` to a *real, signed*
//! issuer KEL atomically (one commit per `anchor_tel_event`).

use std::ops::ControlFlow;
use std::sync::Arc;

use auths_core::storage::keychain::{IdentityDID, KeyAlias};
use auths_core::testing::{IsolatedKeychainHandle, TestPassphraseProvider};
use auths_crypto::CurveType;
use auths_id::identity::initialize::{
    initialize_registry_identity, initialize_registry_identity_multi,
};
use auths_id::keri::credential_registry::{
    CredentialRegistryError, anchor_tel_event, build_iss, ensure_registry, find_registry,
    read_credential_tel,
};
use auths_id::keri::types::Prefix;
use auths_id::keri::{Event, Said, Seal, Threshold};
use auths_id::ports::registry::RegistryBackend;
use auths_keri::{Acdc, TelEvent, compute_capability_schema_said, validate_tel};
use auths_storage::git::{GitRegistryBackend, RegistryConfig};

const TEST_PASSPHRASE: &str = "Test-passphrase1!";
const DT: &str = "2026-01-01T00:00:00.000000+00:00";
const SUBJECT: &str = "did:keri:ESubjectHolderAID00000000000000000000000000";

fn prefix_of(did: &IdentityDID) -> Prefix {
    Prefix::new_unchecked(did.as_str().strip_prefix("did:keri:").unwrap().to_string())
}

struct GitIssuer {
    backend: Arc<dyn RegistryBackend + Send + Sync>,
    prefix: Prefix,
    alias: KeyAlias,
    keychain: IsolatedKeychainHandle,
    provider: TestPassphraseProvider,
    _dir: tempfile::TempDir,
}

fn setup_git_issuer() -> GitIssuer {
    let dir = tempfile::tempdir().unwrap();
    let backend: Arc<dyn RegistryBackend + Send + Sync> = Arc::new(
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(dir.path())),
    );
    backend.init_if_needed().unwrap();

    let keychain = IsolatedKeychainHandle::new();
    let provider = TestPassphraseProvider::new(TEST_PASSPHRASE);
    let alias = KeyAlias::new_unchecked("git-issuer");
    let (did, _) = initialize_registry_identity(
        backend.clone(),
        &alias,
        &provider,
        &keychain,
        None,
        CurveType::Ed25519,
    )
    .unwrap();

    GitIssuer {
        prefix: prefix_of(&did),
        backend,
        alias,
        keychain,
        provider,
        _dir: dir,
    }
}

impl GitIssuer {
    fn ensure_registry(&self) -> Result<Said, CredentialRegistryError> {
        ensure_registry(
            self.backend.as_ref(),
            &self.prefix,
            &self.alias,
            CurveType::Ed25519,
            &self.provider,
            &self.keychain,
        )
    }

    fn issue(&self, registry: &Said, subject: &str) -> Said {
        let schema = compute_capability_schema_said().unwrap();
        let acdc = Acdc::new(
            Prefix::new_unchecked(self.prefix.as_str().to_string()),
            Said::new_unchecked(registry.as_str().to_string()),
            Said::new_unchecked(schema.as_str().to_string()),
            Prefix::new_unchecked(subject.to_string()),
            DT.to_string(),
            serde_json::Map::new(),
        )
        .saidify()
        .unwrap();
        let cred = Said::new_unchecked(acdc.d.as_str().to_string());
        let reg = Said::new_unchecked(registry.as_str().to_string());
        let iss = build_iss(&cred, &reg, DT.to_string()).unwrap();

        anchor_tel_event(
            self.backend.as_ref(),
            &self.prefix,
            &self.alias,
            CurveType::Ed25519,
            &TelEvent::Iss(iss),
            Some((cred.clone(), acdc.to_wire_bytes().unwrap())),
            &self.provider,
            &self.keychain,
        )
        .unwrap();
        cred
    }
}

fn collect_kel(backend: &(dyn RegistryBackend + Send + Sync), prefix: &Prefix) -> Vec<Event> {
    let mut events = Vec::new();
    backend
        .visit_events(prefix, 0, &mut |e| {
            events.push(e.clone());
            ControlFlow::Continue(())
        })
        .unwrap();
    events
}

#[test]
fn vcp_registry_lazily_incepted_and_anchored_git() {
    let issuer = setup_git_issuer();
    assert!(
        find_registry(issuer.backend.as_ref(), &issuer.prefix)
            .unwrap()
            .is_none()
    );

    let registry = issuer.ensure_registry().unwrap();

    let kel = collect_kel(issuer.backend.as_ref(), &issuer.prefix);
    let anchored = kel.iter().any(|e| {
        matches!(e, Event::Ixn(_))
            && e.anchors().iter().any(|s| matches!(
                s,
                Seal::KeyEvent { i, s: sn, d }
                    if i.as_str() == registry.as_str() && sn.value() == 0 && d.as_str() == registry.as_str()
            ))
    });
    assert!(anchored, "issuer KEL must anchor the vcp");

    let events = read_credential_tel(
        issuer.backend.as_ref(),
        &issuer.prefix,
        &registry,
        &registry,
    )
    .unwrap();
    assert!(matches!(events.as_slice(), [TelEvent::Vcp(_)]));
    validate_tel(&events).unwrap();
}

#[test]
fn iss_event_anchored_in_issuer_kel_git() {
    let issuer = setup_git_issuer();
    let registry = issuer.ensure_registry().unwrap();
    let credential = issuer.issue(&registry, SUBJECT);

    let kel = collect_kel(issuer.backend.as_ref(), &issuer.prefix);
    let anchored = kel.iter().any(|e| {
        matches!(e, Event::Ixn(_))
            && e.anchors().iter().any(|s| {
                matches!(
                    s,
                    Seal::KeyEvent { i, s: sn, .. }
                        if i.as_str() == credential.as_str() && sn.value() == 0
                )
            })
    });
    assert!(anchored, "issuer KEL must anchor the iss event");

    let blob = issuer
        .backend
        .load_credential(&issuer.prefix, &credential)
        .unwrap();
    assert!(
        blob.is_some(),
        "ACDC blob must persist alongside the iss anchor"
    );
}

#[test]
fn tel_events_persist_and_read_back_git() {
    let issuer = setup_git_issuer();
    let registry = issuer.ensure_registry().unwrap();
    let credential = issuer.issue(&registry, SUBJECT);

    let events = read_credential_tel(
        issuer.backend.as_ref(),
        &issuer.prefix,
        &registry,
        &credential,
    )
    .unwrap();
    assert!(
        matches!(events.as_slice(), [TelEvent::Vcp(_), TelEvent::Iss(_)]),
        "expected vcp then iss, got {events:?}"
    );
    let state = validate_tel(&events).unwrap();
    assert!(state.is_valid(&credential));
}

#[test]
fn registry_idempotent_second_issue_reuses_vcp_git() {
    let issuer = setup_git_issuer();
    let first = issuer.ensure_registry().unwrap();
    let second = issuer.ensure_registry().unwrap();
    assert_eq!(first, second, "ensure_registry must be idempotent");

    let kel = collect_kel(issuer.backend.as_ref(), &issuer.prefix);
    let vcp_anchors = kel
        .iter()
        .filter_map(|e| match e {
            Event::Ixn(_) => Some(
                e.anchors()
                    .iter()
                    .filter(|s| {
                        matches!(
                            s,
                            Seal::KeyEvent { i, s: sn, .. }
                                if i.as_str() == first.as_str() && sn.value() == 0
                        )
                    })
                    .count(),
            ),
            _ => None,
        })
        .sum::<usize>();
    assert_eq!(vcp_anchors, 1, "exactly one vcp anchor per issuer");

    let c1 = issuer.issue(
        &first,
        "did:keri:ESubjectAAA000000000000000000000000000000000",
    );
    let c2 = issuer.issue(
        &first,
        "did:keri:ESubjectBBB000000000000000000000000000000000",
    );
    assert_ne!(c1, c2);
    for cred in [&c1, &c2] {
        let events =
            read_credential_tel(issuer.backend.as_ref(), &issuer.prefix, &first, cred).unwrap();
        assert!(validate_tel(&events).unwrap().is_valid(cred));
    }
}

#[test]
fn kt2_issuer_registry_rejected_typed_git() {
    let dir = tempfile::tempdir().unwrap();
    let backend: Arc<dyn RegistryBackend + Send + Sync> = Arc::new(
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(dir.path())),
    );
    backend.init_if_needed().unwrap();
    let keychain = IsolatedKeychainHandle::new();
    let provider = TestPassphraseProvider::new(TEST_PASSPHRASE);
    let alias = KeyAlias::new_unchecked("git-multisig-issuer");

    let (did, _) = initialize_registry_identity_multi(
        backend.clone(),
        &alias,
        &provider,
        &keychain,
        None,
        &[CurveType::Ed25519, CurveType::Ed25519],
        Threshold::Simple(2),
        Threshold::Simple(2),
    )
    .unwrap();
    let prefix = prefix_of(&did);

    let err = ensure_registry(
        backend.as_ref(),
        &prefix,
        &alias,
        CurveType::Ed25519,
        &provider,
        &keychain,
    )
    .expect_err("kt=2 issuer must be rejected");
    assert!(matches!(
        err,
        CredentialRegistryError::ThresholdUnsupported { .. }
    ));
}
