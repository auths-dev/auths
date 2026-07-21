//! Credential registry — backerless TEL persistence anchored to the issuer KEL.
//!
//! Exercises the F.3 surface against the in-memory [`FakeRegistryBackend`]:
//! - a `vcp` registry is lazily incepted (once per issuer) and anchored,
//! - an `iss` event is anchored via a `{i,s,d}` `Seal::KeyEvent` in the issuer KEL,
//! - TEL events + the ACDC blob round-trip through the backend,
//! - a second issuance reuses the existing `vcp` (idempotent), and
//! - a `kt≥2` issuer is rejected with a typed error.
//!
//! The Git backend runs the same flow in `auths-storage/tests/cases/credential_registry.rs`.

use std::ops::ControlFlow;
use std::sync::Arc;

use auths_core::storage::keychain::{IdentityDID, KeyAlias};
use auths_core::testing::{IsolatedKeychainHandle, TestPassphraseProvider};
use auths_crypto::CurveType;
use auths_id::identity::initialize::initialize_registry_identity;
use auths_id::keri::credential_registry::{
    CredentialRegistryError, anchor_tel_event, build_iss, ensure_registry, find_registry,
    read_credential_tel,
};
use auths_id::keri::types::Prefix;
use auths_id::keri::{Event, Seal};
use auths_id::storage::registry::backend::RegistryBackend;
use auths_id::testing::fakes::FakeRegistryBackend;
use auths_id::witness_config::WitnessParams;
use auths_keri::{Acdc, TelEvent, compute_capability_schema_said, validate_tel};

const TEST_PASSPHRASE: &str = "Test-passphrase1!";
const DT: &str = "2026-01-01T00:00:00.000000+00:00";

fn prefix_of(did: &IdentityDID) -> Prefix {
    Prefix::new_unchecked(
        did.as_str()
            .strip_prefix("did:keri:")
            .expect("did:keri prefix")
            .to_string(),
    )
}

/// A signed root identity on a fresh fake backend, plus the keychain/provider it signs with.
struct Issuer {
    backend: Arc<dyn RegistryBackend + Send + Sync>,
    prefix: Prefix,
    alias: KeyAlias,
    keychain: IsolatedKeychainHandle,
    provider: TestPassphraseProvider,
}

fn setup_issuer() -> Issuer {
    let backend: Arc<dyn RegistryBackend + Send + Sync> = Arc::new(FakeRegistryBackend::new());
    let keychain = IsolatedKeychainHandle::new();
    let provider = TestPassphraseProvider::new(TEST_PASSPHRASE);
    let alias = KeyAlias::new_unchecked("issuer");
    let (did, _) = initialize_registry_identity(
        backend.clone(),
        &alias,
        &provider,
        &keychain,
        WitnessParams::Disabled,
        CurveType::Ed25519,
        chrono::Utc::now(),
    )
    .expect("issuer inception");
    let prefix = prefix_of(&did);
    Issuer {
        backend,
        prefix,
        alias,
        keychain,
        provider,
    }
}

impl Issuer {
    fn ensure_registry(&self) -> Result<auths_id::keri::Said, CredentialRegistryError> {
        ensure_registry(
            self.backend.as_ref(),
            &self.prefix,
            &self.alias,
            CurveType::Ed25519,
            &self.provider,
            &self.keychain,
        )
    }

    /// Issue a credential to `subject`, anchoring the `iss` + ACDC blob atomically.
    fn issue(&self, registry: &auths_id::keri::Said, subject: &str) -> auths_id::keri::Said {
        let schema = compute_capability_schema_said().expect("schema said");
        let acdc = Acdc::new(
            Prefix::new_unchecked(self.prefix.as_str().to_string()),
            auths_keri::Said::new_unchecked(registry.as_str().to_string()),
            auths_keri::Said::new_unchecked(schema.as_str().to_string()),
            Prefix::new_unchecked(subject.to_string()),
            DT.to_string(),
            serde_json::Map::new(),
        )
        .saidify()
        .expect("saidify acdc");

        let cred_said = auths_id::keri::Said::new_unchecked(acdc.d.as_str().to_string());
        let reg_said = auths_id::keri::Said::new_unchecked(registry.as_str().to_string());
        let iss = build_iss(&cred_said, &reg_said, DT.to_string()).expect("build iss");

        anchor_tel_event(
            self.backend.as_ref(),
            &self.prefix,
            &self.alias,
            CurveType::Ed25519,
            &TelEvent::Iss(iss),
            Some((cred_said.clone(), acdc.to_wire_bytes().expect("acdc bytes"))),
            &self.provider,
            &self.keychain,
        )
        .expect("anchor iss");

        cred_said
    }
}

/// Collect the issuer KEL (oldest first).
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
fn vcp_registry_lazily_incepted_and_anchored() {
    let issuer = setup_issuer();

    // No registry before the first call.
    assert!(
        find_registry(issuer.backend.as_ref(), &issuer.prefix)
            .expect("find registry")
            .is_none()
    );

    let registry = issuer.ensure_registry().expect("incept registry");

    // The issuer KEL grew an anchoring ixn carrying the vcp's key-event seal at sn 0.
    let kel = collect_kel(issuer.backend.as_ref(), &issuer.prefix);
    let anchored = kel.iter().any(|e| {
        matches!(e, Event::Ixn(_))
            && e.anchors().iter().any(|s| matches!(
                s,
                Seal::KeyEvent { i, s: sn, d }
                    if i.as_str() == registry.as_str() && sn.value() == 0 && d.as_str() == registry.as_str()
            ))
    });
    assert!(
        anchored,
        "issuer KEL must anchor the vcp via a {{i,s,d}} key-event seal"
    );

    // The vcp TEL event persisted and validates as a registry inception.
    let events = read_credential_tel(
        issuer.backend.as_ref(),
        &issuer.prefix,
        &registry,
        &registry,
    )
    .expect("read vcp");
    assert!(matches!(events.as_slice(), [TelEvent::Vcp(_)]));
    validate_tel(&events).expect("vcp validates");
}

#[test]
fn iss_event_anchored_in_issuer_kel() {
    let issuer = setup_issuer();
    let registry = issuer.ensure_registry().expect("incept registry");
    let credential = issuer.issue(
        &registry,
        "did:keri:ESubjectHolderAID00000000000000000000000000",
    );

    // The issuer KEL anchors the iss via a {i,s,d} key-event seal where i == credential SAID.
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

    // The ACDC blob landed atomically with the iss.
    let blob = issuer
        .backend
        .load_credential(&issuer.prefix, &credential)
        .expect("load credential");
    assert!(
        blob.is_some(),
        "ACDC blob must persist alongside the iss anchor"
    );
}

#[test]
fn tel_events_persist_and_read_back() {
    let issuer = setup_issuer();
    let registry = issuer.ensure_registry().expect("incept registry");
    let credential = issuer.issue(
        &registry,
        "did:keri:ESubjectHolderAID00000000000000000000000000",
    );

    // The vcp + iss chain reads back in order and the credential validates as issued.
    let events = read_credential_tel(
        issuer.backend.as_ref(),
        &issuer.prefix,
        &registry,
        &credential,
    )
    .expect("read tel");
    assert!(
        matches!(events.as_slice(), [TelEvent::Vcp(_), TelEvent::Iss(_)]),
        "expected vcp then iss, got {events:?}"
    );

    let state = validate_tel(&events).expect("tel validates");
    assert!(
        state.is_valid(&credential),
        "credential must read back as issued"
    );
}

#[test]
fn registry_idempotent_second_issue_reuses_vcp() {
    let issuer = setup_issuer();
    let first = issuer.ensure_registry().expect("incept registry");
    let second = issuer.ensure_registry().expect("second ensure");
    assert_eq!(
        first, second,
        "ensure_registry must be idempotent per issuer"
    );

    // Only one vcp anchor exists in the KEL (the second ensure incepted nothing).
    let kel = collect_kel(issuer.backend.as_ref(), &issuer.prefix);
    let vcp_anchors = kel
        .iter()
        .filter_map(|e| match e {
            Event::Ixn(_) => Some(e.anchors().iter().filter(|s| matches!(
                s,
                Seal::KeyEvent { i, s: sn, d }
                    if i.as_str() == first.as_str() && sn.value() == 0 && d.as_str() == first.as_str()
            )).count()),
            _ => None,
        })
        .sum::<usize>();
    assert_eq!(vcp_anchors, 1, "exactly one vcp anchor per issuer");

    // Two issuances against the reused registry both validate.
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
        let events = read_credential_tel(issuer.backend.as_ref(), &issuer.prefix, &first, cred)
            .expect("read tel");
        let state = validate_tel(&events).expect("validates");
        assert!(state.is_valid(cred));
    }
}

#[test]
fn kt2_issuer_registry_rejected_typed() {
    use auths_id::identity::initialize::initialize_registry_identity_multi;
    use auths_id::keri::Threshold;

    let backend: Arc<dyn RegistryBackend + Send + Sync> = Arc::new(FakeRegistryBackend::new());
    let keychain = IsolatedKeychainHandle::new();
    let provider = TestPassphraseProvider::new(TEST_PASSPHRASE);
    let alias = KeyAlias::new_unchecked("multisig-issuer");

    let (did, _) = initialize_registry_identity_multi(
        backend.clone(),
        &alias,
        &provider,
        &keychain,
        WitnessParams::Disabled,
        &[CurveType::Ed25519, CurveType::Ed25519],
        Threshold::Simple(2),
        Threshold::Simple(2),
        chrono::Utc::now(),
    )
    .expect("multi-sig inception");
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

    assert!(
        matches!(err, CredentialRegistryError::ThresholdUnsupported { .. }),
        "expected ThresholdUnsupported, got {err:?}"
    );
}
