//! Credential registry over the Git-backed `GitRegistryBackend`.
//!
//! The same F.3 flow exercised against the in-memory fake in
//! `auths-id/tests/cases/credential_registry.rs`, here proving the Git backend
//! persists TEL events + ACDC blobs and anchors `vcp`/`iss` to a *real, signed*
//! issuer KEL atomically (one commit per `anchor_tel_event`).

use std::ops::ControlFlow;
use std::sync::Arc;

use auths_core::storage::keychain::{IdentityDID, KeyAlias, sign_with_key};
use auths_core::testing::{IsolatedKeychainHandle, TestPassphraseProvider};
use auths_crypto::CurveType;
use auths_id::identity::initialize::{
    initialize_registry_identity, initialize_registry_identity_multi,
};
use auths_id::keri::credential_registry::{
    CredentialRegistryError, anchor_tel_event, build_iss, ensure_registry, find_registry,
    read_credential_tel,
};
use auths_id::keri::sync::{
    KelCaps, RegistryMergeError, merge_credentials_and_tel, merge_registries,
};
use auths_id::keri::types::Prefix;
use auths_id::keri::{Event, Said, Seal, Threshold};
use auths_id::ports::registry::RegistryBackend;
use auths_id::witness_config::WitnessParams;
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
        WitnessParams::Disabled,
        CurveType::Ed25519,
        chrono::Utc::now(),
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

    /// Issue a credential whose stored blob is the production envelope
    /// `{acdc, signature}` — the issuer's real detached signature over
    /// `acdc.to_wire_bytes()`, matching `auths credential issue`. Returns the
    /// credential SAID.
    fn issue_signed(&self, registry: &Said, subject: &str) -> Said {
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

        let wire = acdc.to_wire_bytes().unwrap();
        let (signature, _pk, _curve) =
            sign_with_key(&self.keychain, &self.alias, &self.provider, &wire).unwrap();
        // The on-disk envelope (`StoredCredential` lives in auths-sdk, above this
        // crate): `{ "acdc": {…}, "signature": [u8…] }`.
        let blob = serde_json::json!({ "acdc": acdc, "signature": signature });
        let blob_bytes = serde_json::to_vec(&blob).unwrap();

        let iss = build_iss(&cred, &reg, DT.to_string()).unwrap();
        anchor_tel_event(
            self.backend.as_ref(),
            &self.prefix,
            &self.alias,
            CurveType::Ed25519,
            &TelEvent::Iss(iss),
            Some((cred.clone(), blob_bytes)),
            &self.provider,
            &self.keychain,
        )
        .unwrap();
        cred
    }
}

/// A fresh, empty destination registry on a throwaway disk (a "cold machine").
fn cold_registry() -> (Arc<dyn RegistryBackend + Send + Sync>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let backend: Arc<dyn RegistryBackend + Send + Sync> = Arc::new(
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(dir.path())),
    );
    backend.init_if_needed().unwrap();
    (backend, dir)
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
        WitnessParams::Disabled,
        &[CurveType::Ed25519, CurveType::Ed25519],
        Threshold::Simple(2),
        Threshold::Simple(2),
        chrono::Utc::now(),
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

// ── full-fleet cold import: credentials + TEL ride the authenticated KEL ──────

const CAPS: KelCaps = KelCaps {
    max_events: 10_000,
    max_bytes: 4 * 1024 * 1024,
};

/// The whole-fleet pull: after the KEL merge authenticates the issuer's KEL, the
/// credential body AND its TEL chain materialize on a cold registry, so a cold
/// machine can read back exactly what the issuer issued.
#[test]
fn cold_import_reconstructs_credentials_and_tel() {
    let issuer = setup_git_issuer();
    let registry = issuer.ensure_registry().unwrap();
    let credential = issuer.issue_signed(&registry, SUBJECT);

    let (cold, _cold_dir) = cold_registry();

    // 1. KEL merge (the authenticated trust core).
    let merged = merge_registries(issuer.backend.as_ref(), cold.as_ref(), &CAPS).unwrap();
    let authenticated = merged.iter().map(|m| m.prefix.clone()).collect();

    // Before the artifact import, the cold machine has the KEL but NOT the body.
    assert!(
        cold.load_credential(&issuer.prefix, &credential)
            .unwrap()
            .is_none(),
        "KEL merge alone must not materialize the credential body"
    );

    // 2. Credential + TEL import.
    let report =
        merge_credentials_and_tel(issuer.backend.as_ref(), cold.as_ref(), &authenticated).unwrap();
    assert_eq!(report.credentials_imported, 1);
    assert_eq!(report.tel_events_imported, 2, "vcp + iss");

    // The credential body is present and byte-identical to the source.
    let cold_blob = cold
        .load_credential(&issuer.prefix, &credential)
        .unwrap()
        .expect("credential body must materialize on the cold machine");
    let src_blob = issuer
        .backend
        .load_credential(&issuer.prefix, &credential)
        .unwrap()
        .unwrap();
    assert_eq!(cold_blob, src_blob);

    // The TEL re-reads as a valid vcp→iss chain that proves the credential issued.
    let tel = read_credential_tel(cold.as_ref(), &issuer.prefix, &registry, &credential).unwrap();
    assert!(matches!(
        tel.as_slice(),
        [TelEvent::Vcp(_), TelEvent::Iss(_)]
    ));
    assert!(validate_tel(&tel).unwrap().is_valid(&credential));

    // Re-importing changes nothing — the artifact merge is idempotent.
    let again =
        merge_credentials_and_tel(issuer.backend.as_ref(), cold.as_ref(), &authenticated).unwrap();
    assert_eq!(again.credentials_imported, 0);
    assert_eq!(again.credentials_already_present, 1);
    assert_eq!(again.tel_events_imported, 0);
    assert_eq!(again.tel_events_already_present, 2);
}

/// A credential whose issuer was NOT authenticated in the KEL merge is never
/// imported — a dangling artifact has no anchoring identity.
#[test]
fn cold_import_refuses_orphan_credential() {
    let issuer = setup_git_issuer();
    let registry = issuer.ensure_registry().unwrap();
    let _credential = issuer.issue_signed(&registry, SUBJECT);

    let (cold, _cold_dir) = cold_registry();
    // Empty authenticated set: no issuer's KEL was merged.
    let empty = std::collections::HashSet::new();
    let err =
        merge_credentials_and_tel(issuer.backend.as_ref(), cold.as_ref(), &empty).unwrap_err();
    assert!(
        matches!(err, RegistryMergeError::CredentialOrphan { .. }),
        "an unanchored credential must be refused, got {err:?}"
    );
}

/// A byte-flipped credential body is refused on import (its recomputed SAID no
/// longer matches the SAID-addressed path) — the import never copies a tampered
/// body onto the cold machine.
#[test]
fn cold_import_refuses_tampered_credential_body() {
    let issuer = setup_git_issuer();
    let registry = issuer.ensure_registry().unwrap();
    let credential = issuer.issue_signed(&registry, SUBJECT);

    // The source we hand the merge is a poisoned snapshot: same path/SAID, but the
    // stored ACDC body has one attribute mutated so it no longer recomputes.
    let poisoned = PoisonedSource {
        inner: issuer.backend.clone(),
        target: credential.clone(),
        tamper: Tamper::CredentialBody,
    };

    let (cold, _cold_dir) = cold_registry();
    let merged = merge_registries(&poisoned, cold.as_ref(), &CAPS).unwrap();
    let authenticated = merged.iter().map(|m| m.prefix.clone()).collect();

    let err = merge_credentials_and_tel(&poisoned, cold.as_ref(), &authenticated).unwrap_err();
    assert!(
        matches!(err, RegistryMergeError::CredentialRefused { .. }),
        "a tampered credential body must be refused, got {err:?}"
    );
    assert!(
        cold.load_credential(&issuer.prefix, &credential)
            .unwrap()
            .is_none(),
        "a refused credential must NOT land on the cold machine"
    );
}

/// A byte-flipped TEL event is refused on import (validate_tel rejects the
/// mismatched event SAID) — a tampered status log never materializes cold.
#[test]
fn cold_import_refuses_tampered_tel_event() {
    let issuer = setup_git_issuer();
    let registry = issuer.ensure_registry().unwrap();
    let credential = issuer.issue_signed(&registry, SUBJECT);

    let poisoned = PoisonedSource {
        inner: issuer.backend.clone(),
        target: credential.clone(),
        tamper: Tamper::TelEvent,
    };

    let (cold, _cold_dir) = cold_registry();
    let merged = merge_registries(&poisoned, cold.as_ref(), &CAPS).unwrap();
    let authenticated = merged.iter().map(|m| m.prefix.clone()).collect();

    let err = merge_credentials_and_tel(&poisoned, cold.as_ref(), &authenticated).unwrap_err();
    assert!(
        matches!(err, RegistryMergeError::TelRefused { .. }),
        "a tampered TEL event must be refused, got {err:?}"
    );
    let _ = registry;
}

/// Which artifact a [`PoisonedSource`] corrupts as it is read.
#[derive(Clone, Copy)]
enum Tamper {
    /// Flip a byte in the credential body's stored attributes.
    CredentialBody,
    /// Flip a byte in the credential's `iss` TEL event.
    TelEvent,
}

/// A read-through registry that corrupts ONE artifact for the target credential
/// as it is served — modeling a hostile / bit-rotted export carrier. Everything
/// else (KELs, attachments, other coordinates) passes through verbatim, so the
/// KEL merge still authenticates the issuer and only the poisoned artifact is
/// exercised against the import guards.
struct PoisonedSource {
    inner: Arc<dyn RegistryBackend + Send + Sync>,
    target: Said,
    tamper: Tamper,
}

impl PoisonedSource {
    fn corrupt(mut bytes: Vec<u8>) -> Vec<u8> {
        // Flip an alphanumeric byte near the middle (a value char, not structure).
        if let Some(i) = (bytes.len() / 2..bytes.len())
            .chain(0..bytes.len())
            .find(|&i| bytes[i].is_ascii_alphanumeric())
        {
            bytes[i] = if bytes[i] == b'A' { b'B' } else { b'A' };
        }
        bytes
    }
}

impl RegistryBackend for PoisonedSource {
    fn append_event(
        &self,
        prefix: &Prefix,
        event: &Event,
    ) -> Result<(), auths_id::ports::registry::RegistryError> {
        self.inner.append_event(prefix, event)
    }
    fn append_signed_event(
        &self,
        prefix: &Prefix,
        event: &Event,
        attachment: &[u8],
    ) -> Result<(), auths_id::ports::registry::RegistryError> {
        self.inner.append_signed_event(prefix, event, attachment)
    }
    fn get_attachment(
        &self,
        prefix: &Prefix,
        seq: u128,
    ) -> Result<Option<Vec<u8>>, auths_id::ports::registry::RegistryError> {
        self.inner.get_attachment(prefix, seq)
    }
    fn get_event(
        &self,
        prefix: &Prefix,
        seq: u128,
    ) -> Result<Event, auths_id::ports::registry::RegistryError> {
        self.inner.get_event(prefix, seq)
    }
    fn visit_events(
        &self,
        prefix: &Prefix,
        from_seq: u128,
        visitor: &mut dyn FnMut(&Event) -> ControlFlow<()>,
    ) -> Result<(), auths_id::ports::registry::RegistryError> {
        self.inner.visit_events(prefix, from_seq, visitor)
    }
    fn get_tip(
        &self,
        prefix: &Prefix,
    ) -> Result<auths_id::ports::registry::TipInfo, auths_id::ports::registry::RegistryError> {
        self.inner.get_tip(prefix)
    }
    fn get_key_state(
        &self,
        prefix: &Prefix,
    ) -> Result<auths_id::keri::state::KeyState, auths_id::ports::registry::RegistryError> {
        self.inner.get_key_state(prefix)
    }
    fn write_key_state(
        &self,
        prefix: &Prefix,
        state: &auths_id::keri::state::KeyState,
    ) -> Result<(), auths_id::ports::registry::RegistryError> {
        self.inner.write_key_state(prefix, state)
    }
    fn visit_identities(
        &self,
        visitor: &mut dyn FnMut(&str) -> ControlFlow<()>,
    ) -> Result<(), auths_id::ports::registry::RegistryError> {
        self.inner.visit_identities(visitor)
    }
    fn store_attestation(
        &self,
        attestation: &auths_verifier::core::Attestation,
    ) -> Result<(), auths_id::ports::registry::RegistryError> {
        self.inner.store_attestation(attestation)
    }
    fn load_attestation(
        &self,
        did: &auths_verifier::types::CanonicalDid,
    ) -> Result<Option<auths_verifier::core::Attestation>, auths_id::ports::registry::RegistryError>
    {
        self.inner.load_attestation(did)
    }
    fn visit_attestation_history(
        &self,
        did: &auths_verifier::types::CanonicalDid,
        visitor: &mut dyn FnMut(&auths_verifier::core::Attestation) -> ControlFlow<()>,
    ) -> Result<(), auths_id::ports::registry::RegistryError> {
        self.inner.visit_attestation_history(did, visitor)
    }
    fn visit_devices(
        &self,
        visitor: &mut dyn FnMut(&auths_verifier::types::CanonicalDid) -> ControlFlow<()>,
    ) -> Result<(), auths_id::ports::registry::RegistryError> {
        self.inner.visit_devices(visitor)
    }
    fn store_org_member(
        &self,
        org: &str,
        member: &auths_verifier::core::Attestation,
    ) -> Result<(), auths_id::ports::registry::RegistryError> {
        self.inner.store_org_member(org, member)
    }
    fn visit_org_member_attestations(
        &self,
        org: &str,
        visitor: &mut dyn FnMut(&auths_id::ports::registry::OrgMemberEntry) -> ControlFlow<()>,
    ) -> Result<(), auths_id::ports::registry::RegistryError> {
        self.inner.visit_org_member_attestations(org, visitor)
    }
    fn init_if_needed(&self) -> Result<bool, auths_id::ports::registry::RegistryError> {
        self.inner.init_if_needed()
    }
    fn metadata(
        &self,
    ) -> Result<auths_id::ports::registry::RegistryMetadata, auths_id::ports::registry::RegistryError>
    {
        self.inner.metadata()
    }
    fn append_tel_event(
        &self,
        issuer: &Prefix,
        registry_said: &Said,
        credential_said: &Said,
        sn: u128,
        event_bytes: &[u8],
    ) -> Result<(), auths_id::ports::registry::RegistryError> {
        self.inner
            .append_tel_event(issuer, registry_said, credential_said, sn, event_bytes)
    }
    fn visit_tel_events(
        &self,
        issuer: &Prefix,
        registry_said: &Said,
        credential_said: &Said,
        visitor: &mut dyn FnMut(&[u8]) -> ControlFlow<()>,
    ) -> Result<(), auths_id::ports::registry::RegistryError> {
        let corrupt = matches!(self.tamper, Tamper::TelEvent)
            && credential_said.as_str() == self.target.as_str();
        if !corrupt {
            return self
                .inner
                .visit_tel_events(issuer, registry_said, credential_said, visitor);
        }
        let mut wrapped = |bytes: &[u8]| visitor(&Self::corrupt(bytes.to_vec()));
        self.inner
            .visit_tel_events(issuer, registry_said, credential_said, &mut wrapped)
    }
    fn store_credential(
        &self,
        issuer: &Prefix,
        credential_said: &Said,
        credential_bytes: &[u8],
    ) -> Result<(), auths_id::ports::registry::RegistryError> {
        self.inner
            .store_credential(issuer, credential_said, credential_bytes)
    }
    fn load_credential(
        &self,
        issuer: &Prefix,
        credential_said: &Said,
    ) -> Result<Option<Vec<u8>>, auths_id::ports::registry::RegistryError> {
        self.inner.load_credential(issuer, credential_said)
    }
    fn visit_credentials(
        &self,
        visitor: &mut auths_id::ports::registry::CredentialVisitor<'_>,
    ) -> Result<(), auths_id::ports::registry::RegistryError> {
        let tamper = self.tamper;
        let target = self.target.clone();
        let mut wrapped = |issuer: &Prefix, cred: &Said, bytes: &[u8]| {
            if matches!(tamper, Tamper::CredentialBody) && cred.as_str() == target.as_str() {
                visitor(issuer, cred, &Self::corrupt(bytes.to_vec()))
            } else {
                visitor(issuer, cred, bytes)
            }
        };
        self.inner.visit_credentials(&mut wrapped)
    }
    fn visit_tel_registries(
        &self,
        visitor: &mut auths_id::ports::registry::TelRegistryVisitor<'_>,
    ) -> Result<(), auths_id::ports::registry::RegistryError> {
        self.inner.visit_tel_registries(visitor)
    }
}
