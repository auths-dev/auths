//! Device attestation store/load/history, device enumeration, and staleness.

use std::ops::ControlFlow;

use auths_id::ports::RegistryBackend;
use auths_id::ports::registry::RegistryError;
use auths_verifier::AttestationBuilder;
use auths_verifier::types::CanonicalDid;
use chrono::{Duration, Utc};

use super::support;

#[test]
fn store_load_history_and_devices() {
    let Some(backend) = support::setup() else {
        return;
    };

    let subject = "did:key:zAttDevice1111";
    let did = CanonicalDid::parse(subject).unwrap();
    let t1 = Utc::now();

    let att1 = AttestationBuilder::default()
        .rid("att-1")
        .issuer("did:keri:Eissuer0001")
        .subject(subject)
        .timestamp(Some(t1))
        .build();
    backend.store_attestation(&att1).unwrap();

    assert!(backend.load_attestation(&did).unwrap().is_some());

    // A strictly newer attestation supersedes as the current view.
    let att2 = AttestationBuilder::default()
        .rid("att-2")
        .issuer("did:keri:Eissuer0001")
        .subject(subject)
        .timestamp(Some(t1 + Duration::seconds(5)))
        .build();
    backend.store_attestation(&att2).unwrap();

    assert_eq!(
        backend
            .load_attestation(&did)
            .unwrap()
            .unwrap()
            .rid
            .to_string(),
        "att-2"
    );

    // History is append-only and chronological (oldest first).
    let mut history = Vec::new();
    backend
        .visit_attestation_history(&did, &mut |a| {
            history.push(a.rid.to_string());
            ControlFlow::Continue(())
        })
        .unwrap();
    assert_eq!(history, vec!["att-1".to_string(), "att-2".to_string()]);

    // Device enumeration surfaces the subject.
    let mut devices = Vec::new();
    backend
        .visit_devices(&mut |d| {
            devices.push(d.as_str().to_string());
            ControlFlow::Continue(())
        })
        .unwrap();
    assert!(devices.contains(&subject.to_string()));
}

#[test]
fn stale_attestation_is_rejected() {
    let Some(backend) = support::setup() else {
        return;
    };

    let subject = "did:key:zStaleDevice22";
    let now = Utc::now();

    let current = AttestationBuilder::default()
        .rid("cur")
        .issuer("did:keri:Eissuer0002")
        .subject(subject)
        .timestamp(Some(now))
        .build();
    backend.store_attestation(&current).unwrap();

    // An older timestamp is a replay and must be refused.
    let stale = AttestationBuilder::default()
        .rid("old")
        .issuer("did:keri:Eissuer0002")
        .subject(subject)
        .timestamp(Some(now - Duration::hours(1)))
        .build();
    let err = backend.store_attestation(&stale).unwrap_err();
    assert!(
        matches!(err, RegistryError::StaleAttestation(_)),
        "expected StaleAttestation, got {err:?}"
    );
}

#[test]
fn load_missing_attestation_is_none() {
    let Some(backend) = support::setup() else {
        return;
    };
    let did = CanonicalDid::parse("did:key:zNeverStored99").unwrap();
    assert!(backend.load_attestation(&did).unwrap().is_none());
}
