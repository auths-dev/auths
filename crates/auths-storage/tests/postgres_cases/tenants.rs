//! Tenant lifecycle: init idempotency, metadata gating, and per-tenant counts.

use auths_id::ports::RegistryBackend;

use super::support;

#[test]
fn init_if_needed_is_idempotent() {
    let Some(backend) = support::connect_only() else {
        return;
    };

    // First provisioning inserts the tenant row.
    assert!(backend.init_if_needed().unwrap());
    // Subsequent calls are no-ops.
    assert!(!backend.init_if_needed().unwrap());
    assert!(!backend.init_if_needed().unwrap());
}

#[test]
fn metadata_requires_initialization() {
    let Some(backend) = support::connect_only() else {
        return;
    };

    // Before init the (unprovisioned) tenant has no metadata.
    let err = backend.metadata().unwrap_err();
    assert!(
        matches!(
            err,
            auths_id::ports::registry::RegistryError::NotFound { .. }
        ),
        "expected NotFound before init, got {err:?}"
    );

    backend.init_if_needed().unwrap();
    let meta = backend.metadata().unwrap();
    assert_eq!(meta.identity_count, 0);
    assert_eq!(meta.device_count, 0);
    assert_eq!(meta.member_count, 0);
}

#[test]
fn metadata_counts_reflect_writes() {
    let Some(backend) = support::setup() else {
        return;
    };

    let (icp, prefix, _kp) = support::make_signed_icp();
    backend.append_event(&prefix, &icp).unwrap();

    let subject = "did:key:zMetaDevice0001";
    let att = auths_verifier::AttestationBuilder::default()
        .rid("meta")
        .issuer("did:keri:EmetaIssuer0001")
        .subject(subject)
        .build();
    backend.store_attestation(&att).unwrap();

    let meta = backend.metadata().unwrap();
    assert_eq!(meta.identity_count, 1);
    assert_eq!(meta.device_count, 1);
}

#[test]
fn tenants_are_isolated() {
    let Some(a) = support::setup() else {
        return;
    };
    let Some(b) = support::setup() else {
        return;
    };

    // Two adapters, two distinct tenants: a write to one is invisible to the other.
    let (icp, prefix, _kp) = support::make_signed_icp();
    a.append_event(&prefix, &icp).unwrap();

    assert_eq!(a.metadata().unwrap().identity_count, 1);
    assert_eq!(b.metadata().unwrap().identity_count, 0);
    assert!(b.get_tip(&prefix).is_err());
}
