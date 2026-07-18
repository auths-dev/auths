//! Org member store + validation-aware enumeration.

use std::ops::ControlFlow;

use auths_id::ports::RegistryBackend;
use auths_id::storage::registry::org_member::OrgMemberEntry;
use auths_verifier::AttestationBuilder;

use super::support;

fn collect(backend: &impl RegistryBackend, org: &str) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    backend
        .visit_org_member_attestations(org, &mut |e: &OrgMemberEntry| {
            out.push((e.did.as_str().to_string(), e.attestation.is_ok()));
            ControlFlow::Continue(())
        })
        .unwrap();
    out
}

#[test]
fn store_and_visit_org_member() {
    let Some(backend) = support::setup() else {
        return;
    };

    let org = "EorgMembers000001";
    let member = "did:key:zOrgMember0001";
    let issuer = format!("did:keri:{org}");

    let att = AttestationBuilder::default()
        .rid("member-1")
        .issuer(&issuer)
        .subject(member)
        .build();
    backend.store_org_member(org, &att).unwrap();

    let entries = collect(&backend, org);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0, member);
    assert!(entries[0].1, "member with matching issuer should be valid");
}

#[test]
fn store_org_member_is_latest_view() {
    let Some(backend) = support::setup() else {
        return;
    };

    let org = "EorgMembers000002";
    let member = "did:key:zOrgMember0002";
    let issuer = format!("did:keri:{org}");

    let att1 = AttestationBuilder::default()
        .rid("v1")
        .issuer(&issuer)
        .subject(member)
        .build();
    backend.store_org_member(org, &att1).unwrap();

    let att2 = AttestationBuilder::default()
        .rid("v2")
        .issuer(&issuer)
        .subject(member)
        .build();
    backend.store_org_member(org, &att2).unwrap();

    // Latest-view: the same member DID is overwritten, not duplicated.
    let entries = collect(&backend, org);
    assert_eq!(entries.len(), 1);
}

#[test]
fn mismatched_issuer_is_surfaced_invalid() {
    let Some(backend) = support::setup() else {
        return;
    };

    let org = "EorgMembers000003";
    let member = "did:key:zOrgMember0003";
    // Issuer is a valid did:keri: but not this org's issuer.
    let att = AttestationBuilder::default()
        .rid("bad-issuer")
        .issuer("did:keri:EsomeOtherOrg99")
        .subject(member)
        .build();
    backend.store_org_member(org, &att).unwrap();

    let entries = collect(&backend, org);
    assert_eq!(entries.len(), 1);
    assert!(!entries[0].1, "issuer mismatch should be an invalid entry");
}
