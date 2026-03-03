use auths_id::ports::registry::RegistryBackend;
use auths_sdk::error::OrgError;
use auths_sdk::workflows::org::{
    AddMemberCommand, RevokeMemberCommand, Role, UpdateCapabilitiesCommand,
    add_organization_member, revoke_organization_member, update_member_capabilities,
};
use auths_test_utils::fakes::clock::MockClock;
use auths_test_utils::fakes::id::DeterministicUuidProvider;
use auths_test_utils::fakes::registry::FakeRegistryBackend;
use auths_verifier::Capability;
use auths_verifier::core::{Attestation, Ed25519PublicKey, Ed25519Signature, ResourceId};
use auths_verifier::types::{DeviceDID, IdentityDID};
use chrono::TimeZone;

const ORG: &str = "ETestOrg0001";
const ADMIN_DID: &str = "did:key:z6MkAdminKey0001";
const MEMBER_DID: &str = "did:key:z6MkMemberKey0001";
const ADMIN_PUBKEY: [u8; 32] = [
    0xAA, 0xBB, 0xCC, 0xDD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0,
];

fn admin_pubkey_hex() -> String {
    hex::encode(ADMIN_PUBKEY)
}

fn org_issuer() -> IdentityDID {
    IdentityDID::new(format!("did:keri:{ORG}"))
}

fn base_admin_attestation() -> Attestation {
    Attestation {
        version: 1,
        rid: ResourceId::new("admin-rid-001"),
        issuer: org_issuer(),
        subject: DeviceDID::new(ADMIN_DID),
        device_public_key: Ed25519PublicKey::from_bytes(ADMIN_PUBKEY),
        identity_signature: Ed25519Signature::empty(),
        device_signature: Ed25519Signature::empty(),
        revoked_at: None,
        expires_at: None,
        timestamp: None,
        note: None,
        payload: None,
        role: Some(Role::Admin),
        capabilities: vec![Capability::sign_commit(), Capability::manage_members()],
        delegated_by: None,
        signer_type: None,
    }
}

fn base_member_attestation() -> Attestation {
    Attestation {
        version: 1,
        rid: ResourceId::new("member-rid-001"),
        issuer: org_issuer(),
        subject: DeviceDID::new(MEMBER_DID),
        device_public_key: Ed25519PublicKey::from_bytes([0u8; 32]),
        identity_signature: Ed25519Signature::empty(),
        device_signature: Ed25519Signature::empty(),
        revoked_at: None,
        expires_at: None,
        timestamp: None,
        note: None,
        payload: None,
        role: Some(Role::Member),
        capabilities: vec![Capability::sign_commit()],
        delegated_by: Some(IdentityDID::new(ADMIN_DID)),
        signer_type: None,
    }
}

fn seed_admin(backend: &FakeRegistryBackend) {
    backend
        .store_org_member(ORG, &base_admin_attestation())
        .expect("seed admin");
}

fn seed_member(backend: &FakeRegistryBackend) {
    backend
        .store_org_member(ORG, &base_member_attestation())
        .expect("seed member");
}

// ── find_admin (tested indirectly via add_organization_member) ────────────────

#[test]
fn find_admin_returns_attestation_when_admin_exists() {
    let backend = FakeRegistryBackend::new();
    seed_admin(&backend);

    // A successful add proves find_admin located the admin.
    let result = add_organization_member(
        &backend,
        &MockClock(chrono::Utc::now()),
        &DeterministicUuidProvider::new(),
        AddMemberCommand {
            org_prefix: ORG.to_string(),
            member_did: MEMBER_DID.to_string(),
            role: Role::Member,
            capabilities: vec![],
            public_key_hex: admin_pubkey_hex(),
        },
    );
    assert!(
        result.is_ok(),
        "expected admin to be found: {:?}",
        result.err()
    );
}

#[test]
fn find_admin_returns_not_found_when_pubkey_mismatch() {
    let backend = FakeRegistryBackend::new();
    seed_admin(&backend);

    let wrong_hex = hex::encode([0x00u8; 4]);
    let result = add_organization_member(
        &backend,
        &MockClock(chrono::Utc::now()),
        &DeterministicUuidProvider::new(),
        AddMemberCommand {
            org_prefix: ORG.to_string(),
            member_did: MEMBER_DID.to_string(),
            role: Role::Member,
            capabilities: vec![],
            public_key_hex: wrong_hex,
        },
    );
    assert!(matches!(result, Err(OrgError::AdminNotFound { .. })));
}

#[test]
fn find_admin_returns_not_found_when_no_manage_members_capability() {
    let backend = FakeRegistryBackend::new();
    let mut att = base_admin_attestation();
    att.capabilities = vec![Capability::sign_commit()];
    backend.store_org_member(ORG, &att).unwrap();

    let result = add_organization_member(
        &backend,
        &MockClock(chrono::Utc::now()),
        &DeterministicUuidProvider::new(),
        AddMemberCommand {
            org_prefix: ORG.to_string(),
            member_did: MEMBER_DID.to_string(),
            role: Role::Member,
            capabilities: vec![],
            public_key_hex: admin_pubkey_hex(),
        },
    );
    assert!(matches!(result, Err(OrgError::AdminNotFound { .. })));
}

// ── add_organization_member ──────────────────────────────────────────────────

#[test]
fn add_member_stores_attestation_with_injected_clock_and_uuid() {
    let backend = FakeRegistryBackend::new();
    seed_admin(&backend);

    let fixed_time = chrono::Utc.with_ymd_and_hms(2025, 6, 1, 0, 0, 0).unwrap();
    let clock = MockClock(fixed_time);
    let id_provider = DeterministicUuidProvider::new();
    // DeterministicUuidProvider starts at 0 → "00000000-0000-0000-0000-000000000000"
    let expected_rid = "00000000-0000-0000-0000-000000000000";

    let result = add_organization_member(
        &backend,
        &clock,
        &id_provider,
        AddMemberCommand {
            org_prefix: ORG.to_string(),
            member_did: MEMBER_DID.to_string(),
            role: Role::Member,
            capabilities: vec!["sign_commit".to_string()],
            public_key_hex: admin_pubkey_hex(),
        },
    );

    assert!(result.is_ok(), "unexpected error: {:?}", result.err());
    let att = result.unwrap();
    assert_eq!(att.timestamp, Some(fixed_time));
    assert_eq!(att.rid, ResourceId::new(expected_rid));
}

#[test]
fn add_member_stores_attestation_with_empty_signatures() {
    let backend = FakeRegistryBackend::new();
    seed_admin(&backend);

    let att = add_organization_member(
        &backend,
        &MockClock(chrono::Utc::now()),
        &DeterministicUuidProvider::new(),
        AddMemberCommand {
            org_prefix: ORG.to_string(),
            member_did: MEMBER_DID.to_string(),
            role: Role::Member,
            capabilities: vec![],
            public_key_hex: admin_pubkey_hex(),
        },
    )
    .expect("add_member failed");

    assert!(att.identity_signature.is_empty());
    assert!(att.device_signature.is_empty());
    assert!(att.device_public_key.is_zero());
}

#[test]
fn add_member_fails_when_admin_not_found() {
    let backend = FakeRegistryBackend::new();

    let result = add_organization_member(
        &backend,
        &MockClock(chrono::Utc::now()),
        &DeterministicUuidProvider::new(),
        AddMemberCommand {
            org_prefix: ORG.to_string(),
            member_did: MEMBER_DID.to_string(),
            role: Role::Member,
            capabilities: vec![],
            public_key_hex: admin_pubkey_hex(),
        },
    );

    assert!(matches!(result, Err(OrgError::AdminNotFound { .. })));
}

#[test]
fn add_member_fails_with_invalid_capability() {
    let backend = FakeRegistryBackend::new();
    seed_admin(&backend);

    let result = add_organization_member(
        &backend,
        &MockClock(chrono::Utc::now()),
        &DeterministicUuidProvider::new(),
        AddMemberCommand {
            org_prefix: ORG.to_string(),
            member_did: MEMBER_DID.to_string(),
            role: Role::Member,
            capabilities: vec!["invalid cap!@#".to_string()],
            public_key_hex: admin_pubkey_hex(),
        },
    );

    assert!(matches!(result, Err(OrgError::InvalidCapability { .. })));
}

// ── revoke_organization_member ───────────────────────────────────────────────

#[test]
fn revoke_member_sets_revoked_at_to_injected_clock_value() {
    let backend = FakeRegistryBackend::new();
    seed_admin(&backend);
    seed_member(&backend);

    let fixed_time = chrono::Utc.with_ymd_and_hms(2025, 6, 2, 12, 0, 0).unwrap();

    let result = revoke_organization_member(
        &backend,
        &MockClock(fixed_time),
        RevokeMemberCommand {
            org_prefix: ORG.to_string(),
            member_did: MEMBER_DID.to_string(),
            public_key_hex: admin_pubkey_hex(),
        },
    );

    assert!(result.is_ok(), "unexpected error: {:?}", result.err());
    let att = result.unwrap();
    assert_eq!(att.revoked_at, Some(fixed_time));
    assert!(att.is_revoked());
}

#[test]
fn revoke_member_fails_when_member_not_found() {
    let backend = FakeRegistryBackend::new();
    seed_admin(&backend);

    let result = revoke_organization_member(
        &backend,
        &MockClock(chrono::Utc::now()),
        RevokeMemberCommand {
            org_prefix: ORG.to_string(),
            member_did: "did:key:z6MkNonexistent".to_string(),
            public_key_hex: admin_pubkey_hex(),
        },
    );

    assert!(matches!(result, Err(OrgError::MemberNotFound { .. })));
}

#[test]
fn revoke_member_fails_when_already_revoked() {
    let backend = FakeRegistryBackend::new();
    seed_admin(&backend);

    let mut att = base_member_attestation();
    att.revoked_at = Some(chrono::Utc::now());
    backend.store_org_member(ORG, &att).unwrap();

    let result = revoke_organization_member(
        &backend,
        &MockClock(chrono::Utc::now()),
        RevokeMemberCommand {
            org_prefix: ORG.to_string(),
            member_did: MEMBER_DID.to_string(),
            public_key_hex: admin_pubkey_hex(),
        },
    );

    assert!(matches!(result, Err(OrgError::AlreadyRevoked { .. })));
}

// ── update_member_capabilities ───────────────────────────────────────────────

#[test]
fn update_capabilities_stores_new_capabilities() {
    let backend = FakeRegistryBackend::new();
    seed_admin(&backend);
    seed_member(&backend);

    let result = update_member_capabilities(
        &backend,
        &MockClock(chrono::Utc::now()),
        UpdateCapabilitiesCommand {
            org_prefix: ORG.to_string(),
            member_did: MEMBER_DID.to_string(),
            capabilities: vec!["sign_commit".to_string(), "sign_release".to_string()],
            public_key_hex: admin_pubkey_hex(),
        },
    );

    assert!(result.is_ok(), "unexpected error: {:?}", result.err());
    let att = result.unwrap();
    assert_eq!(att.capabilities.len(), 2);
    assert!(att.capabilities.contains(&Capability::sign_commit()));
    assert!(att.capabilities.contains(&Capability::sign_release()));
}

#[test]
fn update_capabilities_fails_with_invalid_capability() {
    let backend = FakeRegistryBackend::new();
    seed_admin(&backend);
    seed_member(&backend);

    let result = update_member_capabilities(
        &backend,
        &MockClock(chrono::Utc::now()),
        UpdateCapabilitiesCommand {
            org_prefix: ORG.to_string(),
            member_did: MEMBER_DID.to_string(),
            capabilities: vec!["invalid cap!@#".to_string()],
            public_key_hex: admin_pubkey_hex(),
        },
    );

    assert!(matches!(result, Err(OrgError::InvalidCapability { .. })));
}
