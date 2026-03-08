use auths_core::AgentError;
use auths_core::ports::id::UuidProvider;
use auths_core::signing::{PassphraseProvider, SecureSigner};
use auths_core::storage::keychain::KeyAlias;
use auths_core::testing::DeterministicUuidProvider;
use auths_id::ports::registry::RegistryBackend;
use auths_id::testing::fakes::FakeRegistryBackend;
use auths_sdk::error::OrgError;
use auths_sdk::workflows::org::{
    AddMemberCommand, OrgContext, RevokeMemberCommand, Role, UpdateCapabilitiesCommand,
    add_organization_member, revoke_organization_member, update_member_capabilities,
};
use auths_verifier::Capability;
use auths_verifier::clock::ClockProvider;
use auths_verifier::core::{Attestation, Ed25519PublicKey, Ed25519Signature, ResourceId};
use auths_verifier::testing::MockClock;
use auths_verifier::types::{DeviceDID, IdentityDID};
use chrono::TimeZone;

const ORG: &str = "ETestOrg0001";
const ADMIN_DID: &str = "did:key:z6MkAdminKey0001";
const MEMBER_DID: &str = "did:key:z6MkMemberKey0001";
const ADMIN_PUBKEY: [u8; 32] = [
    0xAA, 0xBB, 0xCC, 0xDD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0,
];
const MEMBER_PUBKEY: [u8; 32] = [
    0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0,
];

fn admin_pubkey_hex() -> String {
    hex::encode(ADMIN_PUBKEY)
}

fn org_issuer() -> IdentityDID {
    IdentityDID::new(format!("did:keri:{ORG}"))
}

struct FakeSecureSigner;

impl SecureSigner for FakeSecureSigner {
    fn sign_with_alias(
        &self,
        _alias: &KeyAlias,
        _passphrase_provider: &dyn PassphraseProvider,
        _message: &[u8],
    ) -> Result<Vec<u8>, AgentError> {
        Ok(vec![0u8; 64])
    }

    fn sign_for_identity(
        &self,
        _identity_did: &auths_core::storage::keychain::IdentityDID,
        _passphrase_provider: &dyn PassphraseProvider,
        _message: &[u8],
    ) -> Result<Vec<u8>, AgentError> {
        Ok(vec![0u8; 64])
    }
}

struct FakePassphraseProvider;

impl PassphraseProvider for FakePassphraseProvider {
    fn get_passphrase(&self, _prompt: &str) -> Result<zeroize::Zeroizing<String>, AgentError> {
        Ok(zeroize::Zeroizing::new("test".to_string()))
    }
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
        environment_claim: None,
    }
}

fn base_member_attestation() -> Attestation {
    Attestation {
        version: 1,
        rid: ResourceId::new("member-rid-001"),
        issuer: org_issuer(),
        subject: DeviceDID::new(MEMBER_DID),
        device_public_key: Ed25519PublicKey::from_bytes(MEMBER_PUBKEY),
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
        environment_claim: None,
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

fn make_ctx<'a>(
    backend: &'a dyn RegistryBackend,
    clock: &'a dyn ClockProvider,
    uuid_provider: &'a dyn UuidProvider,
    signer: &'a dyn SecureSigner,
    passphrase_provider: &'a dyn PassphraseProvider,
) -> OrgContext<'a> {
    OrgContext {
        registry: backend,
        clock,
        uuid_provider,
        signer,
        passphrase_provider,
    }
}

// ── find_admin (tested indirectly via add_organization_member) ────────────────

#[test]
fn find_admin_returns_attestation_when_admin_exists() {
    let backend = FakeRegistryBackend::new();
    seed_admin(&backend);
    let signer = FakeSecureSigner;
    let pp = FakePassphraseProvider;
    let uuid = DeterministicUuidProvider::new();
    let clock = MockClock(chrono::Utc::now());
    let ctx = make_ctx(&backend, &clock, &uuid, &signer, &pp);

    let result = add_organization_member(
        &ctx,
        AddMemberCommand {
            org_prefix: ORG.to_string(),
            member_did: MEMBER_DID.to_string(),
            member_public_key: Ed25519PublicKey::from_bytes(MEMBER_PUBKEY),
            role: Role::Member,
            capabilities: vec![],
            admin_public_key_hex: admin_pubkey_hex(),
            signer_alias: KeyAlias::new_unchecked("test-alias"),
            note: None,
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
    let signer = FakeSecureSigner;
    let pp = FakePassphraseProvider;
    let uuid = DeterministicUuidProvider::new();
    let clock = MockClock(chrono::Utc::now());
    let ctx = make_ctx(&backend, &clock, &uuid, &signer, &pp);

    let wrong_hex = hex::encode([0x00u8; 4]);
    let result = add_organization_member(
        &ctx,
        AddMemberCommand {
            org_prefix: ORG.to_string(),
            member_did: MEMBER_DID.to_string(),
            member_public_key: Ed25519PublicKey::from_bytes(MEMBER_PUBKEY),
            role: Role::Member,
            capabilities: vec![],
            admin_public_key_hex: wrong_hex,
            signer_alias: KeyAlias::new_unchecked("test-alias"),
            note: None,
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

    let signer = FakeSecureSigner;
    let pp = FakePassphraseProvider;
    let uuid = DeterministicUuidProvider::new();
    let clock = MockClock(chrono::Utc::now());
    let ctx = make_ctx(&backend, &clock, &uuid, &signer, &pp);

    let result = add_organization_member(
        &ctx,
        AddMemberCommand {
            org_prefix: ORG.to_string(),
            member_did: MEMBER_DID.to_string(),
            member_public_key: Ed25519PublicKey::from_bytes(MEMBER_PUBKEY),
            role: Role::Member,
            capabilities: vec![],
            admin_public_key_hex: admin_pubkey_hex(),
            signer_alias: KeyAlias::new_unchecked("test-alias"),
            note: None,
        },
    );
    assert!(matches!(result, Err(OrgError::AdminNotFound { .. })));
}

// ── add_organization_member ──────────────────────────────────────────────────

#[test]
fn add_member_stores_signed_attestation_with_injected_clock_and_uuid() {
    let backend = FakeRegistryBackend::new();
    seed_admin(&backend);

    let fixed_time = chrono::Utc.with_ymd_and_hms(2025, 6, 1, 0, 0, 0).unwrap();
    let clock = MockClock(fixed_time);
    let id_provider = DeterministicUuidProvider::new();
    let expected_rid = "00000000-0000-0000-0000-000000000000";
    let signer = FakeSecureSigner;
    let pp = FakePassphraseProvider;
    let ctx = make_ctx(&backend, &clock, &id_provider, &signer, &pp);

    let result = add_organization_member(
        &ctx,
        AddMemberCommand {
            org_prefix: ORG.to_string(),
            member_did: MEMBER_DID.to_string(),
            member_public_key: Ed25519PublicKey::from_bytes(MEMBER_PUBKEY),
            role: Role::Member,
            capabilities: vec!["sign_commit".to_string()],
            admin_public_key_hex: admin_pubkey_hex(),
            signer_alias: KeyAlias::new_unchecked("test-alias"),
            note: None,
        },
    );

    assert!(result.is_ok(), "unexpected error: {:?}", result.err());
    let att = result.unwrap();
    assert_eq!(att.timestamp, Some(fixed_time));
    assert_eq!(att.rid, ResourceId::new(expected_rid));
}

#[test]
fn add_member_creates_attestation_with_signatures() {
    let backend = FakeRegistryBackend::new();
    seed_admin(&backend);

    let signer = FakeSecureSigner;
    let pp = FakePassphraseProvider;
    let uuid = DeterministicUuidProvider::new();
    let clock = MockClock(chrono::Utc::now());
    let ctx = make_ctx(&backend, &clock, &uuid, &signer, &pp);

    let att = add_organization_member(
        &ctx,
        AddMemberCommand {
            org_prefix: ORG.to_string(),
            member_did: MEMBER_DID.to_string(),
            member_public_key: Ed25519PublicKey::from_bytes(MEMBER_PUBKEY),
            role: Role::Member,
            capabilities: vec![],
            admin_public_key_hex: admin_pubkey_hex(),
            signer_alias: KeyAlias::new_unchecked("test-alias"),
            note: None,
        },
    )
    .expect("add_member failed");

    // With signed attestations, the identity_signature should not be empty
    assert!(!att.identity_signature.is_empty());
    assert_eq!(
        att.device_public_key,
        Ed25519PublicKey::from_bytes(MEMBER_PUBKEY)
    );
}

#[test]
fn add_member_fails_when_admin_not_found() {
    let backend = FakeRegistryBackend::new();
    let signer = FakeSecureSigner;
    let pp = FakePassphraseProvider;
    let uuid = DeterministicUuidProvider::new();
    let clock = MockClock(chrono::Utc::now());
    let ctx = make_ctx(&backend, &clock, &uuid, &signer, &pp);

    let result = add_organization_member(
        &ctx,
        AddMemberCommand {
            org_prefix: ORG.to_string(),
            member_did: MEMBER_DID.to_string(),
            member_public_key: Ed25519PublicKey::from_bytes(MEMBER_PUBKEY),
            role: Role::Member,
            capabilities: vec![],
            admin_public_key_hex: admin_pubkey_hex(),
            signer_alias: KeyAlias::new_unchecked("test-alias"),
            note: None,
        },
    );

    assert!(matches!(result, Err(OrgError::AdminNotFound { .. })));
}

#[test]
fn add_member_fails_with_invalid_capability() {
    let backend = FakeRegistryBackend::new();
    seed_admin(&backend);
    let signer = FakeSecureSigner;
    let pp = FakePassphraseProvider;
    let uuid = DeterministicUuidProvider::new();
    let clock = MockClock(chrono::Utc::now());
    let ctx = make_ctx(&backend, &clock, &uuid, &signer, &pp);

    let result = add_organization_member(
        &ctx,
        AddMemberCommand {
            org_prefix: ORG.to_string(),
            member_did: MEMBER_DID.to_string(),
            member_public_key: Ed25519PublicKey::from_bytes(MEMBER_PUBKEY),
            role: Role::Member,
            capabilities: vec!["invalid cap!@#".to_string()],
            admin_public_key_hex: admin_pubkey_hex(),
            signer_alias: KeyAlias::new_unchecked("test-alias"),
            note: None,
        },
    );

    assert!(matches!(result, Err(OrgError::InvalidCapability { .. })));
}

// ── revoke_organization_member ───────────────────────────────────────────────

#[test]
fn revoke_member_creates_signed_revocation_with_injected_clock() {
    let backend = FakeRegistryBackend::new();
    seed_admin(&backend);
    seed_member(&backend);

    let fixed_time = chrono::Utc.with_ymd_and_hms(2025, 6, 2, 12, 0, 0).unwrap();
    let clock = MockClock(fixed_time);
    let signer = FakeSecureSigner;
    let pp = FakePassphraseProvider;
    let uuid = DeterministicUuidProvider::new();
    let ctx = make_ctx(&backend, &clock, &uuid, &signer, &pp);

    let result = revoke_organization_member(
        &ctx,
        RevokeMemberCommand {
            org_prefix: ORG.to_string(),
            member_did: MEMBER_DID.to_string(),
            member_public_key: Ed25519PublicKey::from_bytes(MEMBER_PUBKEY),
            admin_public_key_hex: admin_pubkey_hex(),
            signer_alias: KeyAlias::new_unchecked("test-alias"),
            note: None,
        },
    );

    assert!(result.is_ok(), "unexpected error: {:?}", result.err());
    let att = result.unwrap();
    assert_eq!(att.revoked_at, Some(fixed_time));
    assert!(att.is_revoked());
    // Revocation should have a real signature
    assert!(!att.identity_signature.is_empty());
}

#[test]
fn revoke_member_fails_when_member_not_found() {
    let backend = FakeRegistryBackend::new();
    seed_admin(&backend);
    let signer = FakeSecureSigner;
    let pp = FakePassphraseProvider;
    let uuid = DeterministicUuidProvider::new();
    let clock = MockClock(chrono::Utc::now());
    let ctx = make_ctx(&backend, &clock, &uuid, &signer, &pp);

    let result = revoke_organization_member(
        &ctx,
        RevokeMemberCommand {
            org_prefix: ORG.to_string(),
            member_did: "did:key:z6MkNonexistent".to_string(),
            member_public_key: Ed25519PublicKey::from_bytes([0u8; 32]),
            admin_public_key_hex: admin_pubkey_hex(),
            signer_alias: KeyAlias::new_unchecked("test-alias"),
            note: None,
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

    let signer = FakeSecureSigner;
    let pp = FakePassphraseProvider;
    let uuid = DeterministicUuidProvider::new();
    let clock = MockClock(chrono::Utc::now());
    let ctx = make_ctx(&backend, &clock, &uuid, &signer, &pp);

    let result = revoke_organization_member(
        &ctx,
        RevokeMemberCommand {
            org_prefix: ORG.to_string(),
            member_did: MEMBER_DID.to_string(),
            member_public_key: Ed25519PublicKey::from_bytes(MEMBER_PUBKEY),
            admin_public_key_hex: admin_pubkey_hex(),
            signer_alias: KeyAlias::new_unchecked("test-alias"),
            note: None,
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
