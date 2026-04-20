use auths_core::ports::id::UuidProvider;
use auths_core::signing::{PassphraseProvider, PrefilledPassphraseProvider, SecureSigner};
use auths_core::storage::keychain::KeyAlias;
use auths_core::testing::DeterministicUuidProvider;
use auths_id::ports::registry::RegistryBackend;
use auths_id::testing::fakes::FakeRegistryBackend;
use auths_sdk::domains::org::error::OrgError;
use auths_sdk::testing::fakes::FakeSecureSigner;
use auths_sdk::workflows::org::{
    AddMemberCommand, OrgContext, OrgIdentifier, RevokeMemberCommand, Role,
    UpdateCapabilitiesCommand, UpdateMemberCommand, add_organization_member,
    get_organization_member, member_role_order, revoke_organization_member,
    update_member_capabilities, update_organization_member,
};
use auths_verifier::AttestationBuilder;
use auths_verifier::Capability;
use auths_verifier::PublicKeyHex;
use auths_verifier::clock::ClockProvider;
use auths_verifier::core::{Attestation, Ed25519PublicKey, ResourceId};
use auths_verifier::testing::MockClock;
use auths_verifier::types::{CanonicalDid, IdentityDID};
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

fn admin_pubkey_hex() -> PublicKeyHex {
    PublicKeyHex::new_unchecked(hex::encode(ADMIN_PUBKEY))
}

fn org_issuer() -> IdentityDID {
    IdentityDID::new_unchecked(format!("did:keri:{ORG}"))
}

fn base_admin_attestation() -> Attestation {
    AttestationBuilder::default()
        .rid("admin-rid-001")
        .issuer(org_issuer().as_ref())
        .subject(ADMIN_DID)
        .device_public_key(Ed25519PublicKey::from_bytes(ADMIN_PUBKEY))
        .role(Some(Role::Admin))
        .capabilities(vec![
            Capability::sign_commit(),
            Capability::manage_members(),
        ])
        .build()
}

fn base_member_attestation() -> Attestation {
    AttestationBuilder::default()
        .rid("member-rid-001")
        .issuer(org_issuer().as_ref())
        .subject(MEMBER_DID)
        .device_public_key(Ed25519PublicKey::from_bytes(MEMBER_PUBKEY))
        .role(Some(Role::Member))
        .capabilities(vec![Capability::sign_commit()])
        .delegated_by(Some(CanonicalDid::new_unchecked(ADMIN_DID)))
        .build()
}

fn seed_org_identity(backend: &FakeRegistryBackend) {
    use auths_id::keri::Event;
    use auths_id::keri::IcpEvent;
    use auths_id::keri::event::{CesrKey, KeriSequence, Threshold, VersionString};
    use auths_id::keri::types::{Prefix, Said};

    let icp = IcpEvent {
        v: VersionString::placeholder(),
        d: Said::default(),
        i: Prefix::new_unchecked(ORG.to_string()),
        s: KeriSequence::new(0),
        kt: Threshold::Simple(1),
        k: vec![CesrKey::new_unchecked(
            "DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        )],
        nt: Threshold::Simple(1),
        n: vec!["EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()],
        bt: Threshold::Simple(0),
        b: vec![],
        c: vec![],
        a: vec![],
        dt: None,
    };
    let prefix = Prefix::new_unchecked(ORG.to_string());
    backend
        .append_event(&prefix, &Event::Icp(icp))
        .expect("seed org KEL identity");
}

fn seed_admin(backend: &FakeRegistryBackend) {
    seed_org_identity(backend);
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
        witness_params: auths_id::witness_config::WitnessParams::Disabled,
    }
}

// ── Regression: identity DID (did:keri:) as member DID ──────────────────────
// These tests reproduce the bug where members added with did:keri: DIDs
// silently vanish from list/find results because the storage layer previously
// used DeviceDID::parse (which rejects did:keri:).

const KERI_MEMBER_DID: &str = "did:keri:EH-Bgtw9tm61YHxUWOw37UweX_7LNJC89t0Pl7ateDdM";

fn base_keri_member_attestation() -> Attestation {
    AttestationBuilder::default()
        .rid("keri-member-rid-001")
        .issuer(org_issuer().as_ref())
        .subject(KERI_MEMBER_DID)
        .device_public_key(Ed25519PublicKey::from_bytes(MEMBER_PUBKEY))
        .role(Some(Role::Member))
        .capabilities(vec![Capability::sign_commit()])
        .delegated_by(Some(CanonicalDid::new_unchecked(ADMIN_DID)))
        .build()
}

#[test]
fn add_and_find_member_with_identity_did() {
    let backend = FakeRegistryBackend::new();
    seed_admin(&backend);
    let signer = FakeSecureSigner;
    let pp = PrefilledPassphraseProvider::new("test");
    let uuid = DeterministicUuidProvider::new();
    let clock = MockClock(chrono::Utc::now());
    let ctx = make_ctx(&backend, &clock, &uuid, &signer, &pp);

    let att = add_organization_member(
        &ctx,
        AddMemberCommand {
            org_prefix: ORG.to_string(),
            member_did: KERI_MEMBER_DID.to_string(),
            member_public_key: MEMBER_PUBKEY.to_vec(),
            member_curve: auths_crypto::CurveType::Ed25519,
            role: Role::Member,
            capabilities: vec![],
            admin_public_key_hex: admin_pubkey_hex(),
            signer_alias: KeyAlias::new_unchecked("test-alias"),
            note: None,
        },
    )
    .expect("add_member with did:keri: should succeed");

    assert_eq!(att.subject.as_str(), KERI_MEMBER_DID);

    // The member must be findable by its did:keri: DID
    let mut found = false;
    backend
        .visit_org_member_attestations(ORG, &mut |entry| {
            if entry.did.as_str() == KERI_MEMBER_DID {
                found = true;
            }
            std::ops::ControlFlow::Continue(())
        })
        .unwrap();
    assert!(found, "member with did:keri: should be findable after add");
}

#[test]
fn revoke_member_with_identity_did() {
    let backend = FakeRegistryBackend::new();
    seed_admin(&backend);

    // Add member with did:keri: DID
    backend
        .store_org_member(ORG, &base_keri_member_attestation())
        .unwrap();

    let signer = FakeSecureSigner;
    let pp = PrefilledPassphraseProvider::new("test");
    let uuid = DeterministicUuidProvider::new();
    let clock = MockClock(chrono::Utc::now());
    let ctx = make_ctx(&backend, &clock, &uuid, &signer, &pp);

    // Revoking by did:keri: DID must work
    let result = revoke_organization_member(
        &ctx,
        RevokeMemberCommand {
            org_prefix: ORG.to_string(),
            member_did: KERI_MEMBER_DID.to_string(),
            member_public_key: MEMBER_PUBKEY.to_vec(),
            member_curve: auths_crypto::CurveType::Ed25519,
            admin_public_key_hex: admin_pubkey_hex(),
            signer_alias: KeyAlias::new_unchecked("test-alias"),
            note: Some("offboarded".to_string()),
        },
    );

    assert!(
        result.is_ok(),
        "revoke with did:keri: should succeed, got: {:?}",
        result.err()
    );
    assert!(result.unwrap().is_revoked());
}

#[test]
fn member_with_underscore_in_keri_prefix_roundtrips() {
    // KERI prefixes can contain underscores (Base64url), which the
    // sanitize/unsanitize path must handle without corruption.
    let did_with_underscore = "did:keri:EH-Bgtw9tm61YHxUWOw37UweX_7LNJC89t0Pl7ateDdM";
    let backend = FakeRegistryBackend::new();
    seed_admin(&backend);

    let att = AttestationBuilder::default()
        .rid("underscore-rid")
        .issuer(org_issuer().as_ref())
        .subject(did_with_underscore)
        .device_public_key(Ed25519PublicKey::from_bytes(MEMBER_PUBKEY))
        .role(Some(Role::Member))
        .capabilities(vec![Capability::sign_commit()])
        .build();

    backend.store_org_member(ORG, &att).unwrap();

    let mut found_did: Option<String> = None;
    backend
        .visit_org_member_attestations(ORG, &mut |entry| {
            if entry.did.as_str().contains("UweX_7") {
                found_did = Some(entry.did.as_str().to_string());
            }
            std::ops::ControlFlow::Continue(())
        })
        .unwrap();

    assert_eq!(
        found_did.as_deref(),
        Some(did_with_underscore),
        "DID with underscore in KERI prefix must round-trip through sanitize/unsanitize"
    );
}

// ── find_admin (tested indirectly via add_organization_member) ────────────────

#[test]
fn find_admin_returns_attestation_when_admin_exists() {
    let backend = FakeRegistryBackend::new();
    seed_admin(&backend);
    let signer = FakeSecureSigner;
    let pp = PrefilledPassphraseProvider::new("test");
    let uuid = DeterministicUuidProvider::new();
    let clock = MockClock(chrono::Utc::now());
    let ctx = make_ctx(&backend, &clock, &uuid, &signer, &pp);

    let result = add_organization_member(
        &ctx,
        AddMemberCommand {
            org_prefix: ORG.to_string(),
            member_did: MEMBER_DID.to_string(),
            member_public_key: MEMBER_PUBKEY.to_vec(),
            member_curve: auths_crypto::CurveType::Ed25519,
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
    let pp = PrefilledPassphraseProvider::new("test");
    let uuid = DeterministicUuidProvider::new();
    let clock = MockClock(chrono::Utc::now());
    let ctx = make_ctx(&backend, &clock, &uuid, &signer, &pp);

    let wrong_hex = PublicKeyHex::new_unchecked(hex::encode([0x00u8; 32]));
    let result = add_organization_member(
        &ctx,
        AddMemberCommand {
            org_prefix: ORG.to_string(),
            member_did: MEMBER_DID.to_string(),
            member_public_key: MEMBER_PUBKEY.to_vec(),
            member_curve: auths_crypto::CurveType::Ed25519,
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
    let pp = PrefilledPassphraseProvider::new("test");
    let uuid = DeterministicUuidProvider::new();
    let clock = MockClock(chrono::Utc::now());
    let ctx = make_ctx(&backend, &clock, &uuid, &signer, &pp);

    let result = add_organization_member(
        &ctx,
        AddMemberCommand {
            org_prefix: ORG.to_string(),
            member_did: MEMBER_DID.to_string(),
            member_public_key: MEMBER_PUBKEY.to_vec(),
            member_curve: auths_crypto::CurveType::Ed25519,
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
    let pp = PrefilledPassphraseProvider::new("test");
    let ctx = make_ctx(&backend, &clock, &id_provider, &signer, &pp);

    let result = add_organization_member(
        &ctx,
        AddMemberCommand {
            org_prefix: ORG.to_string(),
            member_did: MEMBER_DID.to_string(),
            member_public_key: MEMBER_PUBKEY.to_vec(),
            member_curve: auths_crypto::CurveType::Ed25519,
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
    let pp = PrefilledPassphraseProvider::new("test");
    let uuid = DeterministicUuidProvider::new();
    let clock = MockClock(chrono::Utc::now());
    let ctx = make_ctx(&backend, &clock, &uuid, &signer, &pp);

    let att = add_organization_member(
        &ctx,
        AddMemberCommand {
            org_prefix: ORG.to_string(),
            member_did: MEMBER_DID.to_string(),
            member_public_key: MEMBER_PUBKEY.to_vec(),
            member_curve: auths_crypto::CurveType::Ed25519,
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
        auths_verifier::DevicePublicKey::ed25519(&MEMBER_PUBKEY)
    );
}

#[test]
fn add_member_fails_when_admin_not_found() {
    let backend = FakeRegistryBackend::new();
    let signer = FakeSecureSigner;
    let pp = PrefilledPassphraseProvider::new("test");
    let uuid = DeterministicUuidProvider::new();
    let clock = MockClock(chrono::Utc::now());
    let ctx = make_ctx(&backend, &clock, &uuid, &signer, &pp);

    let result = add_organization_member(
        &ctx,
        AddMemberCommand {
            org_prefix: ORG.to_string(),
            member_did: MEMBER_DID.to_string(),
            member_public_key: MEMBER_PUBKEY.to_vec(),
            member_curve: auths_crypto::CurveType::Ed25519,
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
    let pp = PrefilledPassphraseProvider::new("test");
    let uuid = DeterministicUuidProvider::new();
    let clock = MockClock(chrono::Utc::now());
    let ctx = make_ctx(&backend, &clock, &uuid, &signer, &pp);

    let result = add_organization_member(
        &ctx,
        AddMemberCommand {
            org_prefix: ORG.to_string(),
            member_did: MEMBER_DID.to_string(),
            member_public_key: MEMBER_PUBKEY.to_vec(),
            member_curve: auths_crypto::CurveType::Ed25519,
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
    let pp = PrefilledPassphraseProvider::new("test");
    let uuid = DeterministicUuidProvider::new();
    let ctx = make_ctx(&backend, &clock, &uuid, &signer, &pp);

    let result = revoke_organization_member(
        &ctx,
        RevokeMemberCommand {
            org_prefix: ORG.to_string(),
            member_did: MEMBER_DID.to_string(),
            member_public_key: MEMBER_PUBKEY.to_vec(),
            member_curve: auths_crypto::CurveType::Ed25519,
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
    let pp = PrefilledPassphraseProvider::new("test");
    let uuid = DeterministicUuidProvider::new();
    let clock = MockClock(chrono::Utc::now());
    let ctx = make_ctx(&backend, &clock, &uuid, &signer, &pp);

    let result = revoke_organization_member(
        &ctx,
        RevokeMemberCommand {
            org_prefix: ORG.to_string(),
            member_did: "did:key:z6MkNonexistent".to_string(),
            member_public_key: vec![0u8; 32],
            member_curve: auths_crypto::CurveType::Ed25519,
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
    let pp = PrefilledPassphraseProvider::new("test");
    let uuid = DeterministicUuidProvider::new();
    let clock = MockClock(chrono::Utc::now());
    let ctx = make_ctx(&backend, &clock, &uuid, &signer, &pp);

    let result = revoke_organization_member(
        &ctx,
        RevokeMemberCommand {
            org_prefix: ORG.to_string(),
            member_did: MEMBER_DID.to_string(),
            member_public_key: MEMBER_PUBKEY.to_vec(),
            member_curve: auths_crypto::CurveType::Ed25519,
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

    let clock = MockClock(chrono::Utc::now());
    let signer = FakeSecureSigner;
    let pp = PrefilledPassphraseProvider::new("");
    let uuid = DeterministicUuidProvider::new();
    let ctx = make_ctx(&backend, &clock, &uuid, &signer, &pp);
    let result = update_member_capabilities(
        &ctx,
        UpdateCapabilitiesCommand {
            org_prefix: ORG.to_string(),
            member_did: MEMBER_DID.to_string(),
            capabilities: vec!["sign_commit".to_string(), "sign_release".to_string()],
            public_key_hex: admin_pubkey_hex(),
            signer_alias: KeyAlias::new_unchecked("test-admin"),
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

    let clock = MockClock(chrono::Utc::now());
    let signer = FakeSecureSigner;
    let pp = PrefilledPassphraseProvider::new("");
    let uuid = DeterministicUuidProvider::new();
    let ctx = make_ctx(&backend, &clock, &uuid, &signer, &pp);
    let result = update_member_capabilities(
        &ctx,
        UpdateCapabilitiesCommand {
            org_prefix: ORG.to_string(),
            member_did: MEMBER_DID.to_string(),
            capabilities: vec!["invalid cap!@#".to_string()],
            public_key_hex: admin_pubkey_hex(),
            signer_alias: KeyAlias::new_unchecked("test-admin"),
        },
    );

    assert!(matches!(result, Err(OrgError::InvalidCapability { .. })));
}

// ── get_organization_member ─────────────────────────────────────────────────

#[test]
fn get_member_returns_attestation_when_exists() {
    let backend = FakeRegistryBackend::new();
    seed_admin(&backend);
    seed_member(&backend);

    let result = get_organization_member(&backend, ORG, MEMBER_DID);
    assert!(result.is_ok(), "unexpected error: {:?}", result.err());
    let att = result.unwrap();
    assert_eq!(att.subject.as_str(), MEMBER_DID);
}

#[test]
fn get_member_returns_not_found_when_missing() {
    let backend = FakeRegistryBackend::new();
    seed_admin(&backend);

    let result = get_organization_member(&backend, ORG, "did:key:z6MkNonexistent");
    assert!(matches!(result, Err(OrgError::MemberNotFound { .. })));
}

#[test]
fn get_member_returns_admin_too() {
    let backend = FakeRegistryBackend::new();
    seed_admin(&backend);

    let result = get_organization_member(&backend, ORG, ADMIN_DID);
    assert!(result.is_ok());
    let att = result.unwrap();
    assert_eq!(att.subject.as_str(), ADMIN_DID);
}

// ── update_organization_member ──────────────────────────────────────────────

#[test]
fn update_member_changes_role() {
    let backend = FakeRegistryBackend::new();
    seed_admin(&backend);
    seed_member(&backend);

    let clock = MockClock(chrono::Utc::now());
    let signer = FakeSecureSigner;
    let pp = PrefilledPassphraseProvider::new("");
    let uuid = DeterministicUuidProvider::new();
    let ctx = make_ctx(&backend, &clock, &uuid, &signer, &pp);
    let result = update_organization_member(
        &ctx,
        UpdateMemberCommand {
            org_prefix: ORG.to_string(),
            member_did: MEMBER_DID.to_string(),
            role: Some(Role::Readonly),
            capabilities: None,
            admin_public_key_hex: admin_pubkey_hex(),
            signer_alias: KeyAlias::new_unchecked("test-admin"),
        },
    );

    assert!(result.is_ok(), "unexpected error: {:?}", result.err());
    let att = result.unwrap();
    assert_eq!(att.role, Some(Role::Readonly));
    assert!(att.capabilities.contains(&Capability::sign_commit()));
}

#[test]
fn update_member_changes_capabilities() {
    let backend = FakeRegistryBackend::new();
    seed_admin(&backend);
    seed_member(&backend);

    let clock = MockClock(chrono::Utc::now());
    let signer = FakeSecureSigner;
    let pp = PrefilledPassphraseProvider::new("");
    let uuid = DeterministicUuidProvider::new();
    let ctx = make_ctx(&backend, &clock, &uuid, &signer, &pp);
    let result = update_organization_member(
        &ctx,
        UpdateMemberCommand {
            org_prefix: ORG.to_string(),
            member_did: MEMBER_DID.to_string(),
            role: None,
            capabilities: Some(vec!["sign_commit".to_string(), "sign_release".to_string()]),
            admin_public_key_hex: admin_pubkey_hex(),
            signer_alias: KeyAlias::new_unchecked("test-admin"),
        },
    );

    assert!(result.is_ok(), "unexpected error: {:?}", result.err());
    let att = result.unwrap();
    assert_eq!(att.role, Some(Role::Member));
    assert_eq!(att.capabilities.len(), 2);
    assert!(att.capabilities.contains(&Capability::sign_release()));
}

#[test]
fn update_member_changes_both_role_and_capabilities() {
    let backend = FakeRegistryBackend::new();
    seed_admin(&backend);
    seed_member(&backend);

    let clock = MockClock(chrono::Utc::now());
    let signer = FakeSecureSigner;
    let pp = PrefilledPassphraseProvider::new("");
    let uuid = DeterministicUuidProvider::new();
    let ctx = make_ctx(&backend, &clock, &uuid, &signer, &pp);
    let result = update_organization_member(
        &ctx,
        UpdateMemberCommand {
            org_prefix: ORG.to_string(),
            member_did: MEMBER_DID.to_string(),
            role: Some(Role::Admin),
            capabilities: Some(vec![
                "sign_commit".to_string(),
                "manage_members".to_string(),
            ]),
            admin_public_key_hex: admin_pubkey_hex(),
            signer_alias: KeyAlias::new_unchecked("test-admin"),
        },
    );

    assert!(result.is_ok(), "unexpected error: {:?}", result.err());
    let att = result.unwrap();
    assert_eq!(att.role, Some(Role::Admin));
    assert!(att.capabilities.contains(&Capability::manage_members()));
}

#[test]
fn update_member_fails_when_admin_not_found() {
    let backend = FakeRegistryBackend::new();
    seed_member(&backend);

    let clock = MockClock(chrono::Utc::now());
    let signer = FakeSecureSigner;
    let pp = PrefilledPassphraseProvider::new("");
    let uuid = DeterministicUuidProvider::new();
    let ctx = make_ctx(&backend, &clock, &uuid, &signer, &pp);
    let result = update_organization_member(
        &ctx,
        UpdateMemberCommand {
            org_prefix: ORG.to_string(),
            member_did: MEMBER_DID.to_string(),
            role: Some(Role::Readonly),
            capabilities: None,
            admin_public_key_hex: admin_pubkey_hex(),
            signer_alias: KeyAlias::new_unchecked("test-admin"),
        },
    );

    assert!(matches!(result, Err(OrgError::AdminNotFound { .. })));
}

#[test]
fn update_member_fails_when_member_not_found() {
    let backend = FakeRegistryBackend::new();
    seed_admin(&backend);

    let clock = MockClock(chrono::Utc::now());
    let signer = FakeSecureSigner;
    let pp = PrefilledPassphraseProvider::new("");
    let uuid = DeterministicUuidProvider::new();
    let ctx = make_ctx(&backend, &clock, &uuid, &signer, &pp);
    let result = update_organization_member(
        &ctx,
        UpdateMemberCommand {
            org_prefix: ORG.to_string(),
            member_did: "did:key:z6MkNonexistent".to_string(),
            role: Some(Role::Readonly),
            capabilities: None,
            admin_public_key_hex: admin_pubkey_hex(),
            signer_alias: KeyAlias::new_unchecked("test-admin"),
        },
    );

    assert!(matches!(result, Err(OrgError::MemberNotFound { .. })));
}

#[test]
fn update_member_fails_when_already_revoked() {
    let backend = FakeRegistryBackend::new();
    seed_admin(&backend);

    let mut att = base_member_attestation();
    att.revoked_at = Some(chrono::Utc::now());
    backend
        .store_org_member(ORG, &att)
        .expect("seed revoked member");

    let clock = MockClock(chrono::Utc::now());
    let signer = FakeSecureSigner;
    let pp = PrefilledPassphraseProvider::new("");
    let uuid = DeterministicUuidProvider::new();
    let ctx = make_ctx(&backend, &clock, &uuid, &signer, &pp);
    let result = update_organization_member(
        &ctx,
        UpdateMemberCommand {
            org_prefix: ORG.to_string(),
            member_did: MEMBER_DID.to_string(),
            role: Some(Role::Admin),
            capabilities: None,
            admin_public_key_hex: admin_pubkey_hex(),
            signer_alias: KeyAlias::new_unchecked("test-admin"),
        },
    );

    assert!(matches!(result, Err(OrgError::AlreadyRevoked { .. })));
}

#[test]
fn update_member_fails_with_invalid_capability() {
    let backend = FakeRegistryBackend::new();
    seed_admin(&backend);
    seed_member(&backend);

    let clock = MockClock(chrono::Utc::now());
    let signer = FakeSecureSigner;
    let pp = PrefilledPassphraseProvider::new("");
    let uuid = DeterministicUuidProvider::new();
    let ctx = make_ctx(&backend, &clock, &uuid, &signer, &pp);
    let result = update_organization_member(
        &ctx,
        UpdateMemberCommand {
            org_prefix: ORG.to_string(),
            member_did: MEMBER_DID.to_string(),
            role: None,
            capabilities: Some(vec!["not a valid cap!!!".to_string()]),
            admin_public_key_hex: admin_pubkey_hex(),
            signer_alias: KeyAlias::new_unchecked("test-admin"),
        },
    );

    assert!(matches!(result, Err(OrgError::InvalidCapability { .. })));
}

// ── member_role_order ───────────────────────────────────────────────────────

#[test]
fn role_order_admin_before_member_before_readonly_before_none() {
    assert!(member_role_order(&Some(Role::Admin)) < member_role_order(&Some(Role::Member)));
    assert!(member_role_order(&Some(Role::Member)) < member_role_order(&Some(Role::Readonly)));
    assert!(member_role_order(&Some(Role::Readonly)) < member_role_order(&None));
}

// ── OrgIdentifier ───────────────────────────────────────────────────────────

#[test]
fn org_identifier_parse_bare_prefix() {
    let id = OrgIdentifier::parse("EOrg1234567890");
    assert!(matches!(id, OrgIdentifier::Prefix(_)));
    assert_eq!(id.prefix(), "EOrg1234567890");
}

#[test]
fn org_identifier_parse_full_did() {
    let id = OrgIdentifier::parse("did:keri:EOrg1234567890");
    assert!(matches!(id, OrgIdentifier::Did(_)));
    assert_eq!(id.prefix(), "EOrg1234567890");
}

#[test]
fn org_identifier_from_str_delegates_to_parse() {
    let id: OrgIdentifier = "did:keri:EOrg1234567890".into();
    assert_eq!(id.prefix(), "EOrg1234567890");

    let id2: OrgIdentifier = "EOrg1234567890".into();
    assert_eq!(id2.prefix(), "EOrg1234567890");
}

#[test]
fn org_identifier_non_keri_did_falls_back() {
    let id = OrgIdentifier::parse("did:web:example.com");
    assert_eq!(id.prefix(), "did:web:example.com");
}
