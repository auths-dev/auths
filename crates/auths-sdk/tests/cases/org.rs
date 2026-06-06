use auths_id::ports::registry::RegistryBackend;
use auths_id::testing::fakes::FakeRegistryBackend;
use auths_sdk::domains::org::error::OrgError;
use auths_sdk::workflows::org::{OrgIdentifier, Role, get_organization_member, member_role_order};
use auths_verifier::AttestationBuilder;
use auths_verifier::core::{Attestation, Ed25519PublicKey};
use auths_verifier::types::{CanonicalDid, IdentityDID};

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

fn org_issuer() -> IdentityDID {
    IdentityDID::new_unchecked(format!("did:keri:{ORG}"))
}

fn base_admin_attestation() -> Attestation {
    AttestationBuilder::default()
        .rid("admin-rid-001")
        .issuer(org_issuer().as_ref())
        .subject(ADMIN_DID)
        .device_public_key(Ed25519PublicKey::from_bytes(ADMIN_PUBKEY))
        .build()
}

fn base_member_attestation() -> Attestation {
    AttestationBuilder::default()
        .rid("member-rid-001")
        .issuer(org_issuer().as_ref())
        .subject(MEMBER_DID)
        .device_public_key(Ed25519PublicKey::from_bytes(MEMBER_PUBKEY))
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
        n: vec![Said::new_unchecked(
            "EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        )],
        bt: Threshold::Simple(0),
        b: vec![],
        c: vec![],
        a: vec![],
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

// ── Regression: identity DID (did:keri:) as member DID ──────────────────────
// Storage must round-trip member DIDs whose KERI prefix contains underscores
// (Base64url) through the sanitize/unsanitize path without corruption.

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
