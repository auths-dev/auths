use auths_verifier::{
    CommitOid, CommitOidError, IdentityDID, PolicyId, PublicKeyHex, PublicKeyHexError, keri::Prefix,
};

// =============================================================================
// CommitOid tests
// =============================================================================

#[test]
fn commit_oid_valid_sha1() {
    let hex40 = "a".repeat(40);
    let oid = CommitOid::parse(&hex40).unwrap();
    assert_eq!(oid.as_str(), hex40);
}

#[test]
fn commit_oid_valid_sha256() {
    let hex64 = "b".repeat(64);
    let oid = CommitOid::parse(&hex64).unwrap();
    assert_eq!(oid.as_str(), hex64);
}

#[test]
fn commit_oid_rejects_invalid_hex() {
    assert!(matches!(
        CommitOid::parse(&"g".repeat(40)),
        Err(CommitOidError::InvalidHex)
    ));
}

#[test]
fn commit_oid_rejects_wrong_length() {
    assert!(matches!(
        CommitOid::parse(&"a".repeat(20)),
        Err(CommitOidError::InvalidLength(20))
    ));
}

#[test]
fn commit_oid_rejects_empty() {
    assert!(matches!(CommitOid::parse(""), Err(CommitOidError::Empty)));
}

#[test]
fn commit_oid_display_fromstr_roundtrip() {
    let hex40 = "c".repeat(40);
    let oid = CommitOid::parse(&hex40).unwrap();
    let parsed: CommitOid = oid.to_string().parse().unwrap();
    assert_eq!(oid, parsed);
}

#[test]
fn commit_oid_try_from_string() {
    let hex40 = "d".repeat(40);
    let oid: CommitOid = hex40.clone().try_into().unwrap();
    assert_eq!(oid.as_str(), hex40);
}

#[test]
fn commit_oid_try_from_str() {
    let hex40 = "e".repeat(40);
    let oid = CommitOid::try_from(hex40.as_str()).unwrap();
    assert_eq!(oid.as_str(), hex40);
}

#[test]
fn commit_oid_serde_roundtrip() {
    let hex40 = "f".repeat(40);
    let oid = CommitOid::parse(&hex40).unwrap();
    let json = serde_json::to_string(&oid).unwrap();
    let back: CommitOid = serde_json::from_str(&json).unwrap();
    assert_eq!(oid, back);
}

#[test]
fn commit_oid_serde_rejects_invalid() {
    let json = r#""not-a-valid-oid""#;
    assert!(serde_json::from_str::<CommitOid>(json).is_err());
}

#[test]
fn commit_oid_into_string() {
    let hex40 = "a".repeat(40);
    let oid = CommitOid::parse(&hex40).unwrap();
    let s: String = oid.into();
    assert_eq!(s, hex40);
}

#[test]
fn commit_oid_normalizes_to_lowercase() {
    let upper = "A".repeat(40);
    let oid = CommitOid::parse(&upper).unwrap();
    assert_eq!(oid.as_str(), "a".repeat(40));
}

// =============================================================================
// Prefix::from_did tests
// =============================================================================

#[test]
fn prefix_from_did_extracts_keri_prefix() {
    let did = IdentityDID::parse("did:keri:ETest123abc").unwrap();
    let prefix = Prefix::from_did(&did).unwrap();
    assert_eq!(prefix.as_str(), "ETest123abc");
}

#[test]
fn prefix_from_did_roundtrips_with_identity_did() {
    let did = IdentityDID::parse("did:keri:EMyPrefix456").unwrap();
    let prefix = Prefix::from_did(&did).unwrap();
    let reconstructed = IdentityDID::from_prefix(prefix.as_str()).unwrap();
    assert_eq!(did, reconstructed);
}

// =============================================================================
// PublicKeyHex tests
// =============================================================================

#[test]
fn public_key_hex_valid() {
    let hex64 = "ab".repeat(32);
    let pk = PublicKeyHex::parse(&hex64).unwrap();
    assert_eq!(pk.as_str(), hex64);
}

#[test]
fn public_key_hex_to_ed25519() {
    let hex64 = "ab".repeat(32);
    let pk = PublicKeyHex::parse(&hex64).unwrap();
    let ed = pk.to_ed25519().unwrap();
    assert_eq!(ed.as_bytes()[0], 0xab);
}

#[test]
fn public_key_hex_rejects_invalid_hex() {
    assert!(matches!(
        PublicKeyHex::parse("zz".repeat(32).as_str()),
        Err(PublicKeyHexError::InvalidHex(_))
    ));
}

#[test]
fn public_key_hex_rejects_wrong_length() {
    assert!(matches!(
        PublicKeyHex::parse(&"ab".repeat(16)),
        Err(PublicKeyHexError::InvalidLength(32))
    ));
}

#[test]
fn public_key_hex_serde_roundtrip() {
    let hex64 = "cd".repeat(32);
    let pk = PublicKeyHex::parse(&hex64).unwrap();
    let json = serde_json::to_string(&pk).unwrap();
    let back: PublicKeyHex = serde_json::from_str(&json).unwrap();
    assert_eq!(pk, back);
}

#[test]
fn public_key_hex_serde_rejects_invalid() {
    let json = r#""too-short""#;
    assert!(serde_json::from_str::<PublicKeyHex>(json).is_err());
}

#[test]
fn public_key_hex_into_string() {
    let hex64 = "ef".repeat(32);
    let pk = PublicKeyHex::parse(&hex64).unwrap();
    let s: String = pk.into();
    assert_eq!(s, hex64);
}

// =============================================================================
// PolicyId tests
// =============================================================================

#[test]
fn policy_id_construction() {
    let pid = PolicyId::new("my-policy");
    assert_eq!(pid.as_str(), "my-policy");
    assert_eq!(&*pid, "my-policy"); // Deref
}

#[test]
fn policy_id_from_string() {
    let pid: PolicyId = "test-policy".into();
    assert_eq!(pid.as_str(), "test-policy");
}

#[test]
fn policy_id_from_owned_string() {
    let pid = PolicyId::from(String::from("owned"));
    assert_eq!(pid.as_str(), "owned");
}

#[test]
fn policy_id_display() {
    let pid = PolicyId::new("display-test");
    assert_eq!(format!("{pid}"), "display-test");
}

#[test]
fn policy_id_serde_transparent_roundtrip() {
    let pid = PolicyId::new("serde-test");
    let json = serde_json::to_string(&pid).unwrap();
    assert_eq!(json, r#""serde-test""#);
    let back: PolicyId = serde_json::from_str(&json).unwrap();
    assert_eq!(pid, back);
}
