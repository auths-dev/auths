use auths_verifier::{DeviceDID, DidParseError, IdentityDID};

// ============================================================================
// DeviceDID::parse()
// ============================================================================

#[test]
fn device_did_parse_valid_did_key_z() {
    let did = DeviceDID::parse("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").unwrap();
    assert_eq!(
        did.as_str(),
        "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    );
}

#[test]
fn device_did_parse_minimal_valid() {
    let did = DeviceDID::parse("did:key:zA").unwrap();
    assert_eq!(did.as_str(), "did:key:zA");
}

#[test]
fn device_did_parse_rejects_wrong_multibase_prefix() {
    let err = DeviceDID::parse("did:key:fOtherBase").unwrap_err();
    assert!(matches!(err, DidParseError::InvalidDevicePrefix(_)));
}

#[test]
fn device_did_parse_rejects_empty_after_z() {
    let err = DeviceDID::parse("did:key:z").unwrap_err();
    assert!(matches!(err, DidParseError::EmptyIdentifier));
}

#[test]
fn device_did_parse_rejects_empty_did_key() {
    let err = DeviceDID::parse("did:key:").unwrap_err();
    assert!(matches!(err, DidParseError::InvalidDevicePrefix(_)));
}

#[test]
fn device_did_parse_rejects_wrong_scheme() {
    let err = DeviceDID::parse("did:keri:EPrefix").unwrap_err();
    assert!(matches!(err, DidParseError::InvalidDevicePrefix(_)));
}

#[test]
fn device_did_parse_rejects_garbage() {
    let err = DeviceDID::parse("garbage").unwrap_err();
    assert!(matches!(err, DidParseError::InvalidDevicePrefix(_)));
}

#[test]
fn device_did_parse_rejects_empty_string() {
    let err = DeviceDID::parse("").unwrap_err();
    assert!(matches!(err, DidParseError::InvalidDevicePrefix(_)));
}

// ============================================================================
// IdentityDID::parse()
// ============================================================================

#[test]
fn identity_did_parse_valid_did_keri() {
    let did = IdentityDID::parse("did:keri:EPrefix123").unwrap();
    assert_eq!(did.as_str(), "did:keri:EPrefix123");
}

#[test]
fn identity_did_parse_rejects_did_key() {
    let err = IdentityDID::parse("did:key:z6MkValid").unwrap_err();
    assert!(matches!(err, DidParseError::InvalidIdentityPrefix(_)));
}

#[test]
fn identity_did_parse_rejects_empty_keri_prefix() {
    let err = IdentityDID::parse("did:keri:").unwrap_err();
    assert!(matches!(err, DidParseError::EmptyIdentifier));
}

#[test]
fn identity_did_parse_rejects_garbage() {
    let err = IdentityDID::parse("garbage").unwrap_err();
    assert!(matches!(err, DidParseError::InvalidIdentityPrefix(_)));
}

#[test]
fn identity_did_parse_rejects_empty_string() {
    let err = IdentityDID::parse("").unwrap_err();
    assert!(matches!(err, DidParseError::InvalidIdentityPrefix(_)));
}

// ============================================================================
// IdentityDID::from_prefix() and prefix()
// ============================================================================

#[test]
fn identity_did_from_prefix_builds_correct_did() {
    let did = IdentityDID::from_prefix("EOrg123").unwrap();
    assert_eq!(did.as_str(), "did:keri:EOrg123");
}

#[test]
fn identity_did_from_prefix_rejects_empty() {
    let err = IdentityDID::from_prefix("").unwrap_err();
    assert!(matches!(err, DidParseError::EmptyIdentifier));
}

#[test]
fn identity_did_prefix_returns_keri_portion() {
    let did = IdentityDID::parse("did:keri:EOrg123").unwrap();
    assert_eq!(did.prefix(), "EOrg123");
}

#[test]
fn identity_did_from_prefix_roundtrips_through_prefix() {
    let did = IdentityDID::from_prefix("ETestPrefix").unwrap();
    assert_eq!(did.prefix(), "ETestPrefix");
}

// ============================================================================
// FromStr
// ============================================================================

#[test]
fn device_did_fromstr_works() {
    let did: DeviceDID = "did:key:z6MkTest".parse().unwrap();
    assert_eq!(did.as_str(), "did:key:z6MkTest");
}

#[test]
fn device_did_fromstr_rejects_invalid() {
    let err = "garbage".parse::<DeviceDID>().unwrap_err();
    assert!(matches!(err, DidParseError::InvalidDevicePrefix(_)));
}

#[test]
fn identity_did_fromstr_works() {
    let did: IdentityDID = "did:keri:ETest".parse().unwrap();
    assert_eq!(did.as_str(), "did:keri:ETest");
}

#[test]
fn identity_did_fromstr_rejects_invalid() {
    let err = "did:key:z6MkTest".parse::<IdentityDID>().unwrap_err();
    assert!(matches!(err, DidParseError::InvalidIdentityPrefix(_)));
}

// ============================================================================
// Display round-trips through FromStr
// ============================================================================

#[test]
fn device_did_display_roundtrips_through_fromstr() {
    let original =
        DeviceDID::parse("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").unwrap();
    let displayed = original.to_string();
    let parsed: DeviceDID = displayed.parse().unwrap();
    assert_eq!(original, parsed);
}

#[test]
fn identity_did_display_roundtrips_through_fromstr() {
    let original = IdentityDID::parse("did:keri:EOrg123").unwrap();
    let displayed = original.to_string();
    let parsed: IdentityDID = displayed.parse().unwrap();
    assert_eq!(original, parsed);
}

// ============================================================================
// Error messages
// ============================================================================

#[test]
fn did_parse_error_display_is_useful() {
    let err = DidParseError::InvalidDevicePrefix("bad".to_string());
    assert!(err.to_string().contains("did:key:z"));
    assert!(err.to_string().contains("bad"));

    let err = DidParseError::InvalidIdentityPrefix("bad".to_string());
    assert!(err.to_string().contains("did:keri:"));
    assert!(err.to_string().contains("bad"));

    let err = DidParseError::EmptyIdentifier;
    assert!(err.to_string().contains("empty"));
}
