use auths_verifier::{DeviceDID, DidParseError, IdentityDID};
use std::convert::TryFrom;

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

// ============================================================================
// TryFrom round-trips
// ============================================================================

#[test]
fn device_did_try_from_string_matches_parse() {
    let s = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string();
    let from_parse = DeviceDID::parse(&s).unwrap();
    let from_try: DeviceDID = DeviceDID::try_from(s).unwrap();
    assert_eq!(from_parse, from_try);
}

#[test]
fn device_did_try_from_str_matches_parse() {
    let s = "did:key:z6MkTest";
    let from_parse = DeviceDID::parse(s).unwrap();
    let from_try: DeviceDID = DeviceDID::try_from(s).unwrap();
    assert_eq!(from_parse, from_try);
}

#[test]
fn device_did_try_from_invalid_returns_error() {
    assert!(DeviceDID::try_from("garbage".to_string()).is_err());
    assert!(DeviceDID::try_from("garbage").is_err());
}

#[test]
fn identity_did_try_from_string_matches_parse() {
    let s = "did:keri:ETest123".to_string();
    let from_parse = IdentityDID::parse(&s).unwrap();
    let from_try: IdentityDID = IdentityDID::try_from(s).unwrap();
    assert_eq!(from_parse, from_try);
}

#[test]
fn identity_did_try_from_str_matches_parse() {
    let s = "did:keri:ETest123";
    let from_parse = IdentityDID::parse(s).unwrap();
    let from_try: IdentityDID = IdentityDID::try_from(s).unwrap();
    assert_eq!(from_parse, from_try);
}

#[test]
fn identity_did_try_from_invalid_returns_error() {
    assert!(IdentityDID::try_from("did:key:z6Mk".to_string()).is_err());
    assert!(IdentityDID::try_from("garbage").is_err());
}

// ============================================================================
// Serde round-trips
// ============================================================================

#[test]
fn device_did_serde_roundtrip() {
    let did = DeviceDID::parse("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").unwrap();
    let json = serde_json::to_string(&did).unwrap();
    assert_eq!(
        json,
        "\"did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK\""
    );
    let parsed: DeviceDID = serde_json::from_str(&json).unwrap();
    assert_eq!(did, parsed);
}

#[test]
fn identity_did_serde_roundtrip() {
    let did = IdentityDID::parse("did:keri:EOrg123").unwrap();
    let json = serde_json::to_string(&did).unwrap();
    assert_eq!(json, "\"did:keri:EOrg123\"");
    let parsed: IdentityDID = serde_json::from_str(&json).unwrap();
    assert_eq!(did, parsed);
}

#[test]
fn device_did_serde_rejects_invalid() {
    let result: Result<DeviceDID, _> = serde_json::from_str("\"garbage\"");
    assert!(result.is_err());
}

#[test]
fn device_did_serde_rejects_wrong_prefix() {
    let result: Result<DeviceDID, _> = serde_json::from_str("\"did:keri:EPrefix\"");
    assert!(result.is_err());
}

#[test]
fn identity_did_serde_rejects_invalid() {
    let result: Result<IdentityDID, _> = serde_json::from_str("\"garbage\"");
    assert!(result.is_err());
}

#[test]
fn identity_did_serde_rejects_did_key() {
    let result: Result<IdentityDID, _> = serde_json::from_str("\"did:key:z6MkTest\"");
    assert!(result.is_err());
}

// ============================================================================
// as_str() accessor
// ============================================================================

#[test]
fn device_did_as_str_matches_original() {
    let s = "did:key:z6MkTest";
    let did = DeviceDID::parse(s).unwrap();
    assert_eq!(did.as_str(), s);
}

#[test]
fn identity_did_as_str_matches_original() {
    let s = "did:keri:ETest";
    let did = IdentityDID::parse(s).unwrap();
    assert_eq!(did.as_str(), s);
}

// ============================================================================
// DidParseError implements std::error::Error
// ============================================================================

#[test]
fn did_parse_error_is_std_error() {
    let err = DidParseError::InvalidDevicePrefix("bad".to_string());
    let _: &dyn std::error::Error = &err;
}
