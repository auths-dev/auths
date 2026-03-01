use auths_verifier::Capability;
use auths_verifier::core::CapabilityError;

#[test]
fn test_parse_capability_sign_commit() {
    let cap: Capability = "sign_commit".parse().unwrap();
    assert_eq!(cap.as_str(), "sign_commit");
}

#[test]
fn test_parse_capability_sign_release() {
    let cap: Capability = "sign_release".parse().unwrap();
    assert_eq!(cap.as_str(), "sign_release");
}

#[test]
fn test_parse_capability_manage_members() {
    let cap: Capability = "manage_members".parse().unwrap();
    assert_eq!(cap.as_str(), "manage_members");
}

#[test]
fn test_parse_capability_rotate_keys() {
    let cap: Capability = "rotate_keys".parse().unwrap();
    assert_eq!(cap.as_str(), "rotate_keys");
}

#[test]
fn test_parse_capability_case_insensitive() {
    let cap: Capability = "Sign_Commit".parse().unwrap();
    assert_eq!(cap.as_str(), "sign_commit");

    let cap2: Capability = "SIGN_RELEASE".parse().unwrap();
    assert_eq!(cap2.as_str(), "sign_release");
}

#[test]
fn test_parse_capability_hyphenated() {
    let cap: Capability = "sign-commit".parse().unwrap();
    assert_eq!(cap.as_str(), "sign_commit");

    let cap2: Capability = "manage-members".parse().unwrap();
    assert_eq!(cap2.as_str(), "manage_members");
}

#[test]
fn test_parse_capability_no_underscore_alias() {
    let cap: Capability = "signcommit".parse().unwrap();
    assert_eq!(cap.as_str(), "sign_commit");

    let cap2: Capability = "rotatekeys".parse().unwrap();
    assert_eq!(cap2.as_str(), "rotate_keys");
}

#[test]
fn test_parse_capability_custom_valid() {
    let cap: Capability = "deploy".parse().unwrap();
    assert_eq!(cap.as_str(), "deploy");
}

#[test]
fn test_parse_capability_unknown_returns_err() {
    let result = "has space".parse::<Capability>();
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        CapabilityError::InvalidChars(_)
    ));
}

#[test]
fn test_parse_capability_empty_returns_err() {
    let result = "".parse::<Capability>();
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), CapabilityError::Empty));
}

#[test]
fn test_parse_capability_whitespace_only_returns_err() {
    let result = "   ".parse::<Capability>();
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), CapabilityError::Empty));
}
