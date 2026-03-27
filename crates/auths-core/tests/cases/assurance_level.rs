use auths_core::ports::platform::derive_assurance_level;
use auths_verifier::AssuranceLevel;

#[test]
fn auths_is_sovereign() {
    assert_eq!(
        derive_assurance_level("auths", false),
        AssuranceLevel::Sovereign
    );
}

#[test]
fn github_is_authenticated() {
    assert_eq!(
        derive_assurance_level("github", false),
        AssuranceLevel::Authenticated
    );
}

#[test]
fn npm_is_token_verified() {
    assert_eq!(
        derive_assurance_level("npm", false),
        AssuranceLevel::TokenVerified
    );
}

#[test]
fn pypi_is_self_asserted() {
    assert_eq!(
        derive_assurance_level("pypi", false),
        AssuranceLevel::SelfAsserted
    );
}

#[test]
fn pypi_cross_verified_upgrades_to_token_verified() {
    assert_eq!(
        derive_assurance_level("pypi", true),
        AssuranceLevel::TokenVerified
    );
}

#[test]
fn unknown_platform_defaults_to_self_asserted() {
    assert_eq!(
        derive_assurance_level("unknown_platform", false),
        AssuranceLevel::SelfAsserted
    );
}
