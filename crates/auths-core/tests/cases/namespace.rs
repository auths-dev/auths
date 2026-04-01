use std::sync::Arc;

use auths_core::ports::namespace::{
    Ecosystem, NamespaceVerifier, NamespaceVerifyError, PackageName, PlatformContext,
    VerificationToken,
};
use auths_crypto::AuthsErrorInfo;

#[test]
fn ecosystem_parse_canonical_names() {
    let cases = [
        ("npm", Ecosystem::Npm),
        ("pypi", Ecosystem::Pypi),
        ("cargo", Ecosystem::Cargo),
        ("docker", Ecosystem::Docker),
        ("go", Ecosystem::Go),
        ("maven", Ecosystem::Maven),
        ("nuget", Ecosystem::Nuget),
    ];

    for (input, expected) in cases {
        let parsed = Ecosystem::parse(input).unwrap();
        assert_eq!(parsed, expected, "parse({input})");
        assert_eq!(parsed.as_str(), input, "roundtrip for {input}");
    }
}

#[test]
fn ecosystem_parse_aliases() {
    let cases = [
        ("crates.io", Ecosystem::Cargo),
        ("crates", Ecosystem::Cargo),
        ("npmjs", Ecosystem::Npm),
        ("npmjs.com", Ecosystem::Npm),
        ("pypi.org", Ecosystem::Pypi),
        ("dockerhub", Ecosystem::Docker),
        ("docker.io", Ecosystem::Docker),
        ("golang", Ecosystem::Go),
        ("go.dev", Ecosystem::Go),
        ("pkg.go.dev", Ecosystem::Go),
        ("maven-central", Ecosystem::Maven),
        ("mvn", Ecosystem::Maven),
        ("nuget.org", Ecosystem::Nuget),
    ];

    for (alias, expected) in cases {
        let parsed = Ecosystem::parse(alias).unwrap();
        assert_eq!(parsed, expected, "alias '{alias}'");
    }
}

#[test]
fn ecosystem_parse_case_insensitive() {
    assert_eq!(Ecosystem::parse("NPM").unwrap(), Ecosystem::Npm);
    assert_eq!(Ecosystem::parse("Cargo").unwrap(), Ecosystem::Cargo);
    assert_eq!(Ecosystem::parse("PYPI").unwrap(), Ecosystem::Pypi);
}

#[test]
fn ecosystem_parse_unsupported() {
    let err = Ecosystem::parse("rubygems").unwrap_err();
    assert!(matches!(
        err,
        NamespaceVerifyError::UnsupportedEcosystem { .. }
    ));
}

#[test]
fn ecosystem_display() {
    assert_eq!(format!("{}", Ecosystem::Npm), "npm");
    assert_eq!(format!("{}", Ecosystem::Cargo), "cargo");
}

#[test]
fn ecosystem_serde_roundtrip() {
    let eco = Ecosystem::Cargo;
    let json = serde_json::to_string(&eco).unwrap();
    assert_eq!(json, r#""cargo""#);
    let parsed: Ecosystem = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, eco);
}

#[test]
fn package_name_valid() {
    let name = PackageName::parse("my-package").unwrap();
    assert_eq!(name.as_str(), "my-package");

    PackageName::parse("@scope/package").unwrap();
    PackageName::parse("some_crate_v2").unwrap();
    PackageName::parse("a").unwrap();
}

#[test]
fn package_name_empty() {
    let err = PackageName::parse("").unwrap_err();
    assert!(matches!(
        err,
        NamespaceVerifyError::InvalidPackageName { .. }
    ));
}

#[test]
fn package_name_control_chars() {
    let err = PackageName::parse("bad\x00name").unwrap_err();
    assert!(matches!(
        err,
        NamespaceVerifyError::InvalidPackageName { .. }
    ));

    let err = PackageName::parse("tab\there").unwrap_err();
    assert!(matches!(
        err,
        NamespaceVerifyError::InvalidPackageName { .. }
    ));
}

#[test]
fn package_name_path_traversal() {
    let err = PackageName::parse("../etc/passwd").unwrap_err();
    assert!(matches!(
        err,
        NamespaceVerifyError::InvalidPackageName { .. }
    ));

    let err = PackageName::parse("/absolute/path").unwrap_err();
    assert!(matches!(
        err,
        NamespaceVerifyError::InvalidPackageName { .. }
    ));

    let err = PackageName::parse("\\windows\\path").unwrap_err();
    assert!(matches!(
        err,
        NamespaceVerifyError::InvalidPackageName { .. }
    ));

    let err = PackageName::parse("foo/../bar").unwrap_err();
    assert!(matches!(
        err,
        NamespaceVerifyError::InvalidPackageName { .. }
    ));
}

#[test]
fn package_name_serde_transparent() {
    let name = PackageName::parse("my-pkg").unwrap();
    let json = serde_json::to_string(&name).unwrap();
    assert_eq!(json, r#""my-pkg""#);
    let parsed: PackageName = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, name);
}

#[test]
fn verification_token_valid() {
    let token = VerificationToken::parse("auths-verify-deadbeef0123").unwrap();
    assert_eq!(token.as_str(), "auths-verify-deadbeef0123");
}

#[test]
fn verification_token_bad_prefix() {
    let err = VerificationToken::parse("wrong-prefix-abc123").unwrap_err();
    assert!(matches!(err, NamespaceVerifyError::InvalidToken { .. }));
}

#[test]
fn verification_token_empty_suffix() {
    let err = VerificationToken::parse("auths-verify-").unwrap_err();
    assert!(matches!(err, NamespaceVerifyError::InvalidToken { .. }));
}

#[test]
fn verification_token_non_hex_suffix() {
    let err = VerificationToken::parse("auths-verify-notvalidhex!").unwrap_err();
    assert!(matches!(err, NamespaceVerifyError::InvalidToken { .. }));
}

#[test]
fn namespace_verify_error_codes() {
    let cases: Vec<(NamespaceVerifyError, &str)> = vec![
        (
            NamespaceVerifyError::UnsupportedEcosystem {
                ecosystem: "test".to_string(),
            },
            "AUTHS-E3961",
        ),
        (
            NamespaceVerifyError::PackageNotFound {
                ecosystem: Ecosystem::Npm,
                package_name: "test".to_string(),
            },
            "AUTHS-E4402",
        ),
        (
            NamespaceVerifyError::OwnershipNotConfirmed {
                ecosystem: Ecosystem::Npm,
                package_name: "test".to_string(),
            },
            "AUTHS-E4403",
        ),
        (NamespaceVerifyError::ChallengeExpired, "AUTHS-E4404"),
        (
            NamespaceVerifyError::InvalidToken {
                reason: "test".to_string(),
            },
            "AUTHS-E4405",
        ),
        (
            NamespaceVerifyError::InvalidPackageName {
                name: "test".to_string(),
                reason: "test".to_string(),
            },
            "AUTHS-E4406",
        ),
        (
            NamespaceVerifyError::NetworkError {
                message: "test".to_string(),
            },
            "AUTHS-E4407",
        ),
        (
            NamespaceVerifyError::RateLimited {
                ecosystem: Ecosystem::Npm,
            },
            "AUTHS-E4408",
        ),
    ];

    for (err, expected_code) in cases {
        assert_eq!(err.error_code(), expected_code, "error code for {err}");
        // All errors should have suggestions
        assert!(err.suggestion().is_some(), "suggestion for {err}");
    }
}

#[test]
fn platform_context_default() {
    let ctx = PlatformContext::default();
    assert!(ctx.github_username.is_none());
    assert!(ctx.npm_username.is_none());
    assert!(ctx.pypi_username.is_none());
}

#[test]
fn platform_context_partial() {
    let ctx = PlatformContext {
        github_username: Some("octocat".to_string()),
        npm_username: None,
        pypi_username: None,
    };
    assert_eq!(ctx.github_username.as_deref(), Some("octocat"));
}

#[test]
fn namespace_verifier_dyn_compatible() {
    // Compile-time check: Arc<dyn NamespaceVerifier> must be valid
    fn _accepts_arc(_v: Arc<dyn NamespaceVerifier>) {}
}
