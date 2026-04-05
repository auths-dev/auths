//! Tests for CiToken, Forge URL parsing, identity bundler, and passphrase generation.

use auths_sdk::domains::ci::bundle::{build_identity_bundle, generate_ci_passphrase};
use auths_sdk::domains::ci::error::CiError;
use auths_sdk::domains::ci::forge::Forge;
use auths_sdk::domains::ci::token::CiToken;

// ── CiToken serialization ──

#[test]
fn ci_token_serialize_roundtrip() {
    let token = CiToken::new(
        "abcdef1234567890".to_string(),
        "base64keychain==".to_string(),
        "base64repo==".to_string(),
        serde_json::json!({"identity_did": "did:keri:test"}),
        "2026-01-01T00:00:00Z".to_string(),
        31536000,
    );

    let json = token.to_json().unwrap();
    let parsed = CiToken::from_json(&json).unwrap();

    assert_eq!(parsed.version, 1);
    assert_eq!(parsed.passphrase, "abcdef1234567890");
    assert_eq!(parsed.keychain, "base64keychain==");
    assert_eq!(parsed.identity_repo, "base64repo==");
    assert_eq!(parsed.created_at, "2026-01-01T00:00:00Z");
    assert_eq!(parsed.max_valid_for_secs, 31536000);
}

#[test]
fn ci_token_rejects_unsupported_version() {
    let json = r#"{
        "version": 99,
        "passphrase": "test",
        "keychain": "test",
        "identity_repo": "test",
        "verify_bundle": {},
        "created_at": "2026-01-01T00:00:00Z",
        "max_valid_for_secs": 31536000
    }"#;

    let result = CiToken::from_json(json);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, CiError::TokenVersionUnsupported { version: 99 }),
        "Expected TokenVersionUnsupported, got: {err:?}"
    );
}

#[test]
fn ci_token_rejects_invalid_json() {
    let result = CiToken::from_json("not valid json");
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        CiError::TokenDeserializationFailed { .. }
    ));
}

#[test]
fn ci_token_estimated_size() {
    let token = CiToken::new(
        "a".repeat(64),
        "b".repeat(1000),
        "c".repeat(30000),
        serde_json::json!({"key": "value"}),
        "2026-01-01T00:00:00Z".to_string(),
        31536000,
    );

    let estimated = token.estimated_size();
    let actual_json = token.to_json().unwrap();
    let actual_size = actual_json.len();

    // Estimate should be within 20% of actual
    let tolerance = actual_size / 5;
    assert!(
        estimated.abs_diff(actual_size) < tolerance,
        "Estimated {estimated} vs actual {actual_size} (tolerance {tolerance})"
    );
}

// ── Forge URL parsing ──

#[test]
fn forge_from_github_https() {
    let forge = Forge::from_url("https://github.com/owner/repo.git");
    assert_eq!(
        forge,
        Forge::GitHub {
            owner_repo: "owner/repo".to_string()
        }
    );
    assert_eq!(forge.display_name(), "GitHub");
    assert_eq!(forge.repo_identifier(), "owner/repo");
}

#[test]
fn forge_from_github_https_no_suffix() {
    let forge = Forge::from_url("https://github.com/owner/repo");
    assert_eq!(
        forge,
        Forge::GitHub {
            owner_repo: "owner/repo".to_string()
        }
    );
}

#[test]
fn forge_from_github_ssh() {
    let forge = Forge::from_url("git@github.com:auths-dev/auths.git");
    assert_eq!(
        forge,
        Forge::GitHub {
            owner_repo: "auths-dev/auths".to_string()
        }
    );
}

#[test]
fn forge_from_gitlab_https() {
    let forge = Forge::from_url("https://gitlab.com/group/project.git");
    assert_eq!(
        forge,
        Forge::GitLab {
            group_project: "group/project".to_string()
        }
    );
}

#[test]
fn forge_from_gitlab_ssh() {
    let forge = Forge::from_url("git@gitlab.com:group/subgroup/project.git");
    assert_eq!(
        forge,
        Forge::GitLab {
            group_project: "group/subgroup/project".to_string()
        }
    );
}

#[test]
fn forge_from_bitbucket() {
    let forge = Forge::from_url("git@bitbucket.org:workspace/repo.git");
    assert_eq!(
        forge,
        Forge::Bitbucket {
            workspace_repo: "workspace/repo".to_string()
        }
    );
}

#[test]
fn forge_from_unknown_host() {
    let forge = Forge::from_url("https://selfhosted.example.com/org/repo.git");
    assert_eq!(
        forge,
        Forge::Unknown {
            url: "selfhosted.example.com/org/repo".to_string()
        }
    );
}

#[test]
fn forge_from_enterprise_github() {
    let forge = Forge::from_url("https://github.acme.com/internal/tools.git");
    assert_eq!(
        forge,
        Forge::GitHub {
            owner_repo: "internal/tools".to_string()
        }
    );
}

#[test]
fn forge_from_ssh_with_explicit_protocol() {
    let forge = Forge::from_url("ssh://git@github.com/owner/repo.git");
    assert_eq!(
        forge,
        Forge::GitHub {
            owner_repo: "owner/repo".to_string()
        }
    );
}

#[test]
fn forge_strips_trailing_slash() {
    let forge = Forge::from_url("https://github.com/owner/repo/");
    assert_eq!(forge.repo_identifier(), "owner/repo");
}

// ── Passphrase generation ──

#[test]
fn ci_passphrase_is_hex_64_chars() {
    let pass = generate_ci_passphrase();
    assert_eq!(pass.len(), 64);
    assert!(
        pass.chars().all(|c| c.is_ascii_hexdigit()),
        "Passphrase contains non-hex chars: {pass}"
    );
}

#[test]
fn ci_passphrase_is_unique() {
    let a = generate_ci_passphrase();
    let b = generate_ci_passphrase();
    assert_ne!(a, b, "Two generated passphrases should differ");
}

// ── Identity bundle ──

#[test]
fn build_identity_bundle_produces_valid_base64() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    // Create some test files
    std::fs::write(dir.join("config"), b"test config").unwrap();
    std::fs::create_dir_all(dir.join("objects")).unwrap();
    std::fs::write(dir.join("objects/abc"), b"object data").unwrap();

    let b64 = build_identity_bundle(dir).unwrap();

    // Should be valid base64
    use base64::Engine as _;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .expect("Should be valid base64");
    assert!(!decoded.is_empty());

    // Should be valid gzip
    use std::io::Read;
    let mut gz = flate2::read::GzDecoder::new(&decoded[..]);
    let mut decompressed = Vec::new();
    gz.read_to_end(&mut decompressed)
        .expect("Should be valid gzip");
    assert!(!decompressed.is_empty());
}

#[test]
fn build_identity_bundle_excludes_socks_and_locks() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();

    std::fs::write(dir.join("config"), b"keep").unwrap();
    std::fs::write(dir.join("agent.sock"), b"exclude").unwrap();
    std::fs::write(dir.join("registry.lock"), b"exclude").unwrap();

    let b64 = build_identity_bundle(dir).unwrap();

    // Decode and read tar entries
    use base64::Engine as _;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .unwrap();
    let gz = flate2::read::GzDecoder::new(&decoded[..]);
    let mut archive = tar::Archive::new(gz);

    let entry_names: Vec<String> = archive
        .entries()
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path().unwrap().display().to_string())
        .collect();

    assert!(
        entry_names.iter().any(|n| n.contains("config")),
        "Should include config, got: {entry_names:?}"
    );
    assert!(
        !entry_names.iter().any(|n| n.contains("sock")),
        "Should exclude .sock files, got: {entry_names:?}"
    );
    assert!(
        !entry_names.iter().any(|n| n.contains("lock")),
        "Should exclude .lock files, got: {entry_names:?}"
    );
}
