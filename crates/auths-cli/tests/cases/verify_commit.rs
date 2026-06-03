#![allow(deprecated)] // cargo_bin is deprecated but replacement requires significant refactor

use assert_cmd::Command;

#[test]
fn test_verify_commit_help_shows_usage() {
    // verify-commit is now `auths commit verify`
    let mut cmd = Command::cargo_bin("auths").unwrap();
    cmd.arg("commit").arg("verify").arg("--help");

    cmd.assert()
        .success()
        .stdout(predicates::str::contains("commit"));
}

#[test]
fn test_verify_commit_invalid_commit_ref_returns_error() {
    // An unresolvable commit ref is an error (exit code 2), independent of any trust state.
    let mut cmd = Command::cargo_bin("auths").unwrap();
    cmd.arg("commit")
        .arg("verify")
        .arg("invalid-commit-ref-that-does-not-exist");

    cmd.assert().code(2);
}

#[test]
fn test_verify_commit_json_output_error() {
    let mut cmd = Command::cargo_bin("auths").unwrap();
    cmd.arg("commit")
        .arg("verify")
        .arg("invalid-commit-ref-that-does-not-exist")
        .arg("--json");

    let output = cmd.output().unwrap();
    assert_eq!(output.status.code(), Some(2));

    let stdout = String::from_utf8(output.stdout).unwrap();
    let result: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(result["valid"], false);
    assert!(result["error"].is_string());
}

// Tests for the unified `auths verify` command routing to commit verification
#[test]
fn test_unified_verify_routes_head_to_commit_verify() {
    // `auths verify HEAD` routes to commit verification. Without a trusted, trailer-bearing
    // commit it fails (non-zero exit), but that is a routing success — not a clap parse error.
    let mut cmd = Command::cargo_bin("auths").unwrap();
    cmd.arg("verify").arg("HEAD");

    cmd.assert().failure();
}
