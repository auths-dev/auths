#![allow(deprecated)] // cargo_bin is deprecated but replacement requires significant refactor

use assert_cmd::Command;

#[test]
fn test_verify_commit_help_shows_usage() {
    // verify-commit is now `auths commit verify`
    let mut cmd = Command::cargo_bin("auths").unwrap();
    cmd.arg("commit").arg("verify").arg("--help");

    cmd.assert()
        .success()
        .stdout(predicates::str::contains("commit"))
        .stdout(predicates::str::contains("allowed-signers"));
}

#[test]
fn test_verify_commit_missing_allowed_signers_returns_exit_code_2() {
    let mut cmd = Command::cargo_bin("auths").unwrap();
    cmd.arg("commit")
        .arg("verify")
        .arg("--allowed-signers")
        .arg("/nonexistent/allowed_signers");

    cmd.assert().code(2);
}

#[test]
fn test_verify_commit_invalid_commit_ref_returns_error() {
    let mut cmd = Command::cargo_bin("auths").unwrap();
    // Create a temp allowed_signers file
    let temp_dir = tempfile::tempdir().unwrap();
    let signers_file = temp_dir.path().join("allowed_signers");
    std::fs::write(&signers_file, "user@example.com ssh-ed25519 AAAAC3test").unwrap();

    cmd.arg("commit")
        .arg("verify")
        .arg("--allowed-signers")
        .arg(&signers_file)
        .arg("invalid-commit-ref-that-does-not-exist");

    // Will fail to resolve the commit (exit code 2 = error)
    cmd.assert().code(2);
}

#[test]
fn test_verify_commit_json_output_error() {
    let mut cmd = Command::cargo_bin("auths").unwrap();
    cmd.arg("commit")
        .arg("verify")
        .arg("--allowed-signers")
        .arg("/nonexistent/allowed_signers")
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
    // auths verify HEAD should route to commit verification
    // (will fail due to missing allowed_signers or no signature, but not parse error)
    let mut cmd = Command::cargo_bin("auths").unwrap();
    cmd.arg("verify")
        .arg("HEAD")
        .arg("--allowed-signers")
        .arg("/nonexistent/allowed_signers");

    // Exit code 2 = error (not a parse/clap failure)
    cmd.assert().code(2);
}
