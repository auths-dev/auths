use super::helpers::TestEnv;

#[test]
fn test_sign_verify_roundtrip() {
    let env = TestEnv::new();
    env.init_identity();

    // Create a test file and make a signed commit
    std::fs::write(env.repo_path.join("test.txt"), "hello world").unwrap();

    let add_output = env.git_cmd().args(["add", "test.txt"]).output().unwrap();
    assert!(add_output.status.success(), "git add failed");

    let commit_output = env
        .git_cmd()
        .args(["commit", "-m", "signed test commit"])
        .output()
        .unwrap();
    assert!(
        commit_output.status.success(),
        "git commit failed: {}",
        String::from_utf8_lossy(&commit_output.stderr)
    );

    // Verify the commit signature
    let signers = env.allowed_signers_path();
    let output = env
        .cmd("auths")
        .args([
            "verify",
            "HEAD",
            "--allowed-signers",
            signers.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "verify should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify JSON output
    let json_output = env
        .cmd("auths")
        .args([
            "verify",
            "HEAD",
            "--allowed-signers",
            signers.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(json_output.status.success());
    let stdout = String::from_utf8_lossy(&json_output.stdout);
    let result: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(result["valid"], true);
}

#[test]
fn test_verify_unsigned_commit_fails() {
    let env = TestEnv::new();
    env.init_identity();

    // Disable signing for this commit
    let _ = env
        .git_cmd()
        .args(["config", "--local", "commit.gpgsign", "false"])
        .output()
        .unwrap();

    std::fs::write(env.repo_path.join("unsigned.txt"), "no signature").unwrap();
    let add = env
        .git_cmd()
        .args(["add", "unsigned.txt"])
        .output()
        .unwrap();
    assert!(add.status.success());

    let commit = env
        .git_cmd()
        .args(["commit", "-m", "unsigned commit"])
        .output()
        .unwrap();
    assert!(commit.status.success());

    // Re-enable signing for future commits (not needed, but clean)
    let _ = env
        .git_cmd()
        .args(["config", "--local", "--unset", "commit.gpgsign"])
        .output();

    let signers = env.allowed_signers_path();
    let output = env
        .cmd("auths")
        .args([
            "verify",
            "HEAD",
            "--allowed-signers",
            signers.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "verify should fail for unsigned commit"
    );
}
