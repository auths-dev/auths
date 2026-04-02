use super::helpers::TestEnv;

/// Golden path end-to-end: init → commit → sign → verify → JSON output.
///
/// Guards the most critical user flow against regressions.
#[test]
fn test_golden_path_init_sign_verify() {
    let env = TestEnv::new();
    env.init_identity();

    // Create a file, stage, and commit (auto-signed via gpgsign=true)
    std::fs::write(env.repo_path.join("hello.txt"), "hello world").unwrap();

    let add = env.git_cmd().args(["add", "hello.txt"]).output().unwrap();
    assert!(add.status.success(), "git add failed");

    let commit = env
        .git_cmd()
        .args(["commit", "-m", "initial commit"])
        .output()
        .unwrap();
    assert!(
        commit.status.success(),
        "git commit failed: {}",
        String::from_utf8_lossy(&commit.stderr)
    );

    // Explicitly re-sign via `auths sign HEAD`
    let sign_output = env.cmd("auths").args(["sign", "HEAD"]).output().unwrap();
    assert!(
        sign_output.status.success(),
        "auths sign HEAD failed: {}",
        String::from_utf8_lossy(&sign_output.stderr)
    );

    // Verify with JSON output
    let signers = env.allowed_signers_path();
    let verify_output = env
        .cmd("auths")
        .args([
            "verify",
            "HEAD",
            "--json",
            "--allowed-signers",
            signers.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        verify_output.status.success(),
        "auths verify HEAD --json failed: {}",
        String::from_utf8_lossy(&verify_output.stderr)
    );

    // Parse and validate JSON structure
    let stdout = String::from_utf8(verify_output.stdout).unwrap();
    let result: serde_json::Value =
        serde_json::from_str(&stdout).expect("verify --json should produce valid JSON");

    assert_eq!(result["valid"], true, "golden path commit must be valid");
    assert!(
        result["commit"].is_string(),
        "JSON should contain a 'commit' field with the SHA"
    );
    assert_eq!(
        result["ssh_valid"], true,
        "SSH signature must be valid after explicit sign"
    );
    assert!(
        result["error"].is_null(),
        "no error expected on successful verify, got: {:?}",
        result["error"]
    );
}
