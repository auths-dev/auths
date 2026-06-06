use super::helpers::TestEnv;

fn setup_signed_commit() -> TestEnv {
    let env = TestEnv::new();
    env.init_identity();

    std::fs::write(env.repo_path.join("test.txt"), "hello").unwrap();
    let add = env.git_cmd().args(["add", "test.txt"]).output().unwrap();
    assert!(add.status.success());
    let commit = env
        .git_cmd()
        .args(["commit", "-m", "signed commit"])
        .output()
        .unwrap();
    assert!(
        commit.status.success(),
        "commit failed: {}",
        String::from_utf8_lossy(&commit.stderr)
    );

    // Add the in-band Auths-Id / Auths-Device trailers for KEL-native verification.
    let sign = env.cmd("auths").args(["sign", "HEAD"]).output().unwrap();
    assert!(
        sign.status.success(),
        "auths sign failed: {}",
        String::from_utf8_lossy(&sign.stderr)
    );

    env
}

#[test]
fn test_verify_json_output_on_signed_commit() {
    let env = setup_signed_commit();

    let output = env
        .cmd("auths")
        .args(["verify", "HEAD", "--json"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let result: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert!(
        result["commit"].is_string(),
        "commit field should be a string"
    );
    assert_eq!(result["valid"], true, "valid should be true");
    assert!(
        result["ssh_valid"].is_boolean(),
        "ssh_valid should be a boolean"
    );
}

#[test]
fn test_verify_json_output_on_unsigned_commit() {
    let env = TestEnv::new();
    env.init_identity();

    // Disable signing
    let _ = env
        .git_cmd()
        .args(["config", "--local", "commit.gpgsign", "false"])
        .output();

    std::fs::write(env.repo_path.join("unsigned.txt"), "no sig").unwrap();
    let add = env
        .git_cmd()
        .args(["add", "unsigned.txt"])
        .output()
        .unwrap();
    assert!(add.status.success());
    let commit = env
        .git_cmd()
        .args(["commit", "-m", "unsigned"])
        .output()
        .unwrap();
    assert!(commit.status.success());

    // No `auths sign` → no trailer → KEL-native verify rejects it.
    let output = env
        .cmd("auths")
        .args(["verify", "HEAD", "--json"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let result: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert_eq!(result["valid"], false, "valid should be false for unsigned");
    assert!(
        result["error"].is_string(),
        "error field should describe the issue"
    );
}

#[test]
fn test_verify_json_output_on_invalid_ref() {
    let env = TestEnv::new();
    env.init_identity();

    let output = env
        .cmd("auths")
        .args(["verify", "NONEXISTENT_REF", "--json"])
        .output()
        .unwrap();

    assert!(!output.status.success());

    // Error JSON may be on stdout (from handle_error) or stderr (from renderer)
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    let json_str = if stdout.trim().starts_with('{') {
        &stdout
    } else {
        &stderr
    };

    let result: serde_json::Value = serde_json::from_str(json_str.trim()).unwrap();
    assert!(
        result["error"].is_string() || result["message"].is_string(),
        "should contain error info, got: {}",
        json_str
    );
}
