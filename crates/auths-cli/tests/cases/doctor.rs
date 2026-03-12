use super::helpers::TestEnv;

#[test]
fn test_doctor_passes_signing_checks_after_init() {
    let env = TestEnv::new();
    env.init_identity();

    let output = env
        .cmd("auths")
        .args(["doctor", "--json"])
        .output()
        .unwrap();

    // Doctor may exit non-zero if ssh-keygen check fails on macOS,
    // but the signing-related checks should all pass after init.
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json_str = if stdout.trim().starts_with('{') {
        stdout.to_string()
    } else {
        stderr.to_string()
    };

    let result: serde_json::Value = serde_json::from_str(json_str.trim()).unwrap();
    let checks = result["data"]["checks"].as_array().unwrap();

    let signing_check = checks
        .iter()
        .find(|c| c["name"] == "Git signing config")
        .unwrap();
    assert_eq!(signing_check["passed"], true, "signing config should pass");

    let keychain_check = checks
        .iter()
        .find(|c| c["name"] == "System keychain")
        .unwrap();
    assert_eq!(keychain_check["passed"], true, "keychain should pass");

    let identity_check = checks
        .iter()
        .find(|c| c["name"] == "Auths identity")
        .unwrap();
    assert_eq!(identity_check["passed"], true, "identity should pass");

    let signers_check = checks
        .iter()
        .find(|c| c["name"] == "Allowed signers file")
        .unwrap();
    assert_eq!(signers_check["passed"], true, "allowed signers should pass");
}

#[test]
fn test_doctor_detects_missing_gpg_format() {
    let env = TestEnv::new();
    env.init_identity();

    // Remove gpg.format from global config
    let unset = env
        .git_cmd()
        .args(["config", "--global", "--unset", "gpg.format"])
        .output()
        .unwrap();
    assert!(unset.status.success(), "unset should succeed");

    let output = env
        .cmd("auths")
        .args(["doctor", "--json"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let result: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    let checks = result["data"]["checks"].as_array().unwrap();

    let signing_check = checks
        .iter()
        .find(|c| c["name"] == "Git signing config")
        .unwrap();
    assert_eq!(
        signing_check["passed"], false,
        "signing config should fail after removing gpg.format"
    );
}
