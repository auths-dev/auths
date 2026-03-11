use super::helpers::TestEnv;

#[test]
fn test_doctor_passes_after_init() {
    let env = TestEnv::new();
    env.init_identity();

    let output = env.cmd("auths").arg("doctor").output().unwrap();
    assert!(
        output.status.success(),
        "doctor should pass after init, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
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

    let output = env.cmd("auths").arg("doctor").output().unwrap();
    assert!(
        !output.status.success(),
        "doctor should fail with missing gpg.format"
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("gpg.format") || combined.contains("signing"),
        "output should mention the missing config, got: {}",
        combined
    );
}
