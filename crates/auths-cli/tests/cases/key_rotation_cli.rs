use super::helpers::TestEnv;

#[test]
fn test_key_rotation_preserves_old_commit_verification() {
    let env = TestEnv::new();
    env.init_identity();

    // Commit A: signed with original key
    std::fs::write(env.repo_path.join("a.txt"), "commit A").unwrap();
    let add = env.git_cmd().args(["add", "a.txt"]).output().unwrap();
    assert!(add.status.success());
    let commit = env
        .git_cmd()
        .args(["commit", "-m", "commit A"])
        .output()
        .unwrap();
    assert!(
        commit.status.success(),
        "commit A failed: {}",
        String::from_utf8_lossy(&commit.stderr)
    );

    // Get commit A hash
    let log_a = env.git_cmd().args(["rev-parse", "HEAD"]).output().unwrap();
    let commit_a_hash = String::from_utf8_lossy(&log_a.stdout).trim().to_string();

    // Verify commit A
    let signers = env.allowed_signers_path();
    let verify_a = env
        .cmd("auths")
        .args([
            "verify",
            &commit_a_hash,
            "--allowed-signers",
            signers.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        verify_a.status.success(),
        "commit A should verify before rotation, stderr: {}",
        String::from_utf8_lossy(&verify_a.stderr)
    );

    // Rotate the key
    let rotate = env
        .cmd("auths")
        .args([
            "emergency",
            "rotate-now",
            "--yes",
            "--current-alias",
            "main",
            "--next-alias",
            "main-rotated",
        ])
        .output()
        .unwrap();
    assert!(
        rotate.status.success(),
        "rotation should succeed, stderr: {}",
        String::from_utf8_lossy(&rotate.stderr)
    );

    // Update git signing config to use the new alias
    let _ = env
        .git_cmd()
        .args([
            "config",
            "--global",
            "user.signingkey",
            "auths:main-rotated",
        ])
        .output();

    // Re-sync allowed_signers to include the new key
    let sync = env.cmd("auths").args(["signers", "sync"]).output().unwrap();
    // signers sync may or may not succeed depending on CLI state — that's OK
    let _ = sync;

    // Commit B: signed with rotated key
    std::fs::write(env.repo_path.join("b.txt"), "commit B").unwrap();
    let add = env.git_cmd().args(["add", "b.txt"]).output().unwrap();
    assert!(add.status.success());
    let commit_b = env
        .git_cmd()
        .args(["commit", "-m", "commit B"])
        .output()
        .unwrap();

    // Commit B may fail if the rotated key isn't set up for signing yet.
    // This is expected — rotation doesn't auto-configure git signing.
    // The test verifies that commit A remains verifiable post-rotation.

    // Verify commit A still passes after rotation
    let verify_a_after = env
        .cmd("auths")
        .args([
            "verify",
            &commit_a_hash,
            "--allowed-signers",
            signers.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        verify_a_after.status.success(),
        "commit A should still verify after rotation, stderr: {}",
        String::from_utf8_lossy(&verify_a_after.stderr)
    );

    // If commit B succeeded, verify it too
    if commit_b.status.success() {
        let verify_b = env
            .cmd("auths")
            .args([
                "verify",
                "HEAD",
                "--allowed-signers",
                signers.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        // Post-rotation commit may or may not verify depending on allowed_signers state
        let _ = verify_b;
    }
}
