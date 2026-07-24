use crate::cases::helpers::TestEnv;

#[test]
fn test_e2e_auths_sign_preserves_ssh_signature() {
    let env = TestEnv::new();

    // 1. Create a raw commit BEFORE provisioning ANY identity or agent.
    // This ensures no hooks run, so the commit has no trailers.
    std::fs::write(env.repo_path.join("dummy.txt"), "hello e2e auths sign test").unwrap();
    let output = env.git_cmd().args(["add", "dummy.txt"]).output().unwrap();
    assert!(output.status.success(), "Git add failed");

    let output = env
        .git_cmd()
        .args([
            "commit",
            "--no-verify",
            "-m",
            "Initial commit without trailers",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "Git commit failed");

    // Initialize the identity AFTER the raw commit is made
    env.init_identity();

    // Verify the commit has NO trailers and NO signature yet
    let output = env
        .git_cmd()
        .args(["cat-file", "commit", "HEAD"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains("Auths-Id: did:keri:"));
    assert!(!stdout.contains("-----BEGIN SSH SIGNATURE-----"));

    // 2. Provision the agent, which configures `gpg.ssh.program` and hooks
    let output = env
        .cmd("auths")
        .args([
            "agent",
            "provision",
            "--label",
            "ci-agent",
            "--profile",
            "ci",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "Agent provision failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // 3. Run `auths sign` to retroactively sign HEAD.
    // We must execute it inside bash sourcing `env.sh` to have access to auths-sign in PATH
    let mut bash_cmd = std::process::Command::new("bash");
    bash_cmd.current_dir(&env.repo_path);

    let path = std::env::var("PATH").unwrap_or_default();
    let target_dir = assert_cmd::cargo::cargo_bin("auths-sign");
    let bin_dir = target_dir.parent().unwrap().to_path_buf();
    // Also include the auths binary directory so `auths` command is found
    let auths_dir = assert_cmd::cargo::cargo_bin("auths");
    let auths_bin_dir = auths_dir.parent().unwrap().to_path_buf();
    let env_path = format!("{}:{}:{}", bin_dir.display(), auths_bin_dir.display(), path);

    bash_cmd
        .env("HOME", env.home.path())
        .env("PATH", env_path)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", env.home.path().join(".gitconfig"))
        .arg("-c")
        .arg("source ~/.auths-agents/ci-agent/env.sh && auths sign HEAD");

    let output = bash_cmd.output().unwrap();
    assert!(
        output.status.success(),
        "Bash auths sign failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // 4. Verify the rewritten commit has trailers AND an SSH signature
    let output = env
        .git_cmd()
        .args(["cat-file", "commit", "HEAD"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();

    // If `auths sign` accidentally gets migrated to `libgit2` in the future,
    // this test will FAIL because libgit2 does not automatically invoke gpg.ssh.program
    assert!(
        stdout.contains("Auths-Id: did:keri:"),
        "Missing Auths-Id trailer in rewritten commit"
    );
    assert!(
        stdout.contains("Auths-Device: did:keri:"),
        "Missing Auths-Device trailer in rewritten commit"
    );
    assert!(
        stdout.contains("-----BEGIN SSH SIGNATURE-----"),
        "Missing SSH signature block in rewritten commit. (Did someone replace `git commit --amend` with libgit2?)"
    );
}
