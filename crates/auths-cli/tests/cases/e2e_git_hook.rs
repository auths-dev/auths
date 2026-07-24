use crate::cases::helpers::TestEnv;

#[test]
fn test_e2e_agent_commit_hook() {
    let env = TestEnv::new();
    env.init_identity();

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

    let env_sh_path = env.home.path().join(".auths-agents/ci-agent/env.sh");
    assert!(env_sh_path.exists(), "env.sh should be generated");

    std::fs::write(env.repo_path.join("dummy.txt"), "hello e2e test").unwrap();

    let output = env.git_cmd().args(["add", "dummy.txt"]).output().unwrap();
    assert!(output.status.success(), "Git add failed");

    // Execute bash that sources the env.sh to emulate the actual execution environment.
    let mut bash_cmd = std::process::Command::new("bash");
    bash_cmd.current_dir(&env.repo_path);

    // We need to inject the same PATH that TestEnv uses so it can find auths and auths-sign
    let path = std::env::var("PATH").unwrap_or_default();
    let target_dir = assert_cmd::cargo::cargo_bin("auths-sign");
    let bin_dir = target_dir
        .parent()
        .unwrap()
        .to_path_buf();
    let env_path = format!("{}:{}", bin_dir.display(), path);

    bash_cmd
        .env("HOME", env.home.path())
        .env("PATH", env_path)
        // Ensure no global configs leak in
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", env.home.path().join(".gitconfig"))
        .arg("-c")
        .arg("source ~/.auths-agents/ci-agent/env.sh && git commit -m 'Test commit'");

    let output = bash_cmd.output().unwrap();
    assert!(
        output.status.success(),
        "Bash commit failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify the commit object
    let output = env
        .git_cmd()
        .args(["cat-file", "commit", "HEAD"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();

    // The prepare-commit-msg hook should have injected these
    assert!(
        stdout.contains("Auths-Id: did:keri:"),
        "Missing Auths-Id trailer in commit object"
    );
    assert!(
        stdout.contains("Auths-Device: did:keri:"),
        "Missing Auths-Device trailer in commit object"
    );
    // The gpg.ssh.program (auths-sign) should have attached the signature
    assert!(
        stdout.contains("-----BEGIN SSH SIGNATURE-----"),
        "Missing SSH signature block in commit object"
    );
}
