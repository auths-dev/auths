use super::helpers::TestEnv;

#[test]
fn test_init_github_action_scaffold() {
    let env = TestEnv::new();

    // Set up a GitHub-like remote so the command doesn't warn
    let mut git = env.git_cmd();
    git.args([
        "remote",
        "add",
        "origin",
        "https://github.com/test-org/test-repo.git",
    ]);
    let output = git.output().unwrap();
    assert!(output.status.success(), "failed to add remote");

    let output = env
        .cmd("auths")
        .args(["init", "--github-action"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "init --github-action should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Workflow file should exist
    let workflow = env.repo_path.join(".github/workflows/auths-release.yml");
    assert!(
        workflow.exists(),
        "workflow file should be created at .github/workflows/auths-release.yml"
    );

    let content = std::fs::read_to_string(&workflow).unwrap();
    assert!(
        content.contains("auths-dev/verify@v1"),
        "workflow should reference verify action"
    );
    assert!(
        content.contains("--ci"),
        "workflow should reference ephemeral CI signing"
    );

    // .auths/.gitkeep should exist
    let gitkeep = env.repo_path.join(".auths/.gitkeep");
    assert!(gitkeep.exists(), ".auths/.gitkeep should be created");
}

#[test]
fn test_init_github_action_idempotent() {
    let env = TestEnv::new();

    // Run twice — second run should not fail
    let output1 = env
        .cmd("auths")
        .args(["init", "--github-action"])
        .output()
        .unwrap();
    assert!(output1.status.success());

    let output2 = env
        .cmd("auths")
        .args(["init", "--github-action"])
        .output()
        .unwrap();
    assert!(
        output2.status.success(),
        "second run should succeed (idempotent)"
    );
}

#[test]
fn test_init_happy_path() {
    let env = TestEnv::new();

    let output = env
        .cmd("auths")
        .args(["init", "--non-interactive", "--profile", "developer"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "init should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // AUTHS_HOME should be a git repo
    assert!(
        env.auths_home.join(".git").exists(),
        "AUTHS_HOME should be initialized as git repo"
    );

    // Init sets git config --global, which writes to our temp .gitconfig
    // (redirected via GIT_CONFIG_GLOBAL env var in the subprocess)
    let gitconfig = std::fs::read_to_string(env.home.path().join(".gitconfig")).unwrap();
    assert!(
        gitconfig.contains("ssh"),
        "gitconfig should contain ssh signing format, got: {}",
        gitconfig
    );
    assert!(
        gitconfig.contains("auths-sign"),
        "gitconfig should reference auths-sign program, got: {}",
        gitconfig
    );
    assert!(
        gitconfig.contains("signingkey"),
        "gitconfig should contain signing key, got: {}",
        gitconfig
    );

    // KEL-native trust: init pins the local identity as a trusted root in
    // <repo>/.auths/roots (no allowed_signers allowlist is written anymore).
    let roots_path = env.repo_path.join(".auths").join("roots");
    assert!(roots_path.exists(), ".auths/roots pin should exist");
    let roots = std::fs::read_to_string(&roots_path).unwrap();
    assert!(
        roots.contains("did:keri:"),
        ".auths/roots should pin a did:keri root, got: {roots}"
    );

    // Output uses eprintln, so the identity appears in stderr. First-run
    // human-facing output renders identifiers in product form (`auths:<prefix>`),
    // not the canonical `did:keri:` method (which stays in --json / files / wire),
    // so a newcomer is never shown protocol vocabulary on the way to the aha.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("auths:"),
        "output should contain the identity in product form (auths:<prefix>), got: {}",
        stderr
    );
    assert!(
        !stderr.contains("did:keri:"),
        "first-run human output must not surface the did:keri method, got: {}",
        stderr
    );
}
