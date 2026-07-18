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

    // Init configures git signing globally by default — matching the interactive
    // prompt's own default, and the command's job ("configure Git"). Writes land in
    // our temp .gitconfig via GIT_CONFIG_GLOBAL.
    let gitconfig = std::fs::read_to_string(env.home.path().join(".gitconfig")).unwrap();
    for expected in ["ssh", "auths-sign", "signingkey"] {
        assert!(
            gitconfig.contains(expected),
            "gitconfig should contain {expected}, got: {gitconfig}"
        );
    }

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
        "output should contain the identity in product form (auths:<prefix>), got: {stderr}"
    );
    assert!(
        !stderr.contains("did:keri:"),
        "first-run human output must not surface the did:keri method, got: {stderr}"
    );
}

/// The scope is choosable non-interactively. It previously was not: init
/// hard-returned Global with no override, so a scripted, CI or agent run had no
/// way to keep its hands off the user's ~/.gitconfig.
#[test]
fn test_init_git_scope_local_leaves_global_config_alone() {
    let env = TestEnv::new();

    let before = std::fs::read_to_string(env.home.path().join(".gitconfig")).unwrap();
    let output = env
        .cmd("auths")
        .args([
            "init",
            "--profile",
            "developer",
            "--non-interactive",
            "--git-scope",
            "local",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "init --git-scope local failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let after = std::fs::read_to_string(env.home.path().join(".gitconfig")).unwrap();
    assert_eq!(
        before, after,
        "--git-scope local must not touch ~/.gitconfig"
    );

    let local = std::fs::read_to_string(env.repo_path.join(".git").join("config")).unwrap();
    for expected in ["ssh", "auths-sign", "signingkey"] {
        assert!(
            local.contains(expected),
            "repo-local git config should contain {expected}, got: {local}"
        );
    }
}

/// `--git-scope skip` touches no git configuration at all.
#[test]
fn test_init_git_scope_skip_touches_no_git_config() {
    let env = TestEnv::new();

    let before = std::fs::read_to_string(env.home.path().join(".gitconfig")).unwrap();
    let output = env
        .cmd("auths")
        .args([
            "init",
            "--profile",
            "developer",
            "--non-interactive",
            "--git-scope",
            "skip",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "init --git-scope skip failed");

    let after = std::fs::read_to_string(env.home.path().join(".gitconfig")).unwrap();
    assert_eq!(
        before, after,
        "--git-scope skip must not touch ~/.gitconfig"
    );

    // The identity still exists — only the git wiring was skipped.
    assert!(
        env.repo_path.join(".auths").join("roots").exists(),
        "--git-scope skip must still pin the trusted root"
    );
}
