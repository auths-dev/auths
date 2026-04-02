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
        content.contains("auths-dev/attest-action@v1"),
        "workflow should reference attest-action"
    );
    assert!(
        content.contains("AUTHS_CI_PASSPHRASE"),
        "workflow should reference secrets"
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

    // Allowed signers file should exist and be non-empty
    let signers_path = env.home.path().join(".ssh").join("allowed_signers");
    assert!(signers_path.exists(), "allowed_signers should exist");
    let signers = std::fs::read_to_string(&signers_path).unwrap();
    assert!(!signers.is_empty(), "allowed_signers should not be empty");

    // Output uses eprintln, so DID appears in stderr
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("did:keri:"),
        "output should contain identity DID, got: {}",
        stderr
    );
}
