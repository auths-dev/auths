use super::helpers::TestEnv;

#[test]
fn test_init_happy_path() {
    let env = TestEnv::new();

    let output = env
        .cmd("auths")
        .args([
            "init",
            "--non-interactive",
            "--profile",
            "developer",
            "--skip-registration",
        ])
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
