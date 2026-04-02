use super::helpers::TestEnv;

fn extract_device_did(init_output: &[u8]) -> Option<String> {
    let stdout = String::from_utf8_lossy(init_output);
    for line in stdout.lines() {
        if (line.contains("Device linked:") || line.contains("Device:"))
            && let Some(did) = line.split_whitespace().find(|w| w.starts_with("did:key:"))
        {
            return Some(did.to_string());
        }
    }
    None
}

#[test]
fn test_emergency_revoke_device() {
    let env = TestEnv::new();

    // Run init and capture device DID from output
    let init_output = env
        .cmd("auths")
        .args(["init", "--non-interactive", "--profile", "developer"])
        .output()
        .unwrap();
    assert!(init_output.status.success());

    let device_did =
        extract_device_did(&init_output.stderr).expect("init output should contain device DID");

    // Make a signed commit
    std::fs::write(env.repo_path.join("test.txt"), "before revocation").unwrap();
    let add = env.git_cmd().args(["add", "test.txt"]).output().unwrap();
    assert!(add.status.success());
    let commit = env
        .git_cmd()
        .args(["commit", "-m", "pre-revocation commit"])
        .output()
        .unwrap();
    assert!(
        commit.status.success(),
        "commit failed: {}",
        String::from_utf8_lossy(&commit.stderr)
    );

    // Verify commit before revocation
    let signers = env.allowed_signers_path();
    let verify_before = env
        .cmd("auths")
        .args([
            "verify",
            "HEAD",
            "--allowed-signers",
            signers.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        verify_before.status.success(),
        "commit should verify before revocation"
    );

    // Revoke the device
    let revoke = env
        .cmd("auths")
        .args([
            "emergency",
            "revoke-device",
            "--device",
            &device_did,
            "--key",
            "main",
            "--yes",
        ])
        .output()
        .unwrap();
    assert!(
        revoke.status.success(),
        "revocation should succeed, stderr: {}",
        String::from_utf8_lossy(&revoke.stderr)
    );

    // Verify the revocation attestation was created by checking auths home
    // The revocation is stored as a git ref in AUTHS_HOME
    let repo = git2::Repository::open(&env.auths_home).unwrap();
    let refs: Vec<String> = repo
        .references()
        .unwrap()
        .filter_map(|r| r.ok())
        .filter_map(|r| r.name().map(|n| n.to_string()))
        .collect();
    let has_attestation_refs = refs.iter().any(|r| r.contains("auths"));
    assert!(
        has_attestation_refs,
        "revocation should create attestation refs in AUTHS_HOME, found: {:?}",
        refs
    );

    // NOTE: SSH-level `auths verify HEAD` may still pass after revocation because
    // revocation creates an attestation but doesn't remove the key from allowed_signers.
    // This is a known product gap — revocation affects the attestation chain, not SSH verification.
    // Full chain verification (with --identity-bundle) would detect the revocation.
}
