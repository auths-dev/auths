//! CLI e2e for `auths verify --identity-bundle` (stateless CI commit verification).
//!
//! The `--identity-bundle` flag pins the bundle's identity as a trusted root for the
//! verify, so a CI runner with no committed `.auths/roots` can still constrain trust.
//! It must fail **closed**: a good bundle (root == the commit's delegating root) verifies;
//! a bundle pinning a different root is rejected (RootNotPinned); an unparseable bundle
//! aborts with exit 2 and never verifies.
//!
//! Runs hermetically — the `TestEnv` keychain is file-backed with `AUTHS_PASSPHRASE`, so
//! signing is non-interactive (no macOS keychain / SIP gate).

use super::helpers::TestEnv;

/// A signed HEAD commit in an isolated identity + repo, plus a freshly exported bundle.
fn setup_signed_commit_and_bundle() -> (TestEnv, std::path::PathBuf) {
    let env = TestEnv::new();
    env.init_identity();

    std::fs::write(env.repo_path.join("hello.txt"), "hello world").unwrap();
    let add = env.git_cmd().args(["add", "hello.txt"]).output().unwrap();
    assert!(add.status.success(), "git add failed");
    let commit = env
        .git_cmd()
        .args(["commit", "-m", "initial commit"])
        .output()
        .unwrap();
    assert!(
        commit.status.success(),
        "git commit failed: {}",
        String::from_utf8_lossy(&commit.stderr)
    );
    let sign = env.cmd("auths").args(["sign", "HEAD"]).output().unwrap();
    assert!(
        sign.status.success(),
        "auths sign HEAD failed: {}",
        String::from_utf8_lossy(&sign.stderr)
    );

    // A stateless CI runner has no committed pin; verify must rely on the bundle alone.
    let _ = std::fs::remove_file(env.repo_path.join(".auths").join("roots"));

    let good = env.home.path().join("good-bundle.json");
    let export = env
        .cmd("auths")
        .args([
            "id",
            "export-bundle",
            "--alias",
            "main",
            "--output",
            good.to_str().unwrap(),
            "--max-age-secs",
            "3600",
        ])
        .output()
        .unwrap();
    assert!(
        export.status.success(),
        "id export-bundle failed: {}",
        String::from_utf8_lossy(&export.stderr)
    );
    (env, good)
}

#[test]
fn good_identity_bundle_pins_root_and_verifies() {
    let (env, good) = setup_signed_commit_and_bundle();

    let out = env
        .cmd("auths")
        .args([
            "verify",
            "HEAD",
            "--identity-bundle",
            good.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "a bundle pinning the commit's own root must verify: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).expect("verify --json");
    assert_eq!(json["valid"], true, "good-bundle commit must be valid");
}

#[test]
fn wrong_identity_bundle_root_is_rejected() {
    let (env, good) = setup_signed_commit_and_bundle();

    // Same fresh bundle, but pinning a DIFFERENT root than the commit's delegator.
    let wrong = env.home.path().join("wrong-bundle.json");
    let mut bundle: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&good).unwrap()).unwrap();
    bundle["identity_did"] =
        serde_json::json!("did:keri:ENotThisRoot0000000000000000000000000000000");
    std::fs::write(&wrong, serde_json::to_string(&bundle).unwrap()).unwrap();

    let out = env
        .cmd("auths")
        .args([
            "verify",
            "HEAD",
            "--identity-bundle",
            wrong.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "a bundle pinning a different root must NOT verify (RootNotPinned)"
    );
}

#[test]
fn malformed_identity_bundle_fails_closed_exit_2() {
    let (env, _good) = setup_signed_commit_and_bundle();

    let bad = env.home.path().join("bad-bundle.json");
    std::fs::write(&bad, "this is not a valid identity bundle").unwrap();

    let out = env
        .cmd("auths")
        .args(["verify", "HEAD", "--identity-bundle", bad.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "an unparseable bundle must fail closed with exit 2, never verify"
    );
}
