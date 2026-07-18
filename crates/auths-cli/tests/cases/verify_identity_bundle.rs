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
fn bundle_freshness_grade_ignores_the_producer_timestamp() {
    // The bundle's `bundle_timestamp` / `max_valid_for_secs` are producer-set, unsigned fields.
    // An offline verifier holds no source it can trust to confirm freshness, so the grade must be
    // identical no matter what the producer wrote: a forged recent timestamp cannot buy "fresh",
    // and an aged one cannot be distinguished from it. Otherwise an attacker edits one JSON field
    // and a stale/revoked bundle reads fresh. The honest offline grade is Unknown; the relying
    // party's policy decides whether to tolerate it.
    let (env, good) = setup_signed_commit_and_bundle();

    let graded = |name: &str, ts: chrono::DateTime<chrono::Utc>, ttl: u64| -> serde_json::Value {
        let path = env.home.path().join(name);
        let mut bundle: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&good).unwrap()).unwrap();
        bundle["bundle_timestamp"] = serde_json::json!(ts.to_rfc3339());
        bundle["max_valid_for_secs"] = serde_json::json!(ttl);
        std::fs::write(&path, serde_json::to_string(&bundle).unwrap()).unwrap();
        let out = env
            .cmd("auths")
            .args([
                "verify",
                "HEAD",
                "--identity-bundle",
                path.to_str().unwrap(),
                "--json",
            ])
            .output()
            .unwrap();
        serde_json::from_slice(&out.stdout).expect("verify --json")
    };

    let now = chrono::Utc::now();
    // The attacker's move: stamp the bundle as just-created so it looks maximally fresh.
    let forged_fresh = graded("forged-fresh.json", now, 3600);
    // A genuinely old export, with an inflated TTL so the producer can't be the one capping trust.
    let aged = graded(
        "aged.json",
        now - chrono::Duration::hours(24 * 100),
        31_536_000,
    );

    assert_eq!(
        forged_fresh["freshness"], aged["freshness"],
        "freshness grade must not depend on the producer-set timestamp"
    );
    assert_eq!(
        forged_fresh["freshness"], "unknown",
        "an offline bundle's freshness is Unknown — never a producer-claimed Fresh or Stale"
    );
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

#[test]
fn identity_bundle_with_stripped_signatures_fails_closed() {
    // RT-002: a bundle whose KEL event signatures are removed cannot be
    // AUTHENTICATED and MUST fail closed — even though it pins the correct root
    // and is structurally valid. A purely structural verifier would (wrongly)
    // accept it; this is the regression proving event signatures are checked.
    let (env, good) = setup_signed_commit_and_bundle();

    let stripped = env.home.path().join("stripped-bundle.json");
    let mut bundle: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&good).unwrap()).unwrap();
    // Blank the per-event signature attachments; the KEL is now unauthenticatable.
    bundle["kel_attachments"] = serde_json::json!([]);
    std::fs::write(&stripped, serde_json::to_string(&bundle).unwrap()).unwrap();

    let out = env
        .cmd("auths")
        .args([
            "verify",
            "HEAD",
            "--identity-bundle",
            stripped.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "a bundle with stripped KEL signatures must NOT verify (RT-002): {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn identity_bundle_with_forged_signature_fails_closed() {
    // RT-002: tampering an event's signature attachment (bundle otherwise valid)
    // must fail closed — the signature no longer verifies against the committed
    // key-state.
    let (env, good) = setup_signed_commit_and_bundle();

    let forged = env.home.path().join("forged-bundle.json");
    let mut bundle: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&good).unwrap()).unwrap();
    if let Some(first) = bundle["kel_attachments"]
        .as_array_mut()
        .and_then(|a| a.first_mut())
    {
        // Flip the last hex nibble of the inception's signature attachment.
        let mut s = first.as_str().unwrap().to_string();
        if let Some(last) = s.pop() {
            s.push(if last == '0' { '1' } else { '0' });
        }
        *first = serde_json::json!(s);
    }
    std::fs::write(&forged, serde_json::to_string(&bundle).unwrap()).unwrap();

    let out = env
        .cmd("auths")
        .args([
            "verify",
            "HEAD",
            "--identity-bundle",
            forged.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "a bundle with a forged KEL signature must NOT verify (RT-002): {}",
        String::from_utf8_lossy(&out.stdout)
    );
}
