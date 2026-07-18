use super::helpers::TestEnv;

/// `auths key` operates only on the per-machine keychain selected by
/// `AUTHS_KEYCHAIN_*`; there is no repo-scoped store for it to act on. `--repo`
/// must therefore be rejected with a clear error rather than silently acting on
/// the global keychain. Guards the confused-deputy bug where `--repo` was parsed
/// but ignored.
#[test]
fn key_repo_is_honored_or_rejected() {
    let env = TestEnv::new();

    let alt = env.home.path().join("alt-registry");
    let out = env
        .cmd("auths")
        .args(["key", "list", "--repo", alt.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(
        !out.status.success(),
        "key list --repo should be rejected, not silently run on the global keychain"
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--repo") && stderr.contains("keychain"),
        "expected a clear `--repo` rejection mentioning the keychain, got: {stderr}"
    );
}
