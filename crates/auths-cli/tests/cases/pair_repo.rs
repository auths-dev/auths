use super::helpers::TestEnv;

/// `pair --repo <dir>` must resolve the pairing store from that registry, not
/// the default `~/.auths`. Guards the confused-deputy bug where `PairCommand`
/// dropped `repo_path` and pairing silently operated on the global store.
///
/// The default registry holds an identity (via `init_identity`); the `--repo`
/// override points at an empty registry. Online-initiate pairing loads the
/// controller identity before any network call, so:
///   * with `--repo <ALT>` it reads the empty store and fails "identity not
///     found" — proving it READ the alt registry, not the populated default;
///   * without `--repo` it reads the populated default, gets past identity
///     loading, and fails later (network), never with "identity not found".
#[test]
fn pair_honors_repo_override() {
    let env = TestEnv::new();
    env.init_identity();

    let alt = env.home.path().join("alt-registry");
    std::fs::create_dir_all(&alt).unwrap();

    let scoped = env
        .cmd("auths")
        .args([
            "pair",
            "--registry",
            "http://127.0.0.1:0",
            "--no-qr",
            "--repo",
            alt.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        !scoped.status.success(),
        "pair against an empty --repo store should fail"
    );
    let scoped_err = String::from_utf8_lossy(&scoped.stderr);
    assert!(
        scoped_err.contains("identity not found"),
        "pair --repo did not read the alt store (expected 'identity not found'), got: {scoped_err}"
    );

    let default = env
        .cmd("auths")
        .args(["pair", "--registry", "http://127.0.0.1:0", "--no-qr"])
        .output()
        .unwrap();

    let default_err = String::from_utf8_lossy(&default.stderr);
    assert!(
        !default_err.contains("identity not found"),
        "without --repo, pairing must read the populated default store, got: {default_err}"
    );
}
