use super::helpers::TestEnv;
use std::fs;

/// `reset --repo <dir> --force` must remove only that registry's directory, not
/// the default `~/.auths`. Guards the destructive confused-deputy bug where
/// `--repo` was parsed but ignored, so a repo-scoped reset wiped the global
/// `~/.auths` store.
#[test]
fn reset_honors_repo_override() {
    let env = TestEnv::new();
    env.init_identity();

    let default_marker = env.auths_home.join("reset-sentinel");
    fs::write(&default_marker, b"keep").unwrap();

    let alt = env.home.path().join("alt-registry");
    let out = env
        .cmd("auths")
        .args([
            "init",
            "--non-interactive",
            "--profile",
            "developer",
            "--repo",
            alt.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "init --repo failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(alt.exists(), "init --repo did not create the alt store");

    let reset = env
        .cmd("auths")
        .args(["reset", "--force", "--repo", alt.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        reset.status.success(),
        "reset --repo failed: {}",
        String::from_utf8_lossy(&reset.stderr)
    );

    assert!(
        !alt.exists(),
        "reset --repo did not remove the alt store; --repo was ignored"
    );
    assert!(
        env.auths_home.exists() && default_marker.exists(),
        "reset --repo wiped the default ~/.auths store"
    );
}
