use super::helpers::TestEnv;
use std::fs;

/// `config set --repo <dir>` must write into that registry's `config.toml`, not
/// the default `~/.auths` config. Guards the confused-deputy bug where `--repo`
/// was parsed but silently ignored, so a repo-scoped change mutated the global
/// config.
#[test]
fn config_set_honors_repo_override() {
    let env = TestEnv::new();
    env.init_identity();

    let default_config = env.auths_home.join("config.toml");
    let default_before = fs::read_to_string(&default_config).ok();

    let alt = env.home.path().join("alt-registry");
    let out = env
        .cmd("auths")
        .args([
            "config",
            "set",
            "passphrase.cache",
            "always",
            "--repo",
            alt.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "config set failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let alt_config = alt.join("config.toml");
    assert!(
        alt_config.exists(),
        "config did not land in the --repo store; --repo was ignored"
    );
    assert!(
        fs::read_to_string(&alt_config)
            .unwrap()
            .contains("always"),
        "the --repo config.toml does not reflect the new value"
    );

    let default_after = fs::read_to_string(&default_config).ok();
    assert_eq!(
        default_before, default_after,
        "config set --repo mutated the default ~/.auths config"
    );
}
