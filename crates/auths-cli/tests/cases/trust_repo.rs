use super::helpers::TestEnv;
use std::fs;

/// Extract the `did:keri:` identity DID from `auths whoami --json` output.
fn extract_did(json: &str) -> String {
    let start = json.find("did:keri:").expect("a did:keri: identity in whoami json");
    let rest = &json[start..];
    let end = rest
        .find(|c: char| c == '"' || c == ',' || c.is_whitespace())
        .unwrap_or(rest.len());
    rest[..end].to_string()
}

/// `trust pin --repo <dir>` must write the pin into that registry, not the
/// default `~/.auths` store. Guards the confused-deputy bug where `--repo` was
/// parsed but silently ignored, so a repo-scoped pin mutated global trust.
#[test]
fn trust_pin_honors_repo_override() {
    let env = TestEnv::new();
    env.init_identity();

    let whoami = env.cmd("auths").args(["whoami", "--json"]).output().unwrap();
    assert!(whoami.status.success());
    let did = extract_did(&String::from_utf8_lossy(&whoami.stdout));

    let alt = env.home.path().join("alt-registry");
    let out = env
        .cmd("auths")
        .args([
            "trust",
            "pin",
            "--did",
            &did,
            "--repo",
            alt.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "trust pin failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let alt_store = alt.join("known_identities.json");
    assert!(
        alt_store.exists(),
        "pin did not land in the --repo store; --repo was ignored"
    );
    assert!(fs::read_to_string(&alt_store).unwrap().contains(&did));

    let default_store = env.auths_home.join("known_identities.json");
    let leaked = default_store.exists()
        && fs::read_to_string(&default_store).unwrap().contains(&did);
    assert!(!leaked, "pin leaked into the default store despite --repo");
}
