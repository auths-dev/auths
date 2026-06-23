use super::helpers::TestEnv;

/// Extract the `did:keri:` identity DID from `auths whoami --json` output.
fn extract_did(json: &str) -> String {
    let start = json
        .find("did:keri:")
        .expect("a did:keri: identity in whoami json");
    let rest = &json[start..];
    let end = rest
        .find(|c: char| c == '"' || c == ',' || c.is_whitespace())
        .unwrap_or(rest.len());
    rest[..end].to_string()
}

/// `trust pin --did A --key <wrong-hex>` must be refused when A's key history
/// (KEL) is locally resolvable: the supplied key does not control A, so pinning
/// it would let an unrelated key verify as A. A `--key` that disagrees with the
/// KEL-resolved current key is rejected.
#[test]
fn trust_pin_rejects_key_not_in_kel() {
    let env = TestEnv::new();
    env.init_identity();

    let whoami = env
        .cmd("auths")
        .args(["whoami", "--json"])
        .output()
        .unwrap();
    assert!(whoami.status.success());
    let did = extract_did(&String::from_utf8_lossy(&whoami.stdout));

    let wrong_key = "ab".repeat(32);
    let out = env
        .cmd("auths")
        .args(["trust", "pin", "--did", &did, "--key", &wrong_key])
        .output()
        .unwrap();

    assert!(
        !out.status.success(),
        "trust pin accepted a --key that does not match the identity's KEL"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("does not match") && stderr.contains("KEL"),
        "expected a KEL-mismatch rejection, got: {stderr}"
    );

    let default_store = env.auths_home.join("known_identities.json");
    let pinned = default_store.exists()
        && std::fs::read_to_string(&default_store)
            .unwrap()
            .contains(&did);
    assert!(!pinned, "a rejected pin must not be written to the store");
}

/// Pinning A with no `--key` resolves the current key from A's local KEL and
/// succeeds. This is the happy path the cross-check must leave intact.
#[test]
fn trust_pin_without_key_resolves_from_kel() {
    let env = TestEnv::new();
    env.init_identity();

    let whoami = env
        .cmd("auths")
        .args(["whoami", "--json"])
        .output()
        .unwrap();
    assert!(whoami.status.success());
    let did = extract_did(&String::from_utf8_lossy(&whoami.stdout));

    let out = env
        .cmd("auths")
        .args(["trust", "pin", "--did", &did])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "trust pin without --key failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let default_store = env.auths_home.join("known_identities.json");
    assert!(
        default_store.exists()
            && std::fs::read_to_string(&default_store)
                .unwrap()
                .contains(&did),
        "KEL-resolved pin did not land in the store"
    );
}

/// Pinning A with the correct `--key` (the current key already in A's KEL) is
/// allowed: the cross-check finds a match and proceeds.
#[test]
fn trust_pin_accepts_matching_key() {
    let env = TestEnv::new();
    env.init_identity();

    let whoami = env
        .cmd("auths")
        .args(["whoami", "--json"])
        .output()
        .unwrap();
    assert!(whoami.status.success());
    let whoami_json = String::from_utf8_lossy(&whoami.stdout);
    let did = extract_did(&whoami_json);

    let show = env
        .cmd("auths")
        .args(["trust", "pin", "--did", &did, "--json"])
        .output()
        .unwrap();
    assert!(show.status.success());

    let details = env
        .cmd("auths")
        .args(["trust", "show", &did, "--json"])
        .output()
        .unwrap();
    assert!(details.status.success());
    let details_json = String::from_utf8_lossy(&details.stdout);
    let key = extract_public_key_hex(&details_json);

    env.cmd("auths")
        .args(["trust", "remove", &did])
        .output()
        .unwrap();

    let out = env
        .cmd("auths")
        .args(["trust", "pin", "--did", &did, "--key", &key])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "trust pin with the KEL-matching --key was refused: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Pull `public_key_hex` out of `trust show --json` output.
fn extract_public_key_hex(json: &str) -> String {
    let marker = "\"public_key_hex\"";
    let start = json
        .find(marker)
        .map(|i| i + marker.len())
        .expect("public_key_hex in trust show json");
    let rest = &json[start..];
    let first_quote = rest.find('"').expect("opening quote") + 1;
    let after = &rest[first_quote..];
    let end = after.find('"').expect("closing quote");
    after[..end].to_string()
}
