use super::helpers::TestEnv;

/// `auths id expand` has been removed. It ran a shared-`k` rotation to turn a single-key identity
/// into a multi-slot key set — a path superseded by delegation-based device pairing
/// (`auths device pair`), where each device is its own delegated identity under the root. The
/// command was also brick-prone: on a freshly-migrated single key it read a next-key alias the
/// migration never produced, failing mid-rotation. Multi-device membership is now pairing only.
#[test]
fn id_expand_is_removed() {
    let env = TestEnv::new();

    let output = env
        .cmd("auths")
        .args(["id", "expand", "--add-device", "ed25519"])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "`auths id expand` should no longer exist"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unrecognized subcommand") || stderr.contains("unexpected argument"),
        "expected a clap unrecognized-subcommand error, got: {stderr}"
    );
}
