use super::helpers::TestEnv;

/// A file attestation must not bind the ambient git HEAD. Before the fix, `auths sign <file>`
/// resolved the current repo's HEAD and recorded it as the attestation's `commit_sha`, falsely
/// associating an unrelated commit with the signed file. The commit a file is bound to must be
/// explicit (`auths artifact sign --commit <sha>`), never inferred from ambient git state.
#[test]
fn auths_sign_file_does_not_bind_ambient_git_head() {
    let env = TestEnv::new();
    env.init_identity();

    // Give the working repo a HEAD commit — the value the pre-fix code would have bound.
    std::fs::write(env.repo_path.join("seed.txt"), b"seed").unwrap();
    env.git_cmd().args(["add", "."]).output().unwrap();
    env.git_cmd()
        .args(["commit", "-m", "seed"])
        .output()
        .unwrap();

    std::fs::write(env.repo_path.join("artifact.txt"), b"payload").unwrap();

    let output = env
        .cmd("auths")
        .args(["sign", "artifact.txt"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "auths sign failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let att_path = env.repo_path.join("artifact.txt.auths.json");
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&att_path).unwrap()).unwrap();
    let commit_sha = json.get("commit_sha");
    assert!(
        commit_sha.is_none_or(|v| v.is_null()),
        "a file attestation must not bind the ambient git HEAD, got commit_sha = {commit_sha:?}"
    );
}
