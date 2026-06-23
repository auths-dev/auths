// Integration coverage for the central guarantee of `auths verify`: a clean
// signature verifies true, and any tampering with either the signature or the
// signed artifact flips the verdict to false. Verification must fail closed on
// broken input rather than crash or report a positive result.
//
// Each test owns its own sandboxed `TestEnv` (temp HOME, temp keychain, temp
// git repo), so nothing here touches the real `~/.auths`.

use super::helpers::TestEnv;

/// Read the top-level `valid` flag out of a `--json` verify response.
///
/// The verdict JSON carries a top-level `"valid"` boolean alongside a sibling
/// `"chain_valid"`, so we anchor on the exact `"valid"` key and read the literal
/// that follows it. Returns `Some(true)`/`Some(false)` when the flag is present,
/// or `None` when the output carries no parseable top-level verdict.
fn top_level_valid(json: &str) -> Option<bool> {
    let mut search_from = 0;
    while let Some(rel) = json[search_from..].find("\"valid\"") {
        let key_start = search_from + rel;
        let after_key = key_start + "\"valid\"".len();
        let rest = json[after_key..].trim_start();
        let rest = rest.strip_prefix(':').map(str::trim_start);
        if let Some(rest) = rest {
            if rest.starts_with("true") {
                return Some(true);
            }
            if rest.starts_with("false") {
                return Some(false);
            }
        }
        // A `"valid"` substring that was not a JSON key/value pair (for example a
        // word inside an error message); keep scanning for the real field.
        search_from = after_key;
    }
    None
}

/// Sign a binary artifact and return the path to its `<file>.auths.json` sidecar.
///
/// Uses a non-JSON extension so `auths verify <file>` routes through the artifact
/// path (sidecar lookup) rather than being read as an attestation document.
fn sign_artifact(env: &TestEnv) -> (std::path::PathBuf, std::path::PathBuf) {
    let artifact = env.repo_path.join("release.bin");
    std::fs::write(&artifact, b"artifact payload bytes\n").unwrap();

    // `--key` attaches the issuer (identity) signature; without it the artifact carries only the
    // device signature and verification fails closed on the missing issuer signature. A clean,
    // fully dual-signed attestation is the positive control the tamper tests build on.
    let output = env
        .cmd("auths")
        .args([
            "sign",
            artifact.to_str().unwrap(),
            "--key",
            "main",
            "--device-key",
            "main",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "auths sign <file> failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let sidecar = env.repo_path.join("release.bin.auths.json");
    assert!(
        sidecar.exists(),
        "expected attestation sidecar at {sidecar:?}"
    );
    (artifact, sidecar)
}

/// Run `auths verify <artifact> --json` and return stdout.
fn verify_artifact(env: &TestEnv, artifact: &std::path::Path) -> String {
    let output = env
        .cmd("auths")
        .args(["verify", artifact.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    String::from_utf8_lossy(&output.stdout).to_string()
}

/// Positive control: a clean, untampered signature must verify true.
///
/// Without this anchor the tamper-rejection tests below could pass trivially by
/// always returning false, so we prove a genuine signature is accepted first.
#[test]
fn verify_accepts_clean_signature() {
    let env = TestEnv::new();
    env.init_identity();

    let (artifact, _sidecar) = sign_artifact(&env);
    let stdout = verify_artifact(&env, &artifact);

    assert_eq!(
        top_level_valid(&stdout),
        Some(true),
        "a clean signature must verify as valid; got: {stdout}"
    );
}

/// A signature whose bytes were altered must be rejected.
///
/// We corrupt the signed `identity_signature` field in the attestation sidecar.
/// The signature no longer matches the canonical attestation data, so the verdict
/// must be `valid:false` — never a crash, never a positive result.
#[test]
fn verify_rejects_tampered_signature() {
    let env = TestEnv::new();
    env.init_identity();

    let (artifact, sidecar) = sign_artifact(&env);

    let original = std::fs::read_to_string(&sidecar).unwrap();
    // Prefer the issuer signature; fall back to the device signature, which is
    // always serialized. Both cover the canonical attestation data.
    let mut tampered = corrupt_first_hex_run(&original, "\"identity_signature\"");
    if tampered == original {
        tampered = corrupt_first_hex_run(&original, "\"device_signature\"");
    }
    assert_ne!(
        tampered, original,
        "test setup: failed to alter a signature field in {sidecar:?}"
    );
    std::fs::write(&sidecar, &tampered).unwrap();

    let stdout = verify_artifact(&env, &artifact);
    assert_eq!(
        top_level_valid(&stdout),
        Some(false),
        "a tampered signature must fail verification; got: {stdout}"
    );
}

/// Modifying the artifact body after signing must be rejected.
///
/// The attestation binds the artifact's digest. Changing the file's bytes makes
/// the recomputed digest disagree with the signed digest, so the verdict must be
/// `valid:false`.
#[test]
fn verify_rejects_tampered_artifact_body() {
    let env = TestEnv::new();
    env.init_identity();

    let (artifact, _sidecar) = sign_artifact(&env);

    // Sanity: the signature is good before we touch the body.
    let clean = verify_artifact(&env, &artifact);
    assert_eq!(
        top_level_valid(&clean),
        Some(true),
        "precondition: the signature must verify before tampering; got: {clean}"
    );

    std::fs::write(&artifact, b"artifact payload bytes -- altered\n").unwrap();

    let stdout = verify_artifact(&env, &artifact);
    assert_eq!(
        top_level_valid(&stdout),
        Some(false),
        "a modified artifact body must fail verification; got: {stdout}"
    );
}

/// Verification must fail closed on malformed or missing input.
///
/// Empty files, binary garbage, truncated JSON, and a non-existent path must all
/// resolve to `valid:false` (or a clean error verdict) and must never report
/// `valid:true` or crash the process.
#[test]
fn verify_fails_closed_on_malformed_input() {
    let env = TestEnv::new();
    env.init_identity();

    // `.json` inputs route through attestation parsing, exercising the malformed
    // attestation path directly.
    let empty = env.repo_path.join("empty.json");
    std::fs::write(&empty, b"").unwrap();

    let garbage = env.repo_path.join("garbage.json");
    std::fs::write(&garbage, [0x00u8, 0xff, 0x01, 0xfe, 0x7f, 0x80]).unwrap();

    let truncated = env.repo_path.join("truncated.json");
    std::fs::write(&truncated, b"{\"version\":\"1\",\"issuer\":\"did:keri:E").unwrap();

    let broken_inputs = [&empty, &garbage, &truncated];
    for input in broken_inputs {
        let output = env
            .cmd("auths")
            .args(["verify", input.to_str().unwrap(), "--json"])
            .output()
            .unwrap();
        // The process must exit cleanly (no panic / signal kill), regardless of
        // the non-zero verification exit code.
        assert!(
            output.status.code().is_some(),
            "verify must not crash on malformed input {input:?}"
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_ne!(
            top_level_valid(&stdout),
            Some(true),
            "malformed input must never verify as valid: {input:?} -> {stdout}"
        );
    }

    // A path that does not exist must also fail closed without crashing.
    let missing = env.repo_path.join("does-not-exist.json");
    let output = env
        .cmd("auths")
        .args(["verify", missing.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.code().is_some(),
        "verify must not crash on a non-existent path"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_ne!(
        top_level_valid(&stdout),
        Some(true),
        "a non-existent path must never verify as valid; got: {stdout}"
    );
}

/// Replace the first run of hex characters that follows `field_marker` with a
/// different hex value, leaving the JSON structurally intact but the signed
/// material altered. Returns the input unchanged when no such run is found.
fn corrupt_first_hex_run(json: &str, field_marker: &str) -> String {
    let Some(marker_at) = json.find(field_marker) else {
        return json.to_string();
    };
    let tail = &json[marker_at..];
    // Find the opening quote of the field's value, then the hex run inside it.
    let Some(value_quote_rel) = tail[field_marker.len()..].find('"') else {
        return json.to_string();
    };
    let value_start = marker_at + field_marker.len() + value_quote_rel + 1;
    let bytes = json.as_bytes();
    let mut i = value_start;
    while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
        i += 1;
    }
    if i == value_start {
        return json.to_string();
    }
    let mut out = String::with_capacity(json.len());
    out.push_str(&json[..value_start]);
    for &b in &bytes[value_start..i] {
        // Map each hex digit to a different one so the value stays valid hex of
        // the same length but no longer matches the original signature bytes.
        let c = b as char;
        let flipped = match c {
            '0'..='9' => {
                if c == '9' {
                    '0'
                } else {
                    (b + 1) as char
                }
            }
            'a' | 'A' => 'b',
            'b' | 'B' => 'a',
            'c'..='f' => 'a',
            'C'..='F' => 'a',
            _ => '0',
        };
        out.push(flipped);
    }
    out.push_str(&json[i..]);
    out
}
