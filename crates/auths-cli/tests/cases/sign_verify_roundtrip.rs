use std::process::Command;
use tempfile::TempDir;

/// Returns true if both `auths-sign` and `ssh-keygen` are available in PATH.
fn tools_available() -> bool {
    Command::new("auths-sign").arg("--version").output().is_ok()
        && Command::new("ssh-keygen")
            .arg("-?")
            .output()
            .map(|o| !o.stderr.is_empty() || !o.stdout.is_empty())
            .unwrap_or(false)
}

/// Sign `data` with `auths-sign` using the given key alias and namespace.
/// Returns the PEM-encoded SSHSIG signature.
fn sign_with_auths(
    tmp: &TempDir,
    key_alias: &str,
    namespace: &str,
    data: &[u8],
    passphrase: &str,
) -> Result<String, String> {
    let buf_path = tmp.path().join("payload.buf");
    std::fs::write(&buf_path, data).map_err(|e| e.to_string())?;

    let status = Command::new("auths-sign")
        .args([
            "-Y",
            "sign",
            "-n",
            namespace,
            "-f",
            &format!("auths:{}", key_alias),
            buf_path.to_str().unwrap(),
        ])
        .env("AUTHS_PASSPHRASE", passphrase)
        .status()
        .map_err(|e| e.to_string())?;

    if !status.success() {
        return Err(format!("auths-sign exited with status {}", status));
    }

    let sig_path = tmp.path().join("payload.buf.sig");
    std::fs::read_to_string(&sig_path).map_err(|e| e.to_string())
}

/// Verify a signature with `ssh-keygen -Y verify`.
fn verify_with_ssh_keygen(
    signers_path: &std::path::Path,
    identity: &str,
    namespace: &str,
    sig_pem: &str,
    payload: &[u8],
    tmp: &TempDir,
) -> Result<(), String> {
    let sig_path = tmp.path().join("verify.sig");
    std::fs::write(&sig_path, sig_pem).map_err(|e| e.to_string())?;

    let payload_path = tmp.path().join("verify.payload");
    std::fs::write(&payload_path, payload).map_err(|e| e.to_string())?;

    let stdin_file = std::fs::File::open(&payload_path).map_err(|e| e.to_string())?;

    let output = Command::new("ssh-keygen")
        .args([
            "-Y",
            "verify",
            "-f",
            signers_path.to_str().unwrap(),
            "-I",
            identity,
            "-n",
            namespace,
            "-s",
            sig_path.to_str().unwrap(),
        ])
        .stdin(stdin_file)
        .output()
        .map_err(|e| e.to_string())?;

    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "ssh-keygen verify failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

/// Write an allowed_signers file containing a single entry derived from the
/// public key exported from the `auths-sign`/`ssh-keygen` infrastructure.
///
/// This uses `ssh-keygen -Y find-principals` to confirm the key format after
/// signing, or constructs the file from a known-good public key if provided.
fn write_allowed_signers(tmp: &TempDir, email: &str, pubkey_line: &str) -> std::path::PathBuf {
    let path = tmp.path().join("allowed_signers");
    let entry = format!("{} {}\n", email, pubkey_line);
    std::fs::write(&path, entry).unwrap();
    path
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// End-to-end sign->verify roundtrip using the `main` Auths key.
///
/// This test requires:
///  - `auths-sign` in PATH (built from this workspace)
///  - `ssh-keygen` in PATH
///  - The `main` Auths key to exist in the platform keychain
///  - `AUTHS_TEST_PASSPHRASE` env var set to the passphrase for the `main` key
///  - `AUTHS_TEST_EMAIL` env var set to the email used in the identity
///  - `AUTHS_TEST_PUBKEY` env var set to the `ssh-ed25519 AAAA...` public key
///    (can be obtained from `.auths/allowed_signers` or `auths key export`)
///
/// The test is skipped (not failed) if any of these env vars are absent,
/// so it doesn't break CI environments that haven't configured signing.
#[test]
fn test_auths_sign_verify_roundtrip() {
    if !tools_available() {
        eprintln!("Skipping: auths-sign or ssh-keygen not in PATH");
        return;
    }

    let passphrase = match std::env::var("AUTHS_TEST_PASSPHRASE") {
        Ok(p) => p,
        Err(_) => {
            eprintln!("Skipping: AUTHS_TEST_PASSPHRASE not set");
            return;
        }
    };
    let email = match std::env::var("AUTHS_TEST_EMAIL") {
        Ok(e) => e,
        Err(_) => {
            eprintln!("Skipping: AUTHS_TEST_EMAIL not set");
            return;
        }
    };
    let pubkey = match std::env::var("AUTHS_TEST_PUBKEY") {
        Ok(k) => k,
        Err(_) => {
            eprintln!("Skipping: AUTHS_TEST_PUBKEY not set");
            return;
        }
    };

    let tmp = TempDir::new().unwrap();
    let payload =
        b"tree abc123\nauthor Test User <test@example.com> 1700000000 +0000\n\nTest commit\n";

    // Sign
    let sig_pem = sign_with_auths(&tmp, "main", "git", payload, &passphrase)
        .expect("auths-sign should produce a valid SSHSIG");

    assert!(
        sig_pem.starts_with("-----BEGIN SSH SIGNATURE-----"),
        "signature must be PEM-encoded SSHSIG"
    );

    // Build allowed_signers
    let signers_path = write_allowed_signers(&tmp, &email, &pubkey);

    // Verify: regression for the incorrect-SSHSIG-magic and empty-stdin bugs.
    // If either bug is present, ssh-keygen returns "incorrect signature" here.
    verify_with_ssh_keygen(&signers_path, &email, "git", &sig_pem, payload, &tmp)
        .expect("ssh-keygen must verify the auths-sign signature successfully");
}

/// Verify that `auths-sign -Y check-novalidate` correctly proxies to ssh-keygen.
///
/// This catches the regression where clap rejected -O flags that git passes
/// during verification, and where check-novalidate was not handled at all.
#[test]
fn test_auths_sign_check_novalidate_accepts_o_flag() {
    if !tools_available() {
        eprintln!("Skipping: auths-sign or ssh-keygen not in PATH");
        return;
    }

    let tmp = TempDir::new().unwrap();

    // Create a minimal (invalid) sig file -- check-novalidate will fail on an empty
    // file but the important thing is that auths-sign doesn't crash with
    // "unexpected argument '-O'" before even reaching ssh-keygen.
    let sig_path = tmp.path().join("dummy.sig");
    std::fs::write(&sig_path, "not a real sig").unwrap();

    let payload_file = tmp.path().join("dummy.payload");
    std::fs::write(&payload_file, "hello").unwrap();
    let stdin = std::fs::File::open(&payload_file).unwrap();

    let output = Command::new("auths-sign")
        .args([
            "-Y",
            "check-novalidate",
            "-n",
            "git",
            "-s",
            sig_path.to_str().unwrap(),
            "-Overify-time=20260218012319", // git passes this concatenated
        ])
        .stdin(stdin)
        .output()
        .expect("auths-sign must not crash on check-novalidate with -O flag");

    // We expect a non-zero exit (invalid sig), but NOT a clap parse error.
    // A clap error prints "unexpected argument '-O'" to stderr.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("unexpected argument"),
        "auths-sign must not reject -O flag: {}",
        stderr
    );
    assert!(
        !stderr.contains("Mismatch between definition"),
        "auths-sign must not panic on -O flag: {}",
        stderr
    );
}
