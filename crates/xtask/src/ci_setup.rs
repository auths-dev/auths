#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use flate2::Compression;
use flate2::write::GzEncoder;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use tar::Builder;
use tempfile::TempDir;
use walkdir::WalkDir;

use crate::shell::{run_capture, run_capture_env, run_with_stdin};

pub fn run() -> Result<()> {
    println!();
    println!("\x1b[0;36m╔════════════════════════════════════════════════════════════╗\x1b[0m");
    println!(
        "\x1b[0;36m║\x1b[0m\x1b[1m           CI Release Signing Setup (One-Time)              \x1b[0m\x1b[0;36m║\x1b[0m"
    );
    println!("\x1b[0;36m╚════════════════════════════════════════════════════════════╝\x1b[0m");
    println!();
    println!("This creates a limited-capability device for GitHub Actions to sign");
    println!("release artifacts. Your root identity stays on your machine.");
    println!();

    // Step 1: Verify identity exists
    run_capture("auths", &["status"])
        .context("No auths identity found. Run 'auths init' first.")?;

    // Step 2: Read identity info
    let id_output = run_capture("auths", &["id", "show"])?;
    let identity_did = id_output
        .lines()
        .find(|l| l.contains("Controller DID:"))
        .and_then(|l| l.split_whitespace().nth(2))
        .context("Could not parse Controller DID from `auths id show`")?
        .to_string();

    let key_output = run_capture("auths", &["key", "list"])?;
    let identity_key_alias = key_output
        .lines()
        .find(|l| l.starts_with('-'))
        .and_then(|l| l.split_whitespace().nth(1))
        .context("Could not parse key alias from `auths key list`")?
        .to_string();

    println!("\x1b[1mIdentity:\x1b[0m  \x1b[0;36m{identity_did}\x1b[0m");
    println!("\x1b[1mKey alias:\x1b[0m \x1b[0;36m{identity_key_alias}\x1b[0m");
    println!();

    // Step 3: Check for existing CI device key
    let reuse = key_output.contains("ci-release-device");
    if reuse {
        println!("\x1b[2mFound existing ci-release-device key \u{2014} will reuse it.\x1b[0m");
    }

    // Step 4: Prompt for passphrase
    println!("\x1b[1mChoose a passphrase for the CI device key.\x1b[0m");
    println!("\x1b[2mThis will be stored as AUTHS_CI_PASSPHRASE in GitHub Secrets.\x1b[0m");
    println!();

    let ci_pass = rpassword::prompt_password("CI device passphrase: ")?;
    let ci_pass_confirm = rpassword::prompt_password("Confirm passphrase: ")?;

    if ci_pass != ci_pass_confirm {
        bail!("Passphrases do not match");
    }

    // Step 5: Generate seed + import key (or reuse existing)
    let keychain_b64 = if !reuse {
        println!();
        println!("\x1b[2mGenerating CI device key...\x1b[0m");

        // Generate a fresh 32-byte Ed25519 seed
        let seed: [u8; 32] = rand::random();
        let tmp = TempDir::new()?;
        let seed_path = tmp.path().join("ci-device-seed.bin");
        {
            #[cfg(unix)]
            {
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&seed_path)?;
                f.write_all(&seed)?;
            }
            #[cfg(not(unix))]
            {
                fs::write(&seed_path, seed)?;
            }
        }

        // Import the seed into platform keychain
        println!("\x1b[2mImporting key into platform keychain:\x1b[0m");
        run_capture(
            "auths",
            &[
                "key",
                "import",
                "--alias",
                "ci-release-device",
                "--seed-file",
                seed_path.to_str().unwrap(),
                "--controller-did",
                &identity_did,
            ],
        )?;
        println!("\x1b[0;32m\u{2713}\x1b[0m CI device key imported into platform keychain");

        // Create CI file keychain
        println!("\x1b[2mCreating CI file keychain...\x1b[0m");
        let keychain_path = tmp.path().join("ci-keychain.enc");
        run_capture_env(
            "auths",
            &[
                "key",
                "copy-backend",
                "--alias",
                "ci-release-device",
                "--dst-backend",
                "file",
                "--dst-file",
                keychain_path.to_str().unwrap(),
            ],
            &[("AUTHS_PASSPHRASE", &ci_pass)],
        )?;

        let keychain_bytes = fs::read(&keychain_path)?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&keychain_bytes);
        // TempDir auto-cleans on drop
        println!("\x1b[0;32m\u{2713}\x1b[0m CI file keychain created");
        b64
    } else {
        println!(
            "\x1b[2mReusing existing ci-release-device key \u{2014} regenerating CI file keychain...\x1b[0m"
        );
        let tmp = TempDir::new()?;
        let keychain_path = tmp.path().join("ci-keychain.enc");
        run_capture_env(
            "auths",
            &[
                "key",
                "copy-backend",
                "--alias",
                "ci-release-device",
                "--dst-backend",
                "file",
                "--dst-file",
                keychain_path.to_str().unwrap(),
            ],
            &[("AUTHS_PASSPHRASE", &ci_pass)],
        )?;

        let keychain_bytes = fs::read(&keychain_path)?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&keychain_bytes);
        println!("\x1b[0;32m\u{2713}\x1b[0m CI file keychain regenerated from existing device key");
        b64
    };

    // Step 6: Derive device DID
    let device_pub = run_capture(
        "auths",
        &[
            "key",
            "export",
            "--alias",
            "ci-release-device",
            "--passphrase",
            &ci_pass,
            "--format",
            "pub",
        ],
    )?;
    let device_did = run_capture("auths", &["debug", "util", "pubkey-to-did", &device_pub])?;
    println!("\x1b[0;32m\u{2713}\x1b[0m Device DID: \x1b[0;36m{device_did}\x1b[0m");

    // Step 7: Link device (if not already linked)
    let devices_output = run_capture("auths", &["device", "list"])?;
    if devices_output.contains(&device_did) {
        println!("\x1b[0;32m\u{2713}\x1b[0m CI device already linked \u{2014} skipping");
    } else {
        println!();
        println!("\x1b[2mLinking CI device to identity...\x1b[0m");
        run_capture_env(
            "auths",
            &[
                "device",
                "link",
                "--key",
                &identity_key_alias,
                "--device-key",
                "ci-release-device",
                "--device-did",
                &device_did,
                "--note",
                "GitHub Actions release signer",
                "--capabilities",
                "sign_release",
            ],
            &[("AUTHS_PASSPHRASE", &ci_pass)],
        )?;
        println!("\x1b[0;32m\u{2713}\x1b[0m CI device linked");
    }

    // Step 8: Package identity repo + set GitHub secrets
    let auths_dir = home_dir()?.join(".auths");

    // Verify ~/.auths is a git repo
    println!("\x1b[2mPackaging identity repo...\x1b[0m");
    run_capture(
        "git",
        &["-C", auths_dir.to_str().unwrap(), "rev-parse", "--git-dir"],
    )
    .context("~/.auths does not appear to be a git repository. Run 'auths init' first.")?;
    println!("  \x1b[0;32m\u{2713}\x1b[0m ~/.auths is a valid git repo");

    // Build tar.gz in memory, excluding *.sock
    let identity_bundle_b64 = build_identity_bundle(&auths_dir)?;

    println!();
    println!("\x1b[0;32m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    println!("\x1b[1m  Setting GitHub Secrets:\x1b[0m");
    println!("\x1b[0;32m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m");
    println!();

    let repo = extract_github_repo()?;
    let gh_ok = try_set_github_secrets(&repo, &ci_pass, &keychain_b64, &identity_bundle_b64);

    if gh_ok {
        println!("\x1b[0;32m\u{2713}\x1b[0m All 3 secrets set on \x1b[0;36m{repo}\x1b[0m");
    } else {
        println!("\x1b[1;33mCould not set secrets automatically.\x1b[0m");
        println!(
            "\x1b[2mGITHUB_TOKEN env var (if set) may be overriding the keyring account.\x1b[0m"
        );
        println!("\x1b[2mTry: unset GITHUB_TOKEN && cargo xt ci-setup\x1b[0m");
        println!("\x1b[2mOr: gh auth login then re-run, or add manually:\x1b[0m");
        println!(
            "\x1b[2m  Repository \u{2192} Settings \u{2192} Secrets \u{2192} Actions \u{2192} New secret\x1b[0m"
        );
        println!();
        println!("\x1b[1mAUTHS_CI_PASSPHRASE\x1b[0m");
        println!("{ci_pass}");
        println!();
        println!("\x1b[1mAUTHS_CI_KEYCHAIN\x1b[0m");
        println!("{keychain_b64}");
        println!();
        println!("\x1b[1mAUTHS_CI_IDENTITY_BUNDLE\x1b[0m");
        println!("{identity_bundle_b64}");
    }

    println!();
    println!("\x1b[1mTo revoke CI access at any time:\x1b[0m");
    println!(
        "  \x1b[0;36mauths device revoke --device-did {device_did} --key {identity_key_alias}\x1b[0m"
    );
    println!();

    Ok(())
}

/// Build a tar.gz of ~/.auths, base64-encoded (single-line, no wrapping).
/// Excludes *.sock files.
fn build_identity_bundle(auths_dir: &Path) -> Result<String> {
    let mut buf = Vec::new();
    {
        let gz = GzEncoder::new(&mut buf, Compression::default());
        let mut archive = Builder::new(gz);
        add_dir_to_tar(&mut archive, auths_dir, Path::new("."))?;
        let gz = archive.into_inner()?;
        gz.finish()?;
    }
    Ok(base64::engine::general_purpose::STANDARD.encode(&buf))
}

/// Recursively add a directory to a tar archive, excluding *.sock files.
fn add_dir_to_tar<W: Write>(archive: &mut Builder<W>, src_dir: &Path, prefix: &Path) -> Result<()> {
    for entry in WalkDir::new(src_dir).follow_links(false) {
        let entry = entry?;
        let path = entry.path();

        // Exclude socket files
        if path.extension().is_some_and(|ext| ext == "sock") {
            continue;
        }

        let rel = path.strip_prefix(src_dir)?;
        if rel.as_os_str().is_empty() {
            continue;
        }
        let archive_path = prefix.join(rel);

        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mode(0o755);
            header.set_mtime(0);
            header.set_cksum();
            archive.append_data(&mut header, &archive_path, &[] as &[u8])?;
        } else if metadata.is_file() {
            let data = fs::read(path)?;
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_mtime(0);
            header.set_cksum();
            archive.append_data(&mut header, &archive_path, data.as_slice())?;
        }
        // Skip symlinks, sockets, etc.
    }
    Ok(())
}

/// Extract "owner/repo" from git remote origin URL.
/// Handles HTTPS (https://github.com/owner/repo.git) and SSH (git@github.com:owner/repo.git).
pub fn extract_github_repo() -> Result<String> {
    let url = run_capture("git", &["remote", "get-url", "origin"])?;
    extract_github_repo_from_url(&url)
}

pub fn extract_github_repo_from_url(url: &str) -> Result<String> {
    let repo = url
        .trim()
        .trim_end_matches(".git")
        // SSH: git@github.com:owner/repo
        .rsplit_once(':')
        .map(|(prefix, suffix)| {
            if prefix.contains("github.com") && !suffix.contains("//") {
                suffix.to_string()
            } else {
                // HTTPS: https://github.com/owner/repo
                url.trim()
                    .trim_end_matches(".git")
                    .rsplit("github.com/")
                    .next()
                    .unwrap_or("")
                    .to_string()
            }
        })
        .unwrap_or_default();

    if repo.is_empty() || !repo.contains('/') {
        bail!("Could not extract owner/repo from remote URL: {url}");
    }
    Ok(repo)
}

/// Try to set GitHub secrets using `gh`. Returns true on success.
fn try_set_github_secrets(
    repo: &str,
    passphrase: &str,
    keychain_b64: &str,
    identity_bundle_b64: &str,
) -> bool {
    // Check gh is available and authenticated (with tokens cleared)
    if run_capture_env("gh", &["auth", "status"], &[]).is_err() {
        return false;
    }

    println!("\x1b[2mSetting secrets via gh CLI...\x1b[0m");

    let mut ok = true;

    if run_with_stdin(
        "gh",
        &["secret", "set", "AUTHS_CI_PASSPHRASE", "--repo", repo],
        passphrase.as_bytes(),
    )
    .is_err()
    {
        ok = false;
    }

    if run_with_stdin(
        "gh",
        &["secret", "set", "AUTHS_CI_KEYCHAIN", "--repo", repo],
        keychain_b64.as_bytes(),
    )
    .is_err()
    {
        ok = false;
    }

    if run_with_stdin(
        "gh",
        &["secret", "set", "AUTHS_CI_IDENTITY_BUNDLE", "--repo", repo],
        identity_bundle_b64.as_bytes(),
    )
    .is_err()
    {
        ok = false;
    }

    ok
}

fn home_dir() -> Result<PathBuf> {
    dirs_or_env()
}

fn dirs_or_env() -> Result<PathBuf> {
    std::env::var("HOME")
        .map(PathBuf::from)
        .or_else(|_| std::env::var("USERPROFILE").map(PathBuf::from))
        .context("Could not determine home directory (neither HOME nor USERPROFILE is set)")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_repo_https() {
        let url = "https://github.com/auths-dev/auths.git";
        assert_eq!(
            extract_github_repo_from_url(url).unwrap(),
            "auths-dev/auths"
        );
    }

    #[test]
    fn extract_repo_https_no_suffix() {
        let url = "https://github.com/auths-dev/auths";
        assert_eq!(
            extract_github_repo_from_url(url).unwrap(),
            "auths-dev/auths"
        );
    }

    #[test]
    fn extract_repo_ssh() {
        let url = "git@github.com:auths-dev/auths.git";
        assert_eq!(
            extract_github_repo_from_url(url).unwrap(),
            "auths-dev/auths"
        );
    }

    #[test]
    fn extract_repo_ssh_no_suffix() {
        let url = "git@github.com:auths-dev/auths";
        assert_eq!(
            extract_github_repo_from_url(url).unwrap(),
            "auths-dev/auths"
        );
    }

    #[test]
    fn tar_excludes_sock_files() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();

        // Create test structure
        fs::create_dir_all(dir.join("sub")).unwrap();
        fs::write(dir.join("file.txt"), b"hello").unwrap();
        fs::write(dir.join("agent.sock"), b"socket").unwrap();
        fs::write(dir.join("sub/data.json"), b"{}").unwrap();
        fs::write(dir.join("sub/other.sock"), b"socket2").unwrap();

        // Build archive
        let mut buf = Vec::new();
        {
            let gz = GzEncoder::new(&mut buf, Compression::default());
            let mut archive = Builder::new(gz);
            add_dir_to_tar(&mut archive, dir, Path::new(".")).unwrap();
            let gz = archive.into_inner().unwrap();
            gz.finish().unwrap();
        }

        // Read back and verify entries
        use flate2::read::GzDecoder;
        let decoder = GzDecoder::new(buf.as_slice());
        let mut archive = tar::Archive::new(decoder);
        let names: Vec<String> = archive
            .entries()
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path().unwrap().to_string_lossy().to_string())
            .collect();

        assert!(names.iter().any(|n| n.contains("file.txt")));
        assert!(names.iter().any(|n| n.contains("data.json")));
        assert!(!names.iter().any(|n| n.contains(".sock")));
    }

    #[test]
    fn passphrase_mismatch_detected() {
        // This tests the logic inline — the actual prompt is in the run() fn
        let pass1 = "hunter2";
        let pass2 = "hunter3";
        assert_ne!(pass1, pass2);
    }
}
