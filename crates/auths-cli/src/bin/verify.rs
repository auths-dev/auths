#![allow(clippy::print_stdout, clippy::print_stderr, clippy::exit)]
//! auths-verify: SSH signature verification for Auths identities
//!
//! Supports two modes:
//! 1. ssh-keygen compatible: auths-verify -Y verify -f <allowed_signers> -I <id> -n <ns> -s <sig>
//! 2. Simplified mode: auths-verify --file <file> --signature <sig_file> --allowed-signers <file>

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use tempfile::NamedTempFile;

/// Auths SSH signature verification tool.
///
/// Supports ssh-keygen compatible interface for integration with Git
/// and a simplified interface for general file verification.
#[derive(Parser, Debug)]
#[command(name = "auths-verify")]
#[command(version)]
struct Args {
    #[command(subcommand)]
    command: Option<VerifySubcommand>,

    /// ssh-keygen compatibility: operation type (must be "verify")
    #[arg(short = 'Y', global = true)]
    operation: Option<String>,

    /// ssh-keygen compatibility: namespace (e.g., "git")
    #[arg(short = 'n', global = true)]
    namespace: Option<String>,

    /// ssh-keygen compatibility: allowed signers file
    #[arg(short = 'f', global = true)]
    allowed_signers: Option<PathBuf>,

    /// ssh-keygen compatibility: identity/principal to verify
    #[arg(short = 'I', global = true)]
    identity: Option<String>,

    /// ssh-keygen compatibility: signature file
    #[arg(short = 's', global = true)]
    signature_file: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum VerifySubcommand {
    /// Verify a file signature
    File {
        /// File to verify (or - for stdin)
        #[arg(long)]
        file: PathBuf,

        /// Signature file (.sig)
        #[arg(long)]
        signature: PathBuf,

        /// Allowed signers file
        #[arg(long, default_value = ".auths/allowed_signers")]
        allowed_signers: PathBuf,

        /// Namespace for verification (default: file)
        #[arg(long, default_value = "file")]
        namespace: String,
    },
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {:#}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = Args::parse();

    // Check if we're in ssh-keygen compatibility mode
    if args.operation.is_some() {
        return run_ssh_keygen_compat(args);
    }

    // Check for subcommand
    match args.command {
        Some(VerifySubcommand::File {
            file,
            signature,
            allowed_signers,
            namespace,
        }) => verify_file(&file, &signature, &allowed_signers, &namespace),
        None => {
            bail!(
                "No operation specified.\n\n\
                Usage:\n\
                  auths-verify -Y verify -f <allowed_signers> -I <identity> -n <namespace> -s <sig_file>\n\
                  auths-verify file --file <path> --signature <sig_file> --allowed-signers <file>"
            );
        }
    }
}

/// ssh-keygen compatibility mode
fn run_ssh_keygen_compat(args: Args) -> Result<()> {
    let operation = args.operation.as_deref().unwrap_or("");
    if operation != "verify" {
        bail!(
            "Unsupported operation: '{}'. Only 'verify' is supported.",
            operation
        );
    }

    let allowed_signers = args
        .allowed_signers
        .ok_or_else(|| anyhow!("Missing required argument: -f <allowed_signers>"))?;

    let signature_file = args
        .signature_file
        .ok_or_else(|| anyhow!("Missing required argument: -s <signature_file>"))?;

    let namespace = args.namespace.unwrap_or_else(|| "file".to_string());
    let identity = args.identity.unwrap_or_else(|| "*".to_string());

    // Read data from stdin
    let mut data = Vec::new();
    io::stdin()
        .read_to_end(&mut data)
        .context("Failed to read data from stdin")?;

    verify_with_ssh_keygen(
        &data,
        &signature_file,
        &allowed_signers,
        &namespace,
        &identity,
    )
}

/// Verify a file signature
fn verify_file(
    file: &std::path::Path,
    signature: &std::path::Path,
    allowed_signers: &std::path::Path,
    namespace: &str,
) -> Result<()> {
    // Check if allowed_signers exists
    if !allowed_signers.exists() {
        bail!(
            "Allowed signers file not found: {:?}\n\n\
            Create it with:\n  \
            auths signers sync --output {:?}",
            allowed_signers,
            allowed_signers
        );
    }

    // Read file contents
    let data =
        fs::read(file).with_context(|| format!("Failed to read file: {}", file.display()))?;

    verify_with_ssh_keygen(&data, signature, allowed_signers, namespace, "*")
}

/// Core verification using ssh-keygen
fn verify_with_ssh_keygen(
    data: &[u8],
    signature_file: &std::path::Path,
    allowed_signers: &std::path::Path,
    namespace: &str,
    identity: &str,
) -> Result<()> {
    // Check if ssh-keygen is available
    check_ssh_keygen()?;

    // Write data to temp file for verification
    let mut data_file = NamedTempFile::new().context("Failed to create temp file for data")?;
    data_file
        .write_all(data)
        .context("Failed to write data to temp file")?;
    data_file.flush()?;

    // Run ssh-keygen -Y verify
    let output = Command::new("ssh-keygen")
        .args(["-Y", "verify", "-f"])
        .arg(allowed_signers)
        .args(["-I", identity, "-n", namespace, "-s"])
        .arg(signature_file)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to run ssh-keygen")?;

    // Pipe data to stdin
    let mut child = output;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(data)?;
    }

    let output = child
        .wait_with_output()
        .context("Failed to wait for ssh-keygen")?;

    if output.status.success() {
        // Try to find who signed it
        let signer = find_signer(signature_file, allowed_signers)?;
        println!(
            "Good signature from: {}",
            signer.unwrap_or_else(|| "allowed signer".to_string())
        );
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("no principal matched") || stderr.contains("NONE_ACCEPTED") {
            bail!("Signature from non-allowed signer");
        }
        bail!("Signature verification failed: {}", stderr.trim());
    }
}

/// Find who signed the file using ssh-keygen find-principals
fn find_signer(
    signature_file: &std::path::Path,
    allowed_signers: &std::path::Path,
) -> Result<Option<String>> {
    let output = Command::new("ssh-keygen")
        .args(["-Y", "find-principals", "-f"])
        .arg(allowed_signers)
        .arg("-s")
        .arg(signature_file)
        .output();

    if let Ok(out) = output
        && out.status.success()
    {
        let signer = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !signer.is_empty() {
            return Ok(Some(signer));
        }
    }
    Ok(None)
}

/// Check if ssh-keygen is available
fn check_ssh_keygen() -> Result<()> {
    let output = Command::new("ssh-keygen")
        .arg("-?")
        .stderr(Stdio::piped())
        .output()
        .context("ssh-keygen not found in PATH. Install OpenSSH to use auths-verify.")?;

    // ssh-keygen -? returns non-zero but produces help output, that's fine
    if output.stderr.is_empty() && output.stdout.is_empty() {
        bail!("ssh-keygen not functioning properly");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use tempfile::tempdir;

    #[test]
    fn test_check_ssh_keygen() {
        // This test verifies ssh-keygen is available on the system
        let result = check_ssh_keygen();
        assert!(
            result.is_ok(),
            "ssh-keygen should be available: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_find_signer_nonexistent_file() {
        let dir = tempdir().unwrap();
        let sig_path = dir.path().join("nonexistent.sig");
        let allowed_path = dir.path().join("allowed_signers");

        // Create empty allowed_signers file
        File::create(&allowed_path).unwrap();

        // Should return None for nonexistent signature file
        let result = find_signer(&sig_path, &allowed_path);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }
}
