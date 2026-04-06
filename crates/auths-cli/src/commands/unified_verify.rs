//! Unified verify command: verifies a git commit OR an attestation file.

use anyhow::Result;
use clap::Parser;
use std::path::{Path, PathBuf};

use super::verify_commit::{VerifyCommitCommand, handle_verify_commit};
use crate::commands::device::verify_attestation::{VerifyCommand, handle_verify};

/// What kind of target the user provided.
pub enum VerifyTarget {
    GitRef(String),
    Attestation(String),
    ArtifactFile(PathBuf), // binary artifact, will look up .auths.json sidecar
}

/// Determine whether `raw_target` is a Git reference or an attestation path.
///
/// Rules (evaluated in order):
/// 1. "-" → stdin attestation
/// 2. Path exists on disk and is JSON → attestation file
/// 3. Path exists on disk and is not JSON → artifact file (sidecar lookup)
/// 4. Contains ".." (range notation) → git ref
/// 5. Is "HEAD" or matches ^[0-9a-f]{4,40}$ → git ref
/// 6. Otherwise → git ref (assume the user knows what they're typing)
///
/// Args:
/// * `raw_target` - Raw CLI input string.
///
/// Usage:
/// ```ignore
/// let t = parse_verify_target("HEAD");
/// assert!(matches!(t, VerifyTarget::GitRef(_)));
/// ```
pub fn parse_verify_target(raw_target: &str) -> VerifyTarget {
    if raw_target == "-" {
        return VerifyTarget::Attestation(raw_target.to_string());
    }
    let path = Path::new(raw_target);
    if path.exists() {
        if is_attestation_path(raw_target) {
            return VerifyTarget::Attestation(raw_target.to_string());
        } else {
            return VerifyTarget::ArtifactFile(path.to_path_buf());
        }
    }
    if raw_target.contains("..") {
        return VerifyTarget::GitRef(raw_target.to_string());
    }
    if raw_target.eq_ignore_ascii_case("HEAD") {
        return VerifyTarget::GitRef(raw_target.to_string());
    }
    // 4-40 hex chars → commit hash
    let is_hex = raw_target.len() >= 4
        && raw_target.len() <= 40
        && raw_target.chars().all(|c| c.is_ascii_hexdigit());
    if is_hex {
        return VerifyTarget::GitRef(raw_target.to_string());
    }
    // Fallback: treat as git ref. The execution layer (handle_verify_commit) will
    // return a clear error if the ref doesn't resolve in the git repo, so no
    // silent data loss occurs from a typoed filename being misclassified.
    VerifyTarget::GitRef(raw_target.to_string())
}

/// Returns true if the path looks like an attestation/JSON file rather than a binary artifact.
fn is_attestation_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.ends_with(".json")
}

/// Unified verify command: verifies a signed commit or an attestation.
#[derive(Parser, Debug, Clone)]
#[command(
    about = "Verify a signed commit or attestation.",
    after_help = "Examples:
  auths verify HEAD                       # Verify current commit signature
  auths verify main..HEAD                 # Verify range of commits
  auths verify artifact.json              # Verify signed artifact
  auths verify - < artifact.json          # Verify from stdin

Trust Policies:
  Defaults to TOFU (Trust-On-First-Use) on interactive terminals.
  Use --trust explicit in CI/CD to reject unknown identities.

Artifact Verification:
  File signatures are stored as <file>.auths.json.
  JSON attestations can be verified directly.

Related:
  auths trust add <did>     — Add an identity to your trust store
  auths sign                — Create signatures
  auths --help-all          — See all commands"
)]
pub struct UnifiedVerifyCommand {
    /// Git ref, commit hash, range (e.g. HEAD, abc1234, main..HEAD),
    /// or path to an attestation JSON file / "-" for stdin.
    #[arg(default_value = "HEAD")]
    pub target: String,

    /// Path to allowed signers file (commit verification).
    #[arg(long, default_value = ".auths/allowed_signers")]
    pub allowed_signers: PathBuf,

    /// Path to identity bundle JSON (for CI/CD stateless commit verification).
    #[arg(long, value_parser)]
    pub identity_bundle: Option<PathBuf>,

    /// Issuer public key in hex format (attestation verification).
    #[arg(long = "issuer-pk")]
    pub issuer_pk: Option<String>,

    /// Issuer identity ID for attestation trust-based key resolution.
    #[arg(long = "issuer-did", visible_alias = "issuer")]
    pub issuer_did: Option<String>,

    /// Path to witness receipts JSON file.
    #[arg(long)]
    pub witness_receipts: Option<PathBuf>,

    /// Witness quorum threshold.
    #[arg(long, default_value = "1")]
    pub witness_threshold: usize,

    /// Witness public keys as DID:hex pairs.
    #[arg(long, num_args = 1..)]
    pub witness_keys: Vec<String>,
}

/// Handle the unified verify command.
///
/// Routes to commit verification or attestation verification based on target type.
///
/// Args:
/// * `cmd` - Parsed UnifiedVerifyCommand.
pub async fn handle_verify_unified(cmd: UnifiedVerifyCommand) -> Result<()> {
    match parse_verify_target(&cmd.target) {
        VerifyTarget::GitRef(ref_str) => {
            let commit_cmd = VerifyCommitCommand {
                commit: ref_str,
                allowed_signers: cmd.allowed_signers,
                identity_bundle: cmd.identity_bundle,
                witness_receipts: cmd.witness_receipts,
                witness_threshold: cmd.witness_threshold,
                witness_keys: cmd.witness_keys,
            };
            handle_verify_commit(commit_cmd).await
        }
        VerifyTarget::Attestation(path_str) => {
            let verify_cmd = VerifyCommand {
                attestation: path_str,
                issuer_pk: cmd.issuer_pk,
                issuer_did: cmd.issuer_did,
                trust: None,
                roots_file: None,
                require_capability: None,
                witness_receipts: cmd.witness_receipts,
                witness_threshold: cmd.witness_threshold,
                witness_keys: cmd.witness_keys,
            };
            handle_verify(verify_cmd).await
        }
        VerifyTarget::ArtifactFile(_) => todo!("artifact file routing"),
    }
}

impl crate::commands::executable::ExecutableCommand for UnifiedVerifyCommand {
    fn execute(&self, _ctx: &crate::config::CliConfig) -> anyhow::Result<()> {
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(handle_verify_unified(self.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_verify_target_git_ref() {
        assert!(matches!(
            parse_verify_target("HEAD"),
            VerifyTarget::GitRef(_)
        ));
        assert!(matches!(
            parse_verify_target("abc1234"),
            VerifyTarget::GitRef(_)
        ));
        assert!(matches!(
            parse_verify_target("main..HEAD"),
            VerifyTarget::GitRef(_)
        ));
    }

    #[test]
    fn test_parse_verify_target_stdin() {
        assert!(matches!(
            parse_verify_target("-"),
            VerifyTarget::Attestation(_)
        ));
    }

    #[test]
    fn test_parse_verify_target_nonexistent_defaults_to_git_ref() {
        let target = parse_verify_target("/nonexistent/attestation.json");
        assert!(matches!(target, VerifyTarget::GitRef(_)));
    }

    #[test]
    fn test_parse_verify_target_file() {
        use std::fs::File;
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let f = dir.path().join("attestation.json");
        File::create(&f).unwrap();
        let target = parse_verify_target(f.to_str().unwrap());
        assert!(matches!(target, VerifyTarget::Attestation(_)));
    }

    #[test]
    fn test_parse_verify_target_binary_file_routes_to_artifact() {
        use std::fs::File;
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let artifact = dir.path().join("release.tar.gz");
        File::create(&artifact).unwrap();
        let target = parse_verify_target(artifact.to_str().unwrap());
        assert!(matches!(target, VerifyTarget::ArtifactFile(_)));
    }

    #[test]
    fn test_parse_verify_target_json_file_routes_to_attestation() {
        use std::fs::File;
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let attest = dir.path().join("release.auths.json");
        File::create(&attest).unwrap();
        let target = parse_verify_target(attest.to_str().unwrap());
        assert!(matches!(target, VerifyTarget::Attestation(_)));
    }

    #[test]
    fn test_parse_verify_target_plain_json_routes_to_attestation() {
        use std::fs::File;
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let f = dir.path().join("attestation.json");
        File::create(&f).unwrap();
        let target = parse_verify_target(f.to_str().unwrap());
        assert!(matches!(target, VerifyTarget::Attestation(_)));
    }
}
