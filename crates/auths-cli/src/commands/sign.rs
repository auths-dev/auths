//! Unified sign command: signs a file artifact or a git commit range.

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use auths_sdk::core_config::EnvironmentConfig;
use auths_sdk::domains::identity::local::{LocalSigner, resolve_local_signer};
use auths_sdk::signing::PassphraseProvider;

use super::artifact::sign::handle_sign as handle_artifact_sign;

/// Represents the resolved target for a sign operation.
pub enum SignTarget {
    Artifact(PathBuf),
    CommitRange(String),
}

/// Resolves raw CLI input into a concrete target type.
///
/// Checks the filesystem first. If no file exists at the path, assumes a Git reference.
///
/// Args:
/// * `raw_target` - The raw string input from the CLI.
///
/// Usage:
/// ```ignore
/// let target = parse_sign_target("HEAD");
/// assert!(matches!(target, SignTarget::CommitRange(_)));
/// ```
pub fn parse_sign_target(raw_target: &str) -> SignTarget {
    let path = Path::new(raw_target);
    if path.exists() {
        SignTarget::Artifact(path.to_path_buf())
    } else {
        if looks_like_artifact_path(raw_target) {
            eprintln!(
                "Warning: '{}' looks like an artifact file path, but the file does not exist.\n\
                 Treating as a git commit range. If you meant to sign a file, check the path.",
                raw_target
            );
        }
        SignTarget::CommitRange(raw_target.to_string())
    }
}

/// Heuristic: does the target look like an artifact file path rather than a git ref?
fn looks_like_artifact_path(target: &str) -> bool {
    // Path-shaped strings
    if target.starts_with("./") || target.starts_with("../") || target.contains('/') {
        let lower = target.to_lowercase();
        return ARTIFACT_EXTENSIONS.iter().any(|ext| lower.ends_with(ext));
    }
    // Bare filename with artifact extension
    let lower = target.to_lowercase();
    ARTIFACT_EXTENSIONS.iter().any(|ext| lower.ends_with(ext))
}

const ARTIFACT_EXTENSIONS: &[&str] = &[
    ".tar.gz", ".tgz", ".zip", ".whl", ".gem", ".jar", ".deb", ".rpm", ".dmg", ".exe", ".msi",
    ".pkg", ".nupkg",
];

/// Reject capability scope values that carry control characters.
///
/// A scope value rides in a single-line `Auths-Scope` commit trailer; a newline
/// (or other control character) would split it into an attacker-chosen extra
/// trailer — for example a second `Auths-Id` — which a verifier would then
/// resolve instead of the real signer.
///
/// Args:
/// * `scope`: The capability tokens supplied via `--scope`.
///
/// Usage:
/// ```ignore
/// validate_scope(&scope)?;
/// ```
fn validate_scope(scope: &[String]) -> Result<()> {
    for value in scope {
        if value.chars().any(char::is_control) {
            anyhow::bail!(
                "Invalid --scope value {value:?}: control characters (including newlines) are not allowed"
            );
        }
    }
    Ok(())
}

/// Build the in-band signer trailers for the local machine's signing identity:
/// `Auths-Id` = root identity, `Auths-Device` = signing device, and (when the root
/// KEL tip is known) `Auths-Anchor-Seq` = the delegator-anchoring position at
/// signing, so a verifier can order this commit against a later revocation by KEL
/// position. The trailers ride in the commit message body, covered by the signature.
fn commit_trailer_args(signer: &LocalSigner, scope: &[String]) -> Vec<String> {
    let mut trailers = vec![
        format!("Auths-Id: {}", signer.root_did),
        format!("Auths-Device: {}", signer.signer_did),
    ];
    if let Some(seq) = signer.anchor_seq {
        trailers.push(auths_verifier::anchor_seq_trailer(seq));
    }
    // The capabilities this commit claims it exercises. A verifier rejects a claim
    // outside the signer's delegator-anchored grant (`CommitVerdict::OutsideAgentScope`).
    if !scope.is_empty() {
        trailers.push(auths_verifier::scope_trailer(scope));
    }
    trailers
}

/// Resolve the local signing identity → the trailer values to embed in-band.
///
/// Resolution reads identity + registry only (no key decryption), so it needs no
/// passphrase. Fails clearly when this machine has no resolvable signing identity.
fn resolve_signer_trailer(
    repo_opt: Option<&Path>,
    env_config: &EnvironmentConfig,
) -> Result<LocalSigner> {
    let repo_path =
        auths_sdk::storage_layout::resolve_repo_path(repo_opt.map(|p| p.to_path_buf()))?;
    let ctx = crate::factories::storage::build_auths_context(&repo_path, env_config, None)
        .context("Failed to build auths context for commit signing")?;
    resolve_local_signer(&ctx).map_err(anyhow::Error::from).context(
        "Could not resolve the local signing identity. Run `auths init`, or pair this device with `auths pair --join`.",
    )
}

/// Execute `git rebase --exec` to re-sign a range, embedding the signer trailers
/// per commit (the amend re-signs over the trailered message).
///
/// Args:
/// * `base` - The exclusive base ref (commits after this ref will be re-signed).
/// * `trailers` - The `Auths-Id` / `Auths-Device` trailer strings.
fn execute_git_rebase(base: &str, trailers: &[String]) -> Result<()> {
    // did:keri values and integer sequences are `[A-Za-z0-9_:.\- ]`, safe to
    // single-quote in the exec shell.
    let trailer_flags: String = trailers
        .iter()
        .map(|t| format!(" --trailer '{}'", t))
        .collect();
    // `-c trailer.ifexists=replace`: re-signing a commit that already carries an
    // Auths-* trailer replaces it in place rather than appending a second copy, so
    // a re-signed commit (the recovery rewrite) keeps exactly one trailer per token.
    let exec_cmd = format!(
        "git -c trailer.ifexists=replace commit --amend --no-edit --no-verify{trailer_flags}"
    );
    let output = crate::subprocess::git_command(&["rebase", "--exec", &exec_cmd, base])
        .output()
        .context("Failed to spawn git rebase")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "Failed to re-sign commits. Check for uncommitted changes or rebase conflicts.\n\nGit reported: {}",
            stderr.trim()
        ));
    }
    Ok(())
}

/// Ensure the signer's root is pinned in the repo's committed `.auths/roots` and
/// staged, so the pin (the trust declaration teammates and CI inherit) lands with
/// the next commit. Idempotent and best-effort — a pin failure never fails the
/// sign; self-trust already covers the signer's own verification.
fn ensure_repo_root_pin(signer: &LocalSigner) {
    let Ok(output) = crate::subprocess::git_command(&["rev-parse", "--show-toplevel"]).output()
    else {
        return;
    };
    if !output.status.success() {
        return;
    }
    let toplevel = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
    let auths_dir = toplevel.join(".auths");
    let store = crate::adapters::config_store::FileConfigStore;
    let root_did = signer.root_did.to_string();
    if auths_sdk::workflows::roots::is_pinned_root(&store, &auths_dir, &root_did).unwrap_or(false) {
        return;
    }
    if auths_sdk::workflows::roots::add_pinned_root(&store, &auths_dir, &root_did).is_ok() {
        let roots_file = auths_dir.join("roots");
        let _ =
            crate::subprocess::git_command(&["add", "--", &roots_file.to_string_lossy()]).output();
        eprintln!("auths: pinned your identity root in .auths/roots (staged for the next commit)");
    }
}

/// Resolve a git ref/range into the list of commit SHAs the amend rewrote, so we
/// can confirm each one actually carries a signature.
///
/// `HEAD`-style single refs resolve to that one commit; `base..tip` ranges resolve
/// to every commit the rebase re-signed.
fn resolve_signed_range_shas(range: &str) -> Result<Vec<String>> {
    let rev_arg = if range.contains("..") {
        range.to_string()
    } else {
        format!("{range}^!")
    };
    let output = crate::subprocess::git_command(&["rev-list", &rev_arg])
        .output()
        .context("Failed to list commits to confirm signing")?;
    if !output.status.success() {
        return Err(anyhow!(
            "Could not resolve '{}' to confirm the signature landed.\n\nGit reported: {}",
            range,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_string)
        .collect())
}

/// Confirm every commit in `range` actually carries an SSH signature after the amend.
///
/// The amend embeds the trailers and *asks* git to sign, but git only signs when a
/// signing program is configured (`gpg.format ssh` + `gpg.ssh.program`). When it is
/// not, the rewrite lands unsigned — and `auths verify` would then call the commit
/// `No signature found`. We use the verifier's own `gpgsig` detection as the single
/// source of truth so success is never claimed for a commit the verifier rejects.
fn ensure_commits_signed(range: &str) -> Result<()> {
    let shas = resolve_signed_range_shas(range)?;
    for sha in &shas {
        let raw = read_raw_commit_object(sha)?;
        if !auths_verifier::commit_object_is_signed(&raw) {
            return Err(anyhow!(
                "Commit {} was amended but no signature was attached, so `auths verify` would \
                 call it unsigned. Configure git SSH signing first — run `auths doctor --fix` \
                 (sets gpg.format=ssh, gpg.ssh.program=auths-sign, commit.gpgsign=true).",
                short_sha(sha)
            ));
        }
    }
    Ok(())
}

/// The raw git commit object (`git cat-file commit <sha>`) — the bytes a verifier
/// reads to decide whether a `gpgsig` SSH block is present.
fn read_raw_commit_object(sha: &str) -> Result<String> {
    let output = crate::subprocess::git_command(&["cat-file", "commit", sha])
        .output()
        .context("Failed to read commit object to confirm signing")?;
    if !output.status.success() {
        return Err(anyhow!(
            "git cat-file commit {} failed: {}",
            short_sha(sha),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout).context("Commit object is not valid UTF-8")
}

/// First 8 chars of a SHA for human-readable messages.
fn short_sha(sha: &str) -> &str {
    sha.get(..8).unwrap_or(sha)
}

/// Sign a Git commit range, embedding the `Auths-Id` / `Auths-Device` trailers
/// in-band so a verifier knows which KEL to replay. Amending triggers auths-sign
/// via git's signing program; the trailers (one per token — re-signing replaces
/// rather than appends, via `trailer.ifexists=replace`) are part of the signed
/// message body.
///
/// Args:
/// * `range` - A git ref or range (e.g., "HEAD", "main..HEAD").
/// * `signer` - The resolved local signing identity (root + device DIDs).
/// * `scope` - Capabilities this commit claims (emitted as an `Auths-Scope` trailer).
fn sign_commit_range(range: &str, signer: &LocalSigner, scope: &[String]) -> Result<()> {
    ensure_repo_root_pin(signer);
    validate_scope(scope)?;
    let trailers = commit_trailer_args(signer, scope);
    let is_range = range.contains("..");
    if is_range {
        let parts: Vec<&str> = range.splitn(2, "..").collect();
        let base = parts[0];
        execute_git_rebase(base, &trailers)?;
    } else {
        // `-c trailer.ifexists=replace`: amending a commit that already carries an
        // Auths-* trailer (a re-sign) replaces that trailer in place instead of
        // appending a duplicate, so the message keeps exactly one trailer per token.
        let mut args: Vec<&str> = vec![
            "-c",
            "trailer.ifexists=replace",
            "commit",
            "--amend",
            "--no-edit",
            "--no-verify",
        ];
        for trailer in &trailers {
            args.push("--trailer");
            args.push(trailer);
        }
        let output = crate::subprocess::git_command(&args)
            .output()
            .context("Failed to spawn git commit --amend")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!(
                "Failed to amend commit with signature. Ensure you have a commit to amend and no conflicting changes.\n\nGit reported: {}",
                stderr.trim()
            ));
        }
    }
    // The amend succeeded, but git only attaches a signature when a signing program
    // is configured. Confirm one actually landed before claiming success — otherwise
    // `auths verify` would call this commit unsigned and the success line would lie.
    ensure_commits_signed(range)?;
    if crate::ux::format::is_json_mode() {
        crate::ux::format::JsonResponse::success(
            "sign",
            &serde_json::json!({ "target": range, "type": "commit" }),
        )
        .print()?;
    } else {
        println!("✔ Signed: {}", range);
    }
    Ok(())
}

/// Sign a Git commit or artifact file.
#[derive(Parser, Debug, Clone)]
#[command(
    about = "Sign a Git commit or artifact file.",
    after_help = "Examples:
  auths sign README.md                    # Sign a file → README.md.auths.json
  auths sign HEAD                         # Sign the current commit
  auths sign main..HEAD                   # Re-sign commits after main

Artifacts:
  Signing files creates a .auths.json attestation with your identity and device.
  Use `auths verify` to check the signature.

Commits:
  Commit signing requires a linked device and Git configuration.
  Verify with `auths verify HEAD` or `git log --show-signature`.

Related:
  auths verify      — Verify signatures
  auths device list — Check linked devices"
)]
pub struct SignCommand {
    /// Git ref, commit range (e.g. HEAD, main..HEAD), or path to an artifact file.
    #[arg(help = "Commit ref, range, or artifact file path")]
    pub target: String,

    /// Output path for the signature file. Defaults to <FILE>.auths.json.
    #[arg(long = "sig-output", value_name = "PATH")]
    pub sig_output: Option<PathBuf>,

    /// Local alias of the identity key (for artifact signing).
    #[arg(long)]
    pub key: Option<String>,

    /// Local alias of the device key (for artifact signing, required for files).
    #[arg(long)]
    pub device_key: Option<String>,

    /// Duration in seconds until expiration (per RFC 6749).
    #[arg(long = "expires-in", value_name = "N")]
    pub expires_in: Option<u64>,

    /// Optional note to embed in the attestation (for artifact signing).
    #[arg(long)]
    pub note: Option<String>,

    /// Capabilities this commit claims it exercises (comma-separated), e.g.
    /// `--scope sign_commit`. Emitted as an `Auths-Scope` trailer so a verifier can
    /// reject a claim outside the signer's delegator-anchored grant. Commit-only.
    #[arg(long, value_delimiter = ',')]
    pub scope: Vec<String>,
}

/// Handle the unified sign command.
///
/// Args:
/// * `cmd` - Parsed SignCommand arguments.
/// * `repo_opt` - Optional path to the Auths identity repository.
/// * `passphrase_provider` - Provider for key passphrases.
pub fn handle_sign_unified(
    cmd: SignCommand,
    repo_opt: Option<PathBuf>,
    passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync>,
    env_config: &EnvironmentConfig,
) -> Result<()> {
    match parse_sign_target(&cmd.target) {
        SignTarget::Artifact(path) => {
            let device_key_alias = match cmd.device_key.as_deref() {
                Some(alias) => alias.to_string(),
                None => super::key_detect::auto_detect_device_key(repo_opt.as_deref(), env_config)?,
            };
            // A file attestation does not bind a commit: the ambient git HEAD is unrelated to the
            // file being signed, and inferring it would let whatever commit happens to be checked
            // out be claimed as the attestation's provenance. Bind one explicitly with
            // `auths artifact sign --commit <sha>`.
            let commit_sha: Option<String> = None;
            handle_artifact_sign(
                &path,
                cmd.sig_output,
                cmd.key.as_deref(),
                &device_key_alias,
                cmd.expires_in,
                cmd.note,
                commit_sha,
                repo_opt,
                passphrase_provider,
                env_config,
                &None,
                false,
            )
        }
        SignTarget::CommitRange(range) => {
            let signer = resolve_signer_trailer(repo_opt.as_deref(), env_config)?;
            sign_commit_range(&range, &signer, &cmd.scope)
        }
    }
}

impl crate::commands::executable::ExecutableCommand for SignCommand {
    fn execute(&self, ctx: &crate::config::CliConfig) -> anyhow::Result<()> {
        handle_sign_unified(
            self.clone(),
            ctx.repo_path.clone(),
            ctx.passphrase_provider.clone(),
            &ctx.env_config,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_trailer_args_emit_auths_id_and_device() {
        let signer = LocalSigner {
            signer_did: "did:keri:Edevice".to_string(),
            root_did: "did:keri:Eroot".to_string(),
            anchor_seq: None,
        };
        let trailers = commit_trailer_args(&signer, &[]);
        assert_eq!(trailers[0], "Auths-Id: did:keri:Eroot");
        assert_eq!(trailers[1], "Auths-Device: did:keri:Edevice");
        assert_eq!(
            trailers.len(),
            2,
            "no anchor seq + no scope → only Auths-Id/Auths-Device"
        );
    }

    #[test]
    fn trailer_carries_signing_sequence() {
        let signer = LocalSigner {
            signer_did: "did:keri:Edevice".to_string(),
            root_did: "did:keri:Eroot".to_string(),
            anchor_seq: Some(7),
        };
        let trailers = commit_trailer_args(&signer, &[]);
        assert_eq!(trailers.len(), 3);
        assert_eq!(trailers[2], "Auths-Anchor-Seq: 7");
    }

    #[test]
    fn commit_trailer_args_emit_scope_claim() {
        let signer = LocalSigner {
            signer_did: "did:keri:Eagent".to_string(),
            root_did: "did:keri:Eroot".to_string(),
            anchor_seq: Some(3),
        };
        let trailers =
            commit_trailer_args(&signer, &["sign_commit".to_string(), "open-PR".to_string()]);
        // Auths-Id, Auths-Device, Auths-Anchor-Seq, Auths-Scope (last).
        assert_eq!(trailers.len(), 4);
        assert_eq!(trailers[3], "Auths-Scope: sign_commit,open-PR");
        // Round-trips through the verifier's own formatter.
        assert_eq!(
            trailers[3],
            auths_verifier::scope_trailer(&["sign_commit".to_string(), "open-PR".to_string()])
        );
    }

    #[test]
    fn commit_trailer_args_no_scope_omits_trailer() {
        let signer = LocalSigner {
            signer_did: "did:keri:Eagent".to_string(),
            root_did: "did:keri:Eroot".to_string(),
            anchor_seq: None,
        };
        let trailers = commit_trailer_args(&signer, &[]);
        assert!(
            !trailers.iter().any(|t| t.starts_with("Auths-Scope")),
            "no scope claim → no Auths-Scope trailer (backward compatible)"
        );
    }

    #[test]
    fn validate_scope_rejects_control_chars() {
        // A newline would split the single-line Auths-Scope trailer, injecting an
        // attacker-chosen trailer (e.g. a forged Auths-Id) into the signed body.
        assert!(validate_scope(&["legit\nAuths-Id: did:keri:Eattacker".to_string()]).is_err());
        assert!(validate_scope(&["carriage\rreturn".to_string()]).is_err());
        assert!(validate_scope(&["tab\there".to_string()]).is_err());
        assert!(validate_scope(&["sign_commit".to_string(), "open-PR".to_string()]).is_ok());
        assert!(validate_scope(&[]).is_ok());
    }

    #[test]
    fn commit_trailer_args_root_machine_signs_directly() {
        // On the root machine signer == root → both trailers carry the same DID.
        let signer = LocalSigner {
            signer_did: "did:keri:Eroot".to_string(),
            root_did: "did:keri:Eroot".to_string(),
            anchor_seq: None,
        };
        let trailers = commit_trailer_args(&signer, &[]);
        assert_eq!(trailers[0], "Auths-Id: did:keri:Eroot");
        assert_eq!(trailers[1], "Auths-Device: did:keri:Eroot");
    }

    #[test]
    fn test_parse_sign_target_commit_ref() {
        let target = parse_sign_target("HEAD");
        assert!(matches!(target, SignTarget::CommitRange(_)));
    }

    #[test]
    fn test_parse_sign_target_range() {
        let target = parse_sign_target("main..HEAD");
        assert!(matches!(target, SignTarget::CommitRange(_)));
    }

    #[test]
    fn test_parse_sign_target_nonexistent_path_is_commit_range() {
        let target = parse_sign_target("/nonexistent/artifact.tar.gz");
        assert!(matches!(target, SignTarget::CommitRange(_)));
    }

    #[test]
    fn test_parse_sign_target_file() {
        use std::fs::File;
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("artifact.tar.gz");
        File::create(&file_path).unwrap();
        let target = parse_sign_target(file_path.to_str().unwrap());
        assert!(matches!(target, SignTarget::Artifact(_)));
    }
}
