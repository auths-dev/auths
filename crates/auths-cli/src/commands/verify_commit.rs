use crate::ux::format::is_json_mode;
use anyhow::{Context, Result, anyhow};
use auths_keri::witness::SignedReceipt;
use auths_verifier::witness::{WitnessQuorum, WitnessVerifyConfig};
use auths_verifier::{
    Attestation, IdentityBundle, VerificationReport, verify_chain, verify_chain_with_witnesses,
};
use chrono::{DateTime, Duration, Utc};
use clap::Parser;
use serde::Serialize;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::subprocess::git_command;
use tempfile::NamedTempFile;

use super::verify_helpers::parse_witness_keys;

#[derive(Parser, Debug, Clone)]
#[command(about = "Verify Git commit signatures against Auths identity.")]
pub struct VerifyCommitCommand {
    /// Commit SHA, range (e.g., HEAD~5..HEAD), or "HEAD" (default).
    #[arg(default_value = "HEAD")]
    pub commit: String,

    /// Path to allowed signers file.
    #[arg(long, default_value = ".auths/allowed_signers")]
    pub allowed_signers: PathBuf,

    /// Path to identity bundle JSON (for CI/CD stateless verification).
    ///
    /// When provided, verification uses the bundle's public key instead of
    /// the allowed_signers file. This enables stateless verification without
    /// requiring access to identity repositories.
    #[arg(long, value_parser, help = "Path to identity bundle JSON (for CI)")]
    pub identity_bundle: Option<PathBuf>,

    /// Path to witness signatures JSON file.
    #[arg(long = "witness-signatures")]
    pub witness_receipts: Option<PathBuf>,

    /// Number of witnesses required (default: 1).
    #[arg(long = "witnesses-required", default_value = "1")]
    pub witness_threshold: usize,

    /// Witness public keys as DID:hex pairs (e.g., "did:key:z6Mk...:abcd1234...").
    #[arg(long, num_args = 1..)]
    pub witness_keys: Vec<String>,
}

#[derive(Serialize)]
struct VerifyCommitResult {
    commit: String,
    valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssh_valid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chain_valid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chain_report: Option<VerificationReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    witness_quorum: Option<WitnessQuorum>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    oidc_binding: Option<OidcBindingDisplay>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
}

/// Display representation of OIDC binding information.
///
/// Extracted from the attestation when available, shows CI/CD workload context
/// that signed the commit (issuer, subject, platform, and normalized claims).
#[derive(Serialize)]
struct OidcBindingDisplay {
    /// OIDC token issuer (e.g., "https://token.actions.githubusercontent.com").
    issuer: String,
    /// Token subject (unique workload identifier).
    subject: String,
    /// Expected audience.
    audience: String,
    /// CI/CD platform (e.g., "github", "gitlab", "circleci").
    #[serde(skip_serializing_if = "Option::is_none")]
    platform: Option<String>,
    /// Platform-normalized claims (e.g., repo, actor, run_id for GitHub).
    #[serde(skip_serializing_if = "Option::is_none")]
    normalized_claims: Option<serde_json::Map<String, serde_json::Value>>,
}

impl VerifyCommitResult {
    fn failure(commit: String, error: String) -> Self {
        Self {
            commit,
            valid: false,
            ssh_valid: None,
            chain_valid: None,
            chain_report: None,
            witness_quorum: None,
            signer: None,
            oidc_binding: None,
            error: Some(error),
            warnings: Vec::new(),
        }
    }
}

/// Source of allowed signers for SSH verification.
enum SignersSource {
    /// User-provided allowed_signers file.
    File(PathBuf),
    /// Identity bundle (creates temp signers file from bundle's public key).
    Bundle {
        temp_signers: NamedTempFile,
        bundle: IdentityBundle,
    },
}

impl SignersSource {
    fn signers_path(&self) -> &Path {
        match self {
            SignersSource::File(p) => p,
            SignersSource::Bundle { temp_signers, .. } => temp_signers.path(),
        }
    }

    fn bundle(&self) -> Option<&IdentityBundle> {
        match self {
            SignersSource::File(_) => None,
            SignersSource::Bundle { bundle, .. } => Some(bundle),
        }
    }
}

/// Handle verify-commit command.
/// Exit codes: 0=valid, 1=invalid/unsigned, 2=error
#[allow(clippy::disallowed_methods)]
pub async fn handle_verify_commit(cmd: VerifyCommitCommand) -> Result<()> {
    let now = Utc::now();

    if let Err(e) = check_ssh_keygen() {
        return handle_error(&cmd, 2, &format!("OpenSSH required: {}", e));
    }

    let source = match resolve_signers_source(&cmd) {
        Ok(s) => s,
        Err(e) => return handle_error(&cmd, 2, &e.to_string()),
    };

    let results = match verify_commits(&cmd, &source, now).await {
        Ok(r) => r,
        Err(e) => return handle_error(&cmd, 2, &e.to_string()),
    };

    output_results(&results)
}

/// Build a SignersSource from either --identity-bundle or --allowed-signers.
fn resolve_signers_source(cmd: &VerifyCommitCommand) -> Result<SignersSource> {
    if let Some(ref bundle_path) = cmd.identity_bundle {
        let bundle_content = fs::read_to_string(bundle_path)
            .with_context(|| format!("Failed to read identity bundle: {:?}", bundle_path))?;

        let bundle: IdentityBundle = serde_json::from_str(&bundle_content)
            .with_context(|| format!("Failed to parse identity bundle: {:?}", bundle_path))?;

        let public_key_bytes = hex::decode(bundle.public_key_hex.as_str())
            .context("Invalid public key hex in bundle")?;

        // Curve carried in-band on the bundle JSON; never inferred from length.
        let curve = bundle.curve;
        if public_key_bytes.len() != curve.public_key_len() {
            anyhow::bail!(
                "Bundle public key length {} does not match declared curve {} (expected {} bytes)",
                public_key_bytes.len(),
                curve,
                curve.public_key_len(),
            );
        }
        let device_pk = auths_verifier::DevicePublicKey::try_new(curve, &public_key_bytes)
            .context("Invalid public key in bundle")?;
        let ssh_key = auths_sdk::workflows::git_integration::public_key_to_ssh(&device_pk)
            .context("Failed to encode public key as SSH")?;
        let temp_signers_content = format!("{} {}", bundle.identity_did, ssh_key);

        let mut temp_signers =
            NamedTempFile::new().context("Failed to create temporary allowed_signers file")?;
        temp_signers
            .write_all(temp_signers_content.as_bytes())
            .context("Failed to write temporary allowed_signers")?;
        temp_signers.flush()?;

        Ok(SignersSource::Bundle {
            temp_signers,
            bundle,
        })
    } else {
        if !cmd.allowed_signers.exists() {
            return Err(anyhow!(
                "Allowed signers file not found: {:?}\n\nCreate it with:\n  mkdir -p .auths\n  echo 'user@example.com ssh-ed25519 AAAA...' > .auths/allowed_signers",
                cmd.allowed_signers
            ));
        }
        Ok(SignersSource::File(cmd.allowed_signers.clone()))
    }
}

/// Resolve the commit spec to a list of commit SHAs.
fn resolve_commits(commit_spec: &str) -> Result<Vec<String>> {
    if commit_spec.contains("..") {
        // Commit range — use git rev-list
        let output = git_command(&["rev-list", commit_spec])
            .output()
            .context("Failed to run git rev-list")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let lower = stderr.to_lowercase();

            if lower.contains("unknown revision") || lower.contains("bad revision") {
                return Err(anyhow!(
                    "{}",
                    format_commit_range_hint(commit_spec, stderr.trim())
                ));
            }

            return Err(anyhow!("Invalid commit range: {}", stderr.trim()));
        }

        let commits: Vec<String> = std::str::from_utf8(&output.stdout)
            .context("Invalid UTF-8 in git output")?
            .lines()
            .map(|s| s.to_string())
            .collect();

        if commits.is_empty() {
            return Err(anyhow!("No commits in specified range"));
        }
        Ok(commits)
    } else {
        // Single commit — resolve via rev-parse
        let sha = resolve_commit_sha(commit_spec)?;
        Ok(vec![sha])
    }
}

/// Build a contextual hint when a commit range fails to resolve.
fn format_commit_range_hint(commit_spec: &str, raw_stderr: &str) -> String {
    let hint = if commit_spec.contains('~') || commit_spec.contains('^') {
        "This repository may not have enough commits for that range. \
         Try a smaller offset (e.g. HEAD~1..HEAD) or verify with `git log --oneline`."
    } else if commit_spec.contains("..") {
        "One or both refs in the range do not exist. \
         Check branch/tag names with `git branch -a` or `git tag -l`."
    } else {
        "The commit reference could not be resolved. \
         Verify it exists with `git log --oneline`."
    };

    format!("Failed to resolve commit range '{commit_spec}': {raw_stderr}\n\nHint: {hint}")
}

/// Load an attestation from git ref `refs/auths/commits/<sha>`.
///
/// Attestations are stored as JSON in git refs using the naming convention
/// `refs/auths/commits/<commit-sha>`. This function reads the ref, parses the JSON,
/// and returns the attestation if successful.
///
/// Returns None if the ref doesn't exist, can't be read, or the JSON is invalid.
fn try_load_attestation_from_ref(commit_sha: &str) -> Option<Attestation> {
    let ref_name = format!("refs/auths/commits/{}", commit_sha);

    let stdout = crate::subprocess::git_silent(&["show", &ref_name])?;
    serde_json::from_str(&stdout).ok()
}

/// Extract OIDC binding display from an attestation.
///
/// Converts the internal `OidcBinding` structure from an attestation into
/// a display-friendly `OidcBindingDisplay` that includes issuer, subject,
/// platform, and normalized claims from the CI/CD workload.
///
/// Returns None if the attestation has no OIDC binding, which is expected
/// for non-OIDC attestations or older attestations created before OIDC binding
/// was added.
fn extract_oidc_binding_display(attestation: &Attestation) -> Option<OidcBindingDisplay> {
    attestation
        .oidc_binding
        .as_ref()
        .map(|binding| OidcBindingDisplay {
            issuer: binding.issuer.clone(),
            subject: binding.subject.clone(),
            audience: binding.audience.clone(),
            platform: binding.platform.clone(),
            normalized_claims: binding.normalized_claims.clone(),
        })
}

/// Verify all commits in the list.
async fn verify_commits(
    cmd: &VerifyCommitCommand,
    source: &SignersSource,
    now: DateTime<Utc>,
) -> Result<Vec<VerifyCommitResult>> {
    let commits = resolve_commits(&cmd.commit)?;
    let mut results = Vec::with_capacity(commits.len());

    for sha in &commits {
        let result = verify_one_commit(cmd, source, sha, now).await;
        results.push(result);
    }

    Ok(results)
}

/// Verify a single commit: SSH signature + optional chain + optional witnesses.
async fn verify_one_commit(
    cmd: &VerifyCommitCommand,
    source: &SignersSource,
    commit_sha: &str,
    now: DateTime<Utc>,
) -> VerifyCommitResult {
    // Resolve commit ref to SHA
    let sha = match resolve_commit_sha(commit_sha) {
        Ok(sha) => sha,
        Err(e) => {
            return VerifyCommitResult::failure(
                commit_sha.to_string(),
                format!("Failed to resolve commit: {}", e),
            );
        }
    };

    // Get commit signature info
    let sig_info = match get_commit_signature(&sha) {
        Ok(info) => info,
        Err(e) => return VerifyCommitResult::failure(sha, e.to_string()),
    };

    // 1. SSH signature check
    let (ssh_valid, signer) = match sig_info {
        SignatureInfo::None => {
            return VerifyCommitResult::failure(sha, "No signature found".to_string());
        }
        SignatureInfo::Gpg => {
            return VerifyCommitResult::failure(
                sha,
                "GPG signatures not supported, use SSH signing".to_string(),
            );
        }
        SignatureInfo::Ssh { signature, payload } => {
            match verify_ssh_signature(source.signers_path(), &signature, &payload) {
                Ok(signer) => (true, Some(signer)),
                Err(e) => {
                    return VerifyCommitResult {
                        commit: sha,
                        valid: false,
                        ssh_valid: Some(false),
                        chain_valid: None,
                        chain_report: None,
                        witness_quorum: None,
                        signer: None,
                        oidc_binding: None,
                        error: Some(e.to_string()),
                        warnings: Vec::new(),
                    };
                }
            }
        }
    };

    let mut warnings = Vec::new();

    // 2. Attestation chain verification (only when bundle is present)
    let (chain_valid, chain_report) = if let Some(bundle) = source.bundle() {
        let (cv, cr, cw) = verify_bundle_chain(bundle, now).await;
        warnings.extend(cw);
        (cv, cr)
    } else {
        (None, None)
    };

    // 3. Witness verification
    let witness_quorum = match verify_witnesses(cmd, source.bundle()).await {
        Ok(q) => q,
        Err(e) => {
            return VerifyCommitResult {
                commit: sha,
                valid: false,
                ssh_valid: Some(ssh_valid),
                chain_valid,
                chain_report,
                witness_quorum: None,
                signer,
                oidc_binding: None,
                error: Some(format!("Witness verification error: {}", e)),
                warnings,
            };
        }
    };

    // 4. Try to load attestation from git refs for OIDC binding info
    let oidc_binding =
        try_load_attestation_from_ref(&sha).and_then(|att| extract_oidc_binding_display(&att));

    // 5. Compute overall verdict
    let mut valid = ssh_valid;

    if let Some(cv) = chain_valid
        && !cv
    {
        valid = false;
    }

    if let Some(ref q) = witness_quorum
        && q.verified < q.required
    {
        valid = false;
    }

    VerifyCommitResult {
        commit: sha,
        valid,
        ssh_valid: Some(ssh_valid),
        chain_valid,
        chain_report,
        witness_quorum,
        signer,
        oidc_binding,
        error: None,
        warnings,
    }
}

/// Verify the attestation chain from an identity bundle.
///
/// Returns (chain_valid, chain_report, warnings).
async fn verify_bundle_chain(
    bundle: &IdentityBundle,
    now: DateTime<Utc>,
) -> (Option<bool>, Option<VerificationReport>, Vec<String>) {
    if let Err(e) = bundle.check_freshness(now) {
        return (
            Some(false),
            None,
            vec![format!("Bundle freshness check failed: {}", e)],
        );
    }

    if bundle.attestation_chain.is_empty() {
        return (
            None,
            None,
            vec!["No attestation chain in bundle; SSH-only verification".to_string()],
        );
    }

    let root_pk_bytes = match hex::decode(bundle.public_key_hex.as_str()) {
        Ok(pk) => pk,
        Err(e) => {
            return (
                Some(false),
                None,
                vec![format!("Invalid public key hex in bundle: {}", e)],
            );
        }
    };
    let root_pk = match auths_verifier::DevicePublicKey::try_new(bundle.curve, &root_pk_bytes)
        .map_err(|e| format!("Invalid bundle public key: {e}"))
    {
        Ok(pk) => pk,
        Err(msg) => return (Some(false), None, vec![msg]),
    };

    match verify_chain(&bundle.attestation_chain, &root_pk).await {
        Ok(report) => {
            let mut warnings = Vec::new();

            // Scan for upcoming expiry (< 30 days)
            for att in &bundle.attestation_chain {
                if let Some(exp) = att.expires_at {
                    let remaining = exp - now;
                    if remaining < Duration::zero() {
                        // Already expired — chain_valid will be false from the report
                    } else if remaining < Duration::days(30) {
                        warnings.push(format!(
                            "Attestation for {} expires in {} days",
                            att.subject,
                            remaining.num_days()
                        ));
                    }
                }
            }

            let is_valid = report.is_valid();
            (Some(is_valid), Some(report), warnings)
        }
        Err(e) => (
            Some(false),
            None,
            vec![format!("Chain verification error: {}", e)],
        ),
    }
}

/// Verify witness receipts if --witness-receipts was provided.
async fn verify_witnesses(
    cmd: &VerifyCommitCommand,
    bundle: Option<&IdentityBundle>,
) -> Result<Option<WitnessQuorum>> {
    let receipts_path = match cmd.witness_receipts {
        Some(ref p) => p,
        None => return Ok(None),
    };

    let receipts_bytes = fs::read(receipts_path)
        .with_context(|| format!("Failed to read witness receipts: {:?}", receipts_path))?;

    let receipts: Vec<SignedReceipt> =
        serde_json::from_slice(&receipts_bytes).context("Failed to parse witness receipts JSON")?;

    let witness_keys = parse_witness_keys(&cmd.witness_keys)?;

    let config = WitnessVerifyConfig {
        receipts: &receipts,
        witness_keys: &witness_keys,
        threshold: cmd.witness_threshold,
    };

    // If bundle has attestation chain, do combined chain + witness verification
    if let Some(bundle) = bundle
        && !bundle.attestation_chain.is_empty()
    {
        let root_pk_bytes = hex::decode(bundle.public_key_hex.as_str())
            .context("Invalid public key hex in bundle")?;
        let root_pk = auths_verifier::DevicePublicKey::try_new(bundle.curve, &root_pk_bytes)
            .map_err(|e| anyhow!("Invalid bundle public key: {e}"))?;

        let report = verify_chain_with_witnesses(&bundle.attestation_chain, &root_pk, &config)
            .await
            .context("Witness chain verification failed")?;

        return Ok(report.witness_quorum);
    }

    // Standalone witness receipt verification (no chain)
    let provider = auths_crypto::RingCryptoProvider;
    let quorum = auths_verifier::witness::verify_witness_receipts(&config, &provider).await;
    Ok(Some(quorum))
}

/// Unified output for all results, with JSON/text formatting and exit codes.
fn output_results(results: &[VerifyCommitResult]) -> Result<()> {
    let all_valid = results.iter().all(|r| r.valid);

    if is_json_mode() {
        if results.len() == 1 {
            println!("{}", serde_json::to_string(&results[0])?);
        } else {
            println!("{}", serde_json::to_string(&results)?);
        }
    } else if results.len() == 1 {
        let r = &results[0];
        if r.valid {
            if let Some(ref signer) = r.signer {
                print!("Commit {} verified: signed by {}", r.commit, signer);
            } else {
                print!("Commit {} verified", r.commit);
            }
            print_chain_witness_summary(r);
            println!();
        } else {
            eprint!("Verification failed for {}", r.commit);
            if let Some(ref error) = r.error {
                eprint!(": {}", error);
            }
            print_chain_witness_summary_stderr(r);
            eprintln!();
        }
        for w in &r.warnings {
            eprintln!("Warning: {}", w);
        }
    } else {
        for r in results {
            print!(
                "{}: {}",
                &r.commit[..8.min(r.commit.len())],
                format_result_text(r)
            );
            println!();
        }
    }

    if all_valid {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

/// Format a single result as a human-readable line (for range output).
fn format_result_text(result: &VerifyCommitResult) -> String {
    let status = if result.valid { "valid" } else { "INVALID" };

    let mut parts = vec![status.to_string()];

    if let Some(ref signer) = result.signer {
        parts.push(format!("signer: {}", signer));
    }

    if let Some(cv) = result.chain_valid {
        let chain_desc = if cv {
            "chain: valid".to_string()
        } else if let Some(ref report) = result.chain_report {
            format!("chain: {}", format_chain_status(&report.status))
        } else {
            "chain: invalid".to_string()
        };
        parts.push(chain_desc);
    }

    if let Some(ref q) = result.witness_quorum {
        parts.push(format!("witnesses: {}/{}", q.verified, q.required));
    }

    if let Some(ref binding) = result.oidc_binding {
        parts.push(format!("oidc: {}", binding.issuer));
    }

    if let Some(ref error) = result.error
        && result.signer.is_none()
        && result.chain_valid.is_none()
        && result.witness_quorum.is_none()
    {
        parts.push(error.clone());
    }

    if parts.len() == 1 {
        parts[0].clone()
    } else {
        format!("{} ({})", parts[0], parts[1..].join(", "))
    }
}

/// Format a VerificationStatus for display.
fn format_chain_status(status: &auths_verifier::VerificationStatus) -> String {
    match status {
        auths_verifier::VerificationStatus::Valid => "valid".to_string(),
        auths_verifier::VerificationStatus::Expired { at } => {
            format!("expired at {}", at.to_rfc3339())
        }
        auths_verifier::VerificationStatus::Revoked { at } => match at {
            Some(t) => format!("revoked at {}", t.to_rfc3339()),
            None => "revoked".to_string(),
        },
        auths_verifier::VerificationStatus::InvalidSignature { step } => {
            format!("invalid signature at step {}", step)
        }
        auths_verifier::VerificationStatus::BrokenChain { missing_link } => {
            format!("broken chain: {}", missing_link)
        }
        auths_verifier::VerificationStatus::InsufficientWitnesses { required, verified } => {
            format!("witnesses: {}/{} quorum not met", verified, required)
        }
    }
}

/// Print chain/witness summary to stdout (for valid single-commit output).
fn print_chain_witness_summary(r: &VerifyCommitResult) {
    let mut parts = Vec::new();

    if let Some(cv) = r.chain_valid {
        if cv {
            parts.push("chain: valid".to_string());
        } else {
            parts.push("chain: invalid".to_string());
        }
    }

    if let Some(ref q) = r.witness_quorum {
        parts.push(format!("witnesses: {}/{}", q.verified, q.required));
    }

    if let Some(ref binding) = r.oidc_binding {
        parts.push(format!("oidc: {} ({})", binding.issuer, binding.subject));
    }

    if !parts.is_empty() {
        print!(" ({})", parts.join(", "));
    }
}

/// Print chain/witness summary to stderr (for invalid single-commit output).
fn print_chain_witness_summary_stderr(r: &VerifyCommitResult) {
    if let Some(cv) = r.chain_valid
        && !cv
        && let Some(ref report) = r.chain_report
    {
        eprint!(" (chain: {})", format_chain_status(&report.status));
    }
    if let Some(ref q) = r.witness_quorum
        && q.verified < q.required
    {
        eprint!(" (witnesses: {}/{} quorum not met)", q.verified, q.required);
    }
}

// ============================================================================
// Internal helpers (unchanged SSH / Git plumbing)
// ============================================================================

enum SignatureInfo {
    None,
    Gpg,
    Ssh { signature: String, payload: String },
}

fn resolve_commit_sha(commit_ref: &str) -> Result<String> {
    super::git_helpers::resolve_commit_sha(commit_ref)
}

fn get_commit_signature(sha: &str) -> Result<SignatureInfo> {
    let output = git_command(&["cat-file", "commit", sha])
        .output()
        .context("Failed to run git cat-file")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "Failed to read commit object for '{}'. Ensure the SHA exists in this repository.\n\nGit reported: {}",
            sha,
            stderr.trim()
        ));
    }

    let commit_content = String::from_utf8_lossy(&output.stdout);

    if commit_content.contains("-----BEGIN PGP SIGNATURE-----") {
        return Ok(SignatureInfo::Gpg);
    }

    if commit_content.contains("-----BEGIN SSH SIGNATURE-----") {
        let (signature, payload) = extract_ssh_signature(&commit_content)?;
        return Ok(SignatureInfo::Ssh { signature, payload });
    }

    let show_output = git_command(&["log", "-1", "--format=%G?", sha])
        .output()
        .context("Failed to run git log")?;

    if show_output.status.success() {
        let sig_status = String::from_utf8_lossy(&show_output.stdout)
            .trim()
            .to_string();
        match sig_status.as_str() {
            "N" => return Ok(SignatureInfo::None),
            "G" | "U" | "X" | "Y" | "R" | "E" | "B" => {
                return Ok(SignatureInfo::Gpg);
            }
            _ => {}
        }
    }

    Ok(SignatureInfo::None)
}

fn extract_ssh_signature(commit_content: &str) -> Result<(String, String)> {
    // Process the commit object content preserving exact byte content for the payload.
    // git signs/verifies the raw commit bytes with the gpgsig header block removed;
    // any deviation (missing trailing \n, wrong line endings) causes "incorrect signature".
    let mut sig_lines: Vec<&str> = Vec::new();
    let mut payload = String::with_capacity(commit_content.len());
    let mut in_sig = false;

    let mut remaining = commit_content;
    while !remaining.is_empty() {
        // Consume one line, keeping its \n terminator intact.
        let (line_with_nl, rest) = match remaining.find('\n') {
            Some(i) => (&remaining[..=i], &remaining[i + 1..]),
            None => (remaining, ""),
        };
        remaining = rest;

        // Line content without the trailing \n, for prefix checks.
        let line = line_with_nl.strip_suffix('\n').unwrap_or(line_with_nl);

        if line.starts_with("gpgsig ") {
            in_sig = true;
            sig_lines.push(line.strip_prefix("gpgsig ").unwrap_or(line));
            // gpgsig lines are excluded from the payload.
        } else if in_sig && line.starts_with(' ') {
            // Continuation line of the gpgsig block.
            sig_lines.push(line.strip_prefix(' ').unwrap_or(line));
        } else {
            in_sig = false;
            // All non-signature lines go into the payload verbatim, \n included.
            payload.push_str(line_with_nl);
        }
    }

    if sig_lines.is_empty() {
        return Err(anyhow!("No SSH signature found in commit"));
    }

    // PEM lines are joined with \n (no trailing \n on the last line).
    let signature = sig_lines.join("\n");

    Ok((signature, payload))
}

fn verify_ssh_signature(signers_path: &Path, signature: &str, payload: &str) -> Result<String> {
    let mut sig_file = NamedTempFile::new().context("Failed to create temp signature file")?;
    sig_file
        .write_all(signature.as_bytes())
        .context("Failed to write signature")?;
    sig_file.flush()?;

    // Step 1: find-principals — resolves the signer identity from the allowed_signers file.
    // This must come before verify because `-I "*"` is not a valid wildcard for ssh-keygen
    // on all OpenSSH versions; using the actual identity is required for verify to succeed.
    let find_output = Command::new("ssh-keygen")
        .args(["-Y", "find-principals", "-f"])
        .arg(signers_path)
        .arg("-s")
        .arg(sig_file.path())
        .output()
        .context("Failed to run ssh-keygen find-principals")?;

    if !find_output.status.success() {
        return Err(anyhow!("Signature from non-allowed signer"));
    }
    let identity = String::from_utf8_lossy(&find_output.stdout)
        .trim()
        .to_string();
    if identity.is_empty() {
        return Err(anyhow!("Signature from non-allowed signer"));
    }

    // Step 2: cryptographically verify with the resolved identity.
    // Write payload to a temp file and pass as stdin to avoid deadlock on piped stdin.
    let mut payload_file = NamedTempFile::new().context("Failed to create temp payload file")?;
    payload_file
        .write_all(payload.as_bytes())
        .context("Failed to write payload")?;
    payload_file.flush()?;

    let stdin_file =
        std::fs::File::open(payload_file.path()).context("Failed to open payload file as stdin")?;

    let output = Command::new("ssh-keygen")
        .args(["-Y", "verify", "-f"])
        .arg(signers_path)
        .args(["-I", &identity, "-n", "git", "-s"])
        .arg(sig_file.path())
        .stdin(stdin_file)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("Failed to run ssh-keygen")?;

    if output.status.success() {
        return Ok(identity);
    }

    // ssh-keygen writes errors to stdout on some platforms; check both.
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let msg = if !stdout.trim().is_empty() {
        stdout.trim().to_string()
    } else {
        stderr.trim().to_string()
    };

    if msg.contains("no principal matched") || msg.contains("NONE_ACCEPTED") {
        return Err(anyhow!("Signature from non-allowed signer"));
    }

    Err(anyhow!("Signature verification failed: {}", msg))
}

fn check_ssh_keygen() -> Result<()> {
    let output = Command::new("ssh-keygen")
        .arg("-?")
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .output()
        .with_context(|| {
            let hint = platform_ssh_install_hint();
            format!("ssh-keygen not found in PATH. {hint}")
        })?;

    if output.stderr.is_empty() && output.stdout.is_empty() {
        let hint = platform_ssh_install_hint();
        return Err(anyhow!("ssh-keygen not functioning. {hint}"));
    }

    Ok(())
}

fn platform_ssh_install_hint() -> &'static str {
    if cfg!(target_os = "macos") {
        "ssh-keygen is normally pre-installed on macOS. Check your PATH."
    } else if cfg!(target_os = "windows") {
        "Install OpenSSH via Settings > Apps > Optional features, or `winget install Microsoft.OpenSSH.Client`."
    } else {
        "Install OpenSSH: `sudo apt install openssh-client` (Debian/Ubuntu) or `sudo dnf install openssh-clients` (Fedora/RHEL)."
    }
}

fn handle_error(cmd: &VerifyCommitCommand, exit_code: i32, message: &str) -> Result<()> {
    if is_json_mode() {
        let result = VerifyCommitResult::failure(cmd.commit.clone(), message.to_string());
        println!("{}", serde_json::to_string(&result)?);
    } else {
        eprintln!("Error: {}", message);
    }
    std::process::exit(exit_code);
}

impl crate::commands::executable::ExecutableCommand for VerifyCommitCommand {
    fn execute(&self, _ctx: &crate::config::CliConfig) -> anyhow::Result<()> {
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(handle_verify_commit(self.clone()))
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use auths_verifier::AttestationBuilder;

    #[test]
    fn verify_commit_result_failure_helper() {
        let r = VerifyCommitResult::failure("abc123".into(), "bad sig".into());
        assert!(!r.valid);
        assert_eq!(r.commit, "abc123");
        assert_eq!(r.error.as_deref(), Some("bad sig"));
        assert!(r.ssh_valid.is_none());
        assert!(r.chain_valid.is_none());
        assert!(r.witness_quorum.is_none());
    }

    #[test]
    fn verify_commit_result_json_includes_new_fields() {
        let r = VerifyCommitResult {
            commit: "abc123".into(),
            valid: true,
            ssh_valid: Some(true),
            chain_valid: Some(true),
            chain_report: None,
            witness_quorum: Some(WitnessQuorum {
                required: 2,
                verified: 2,
                receipts: vec![],
            }),
            signer: Some("did:keri:test".into()),
            oidc_binding: None,
            error: None,
            warnings: vec!["expiring soon".into()],
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"ssh_valid\":true"));
        assert!(json.contains("\"chain_valid\":true"));
        assert!(json.contains("\"witness_quorum\""));
        assert!(json.contains("\"warnings\":[\"expiring soon\"]"));
    }

    #[test]
    fn verify_commit_result_json_omits_none_fields() {
        let r = VerifyCommitResult::failure("abc".into(), "err".into());
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("ssh_valid"));
        assert!(!json.contains("chain_valid"));
        assert!(!json.contains("chain_report"));
        assert!(!json.contains("witness_quorum"));
        assert!(!json.contains("warnings"));
    }

    #[test]
    fn format_result_text_valid_ssh_only() {
        let r = VerifyCommitResult {
            commit: "abc12345".into(),
            valid: true,
            ssh_valid: Some(true),
            chain_valid: None,
            chain_report: None,
            witness_quorum: None,
            signer: Some("did:keri:test".into()),
            oidc_binding: None,
            error: None,
            warnings: vec![],
        };
        let text = format_result_text(&r);
        assert!(text.contains("valid"));
        assert!(text.contains("signer: did:keri:test"));
    }

    #[test]
    fn format_result_text_valid_with_chain_and_witnesses() {
        let r = VerifyCommitResult {
            commit: "abc12345".into(),
            valid: true,
            ssh_valid: Some(true),
            chain_valid: Some(true),
            chain_report: Some(VerificationReport::valid(vec![])),
            witness_quorum: Some(WitnessQuorum {
                required: 2,
                verified: 2,
                receipts: vec![],
            }),
            signer: Some("did:keri:test".into()),
            oidc_binding: None,
            error: None,
            warnings: vec![],
        };
        let text = format_result_text(&r);
        assert!(text.contains("chain: valid"));
        assert!(text.contains("witnesses: 2/2"));
    }

    #[test]
    fn format_result_text_invalid_with_error() {
        let r = VerifyCommitResult::failure("abc12345".into(), "No signature found".into());
        let text = format_result_text(&r);
        assert!(text.contains("INVALID"));
        assert!(text.contains("No signature found"));
    }

    #[tokio::test]
    async fn verify_bundle_chain_empty_chain() {
        #[allow(clippy::disallowed_methods)]
        // INVARIANT: test-only hardcoded DID and hex string literals
        let bundle = IdentityBundle {
            identity_did: auths_verifier::IdentityDID::new_unchecked("did:keri:test"),
            public_key_hex: auths_verifier::PublicKeyHex::new_unchecked("aa".repeat(32)),
            curve: Default::default(),
            attestation_chain: vec![],
            bundle_timestamp: Utc::now(),
            max_valid_for_secs: 86400,
        };
        let (cv, cr, warnings) = verify_bundle_chain(&bundle, Utc::now()).await;
        assert!(cv.is_none());
        assert!(cr.is_none());
        assert!(!warnings.is_empty());
        assert!(warnings[0].contains("No attestation chain"));
    }

    #[tokio::test]
    async fn verify_bundle_chain_invalid_hex() {
        #[allow(clippy::disallowed_methods)] // test code
        let bundle_timestamp = Utc::now();

        #[allow(clippy::disallowed_methods)]
        // INVARIANT: test-only hardcoded DID, hex, and canonical DID string literals
        let bundle = IdentityBundle {
            identity_did: auths_verifier::IdentityDID::new_unchecked("did:keri:test"),
            public_key_hex: auths_verifier::PublicKeyHex::new_unchecked("not_hex"),
            curve: Default::default(),
            attestation_chain: vec![
                AttestationBuilder::default()
                    .rid("test")
                    .issuer("did:keri:test")
                    .subject("did:key:zTest")
                    .build(),
            ],
            bundle_timestamp,
            max_valid_for_secs: 86400,
        };
        let (cv, _cr, warnings) = verify_bundle_chain(&bundle, Utc::now()).await;
        assert_eq!(cv, Some(false));
        assert!(warnings[0].contains("Invalid public key hex"));
    }

    // -------------------------------------------------------------------------
    // extract_ssh_signature regression tests
    // -------------------------------------------------------------------------

    /// Minimal realistic git commit object containing an SSH signature.
    ///
    /// Note: written with `concat!` rather than `\` line continuation because
    /// Rust's `\` continuation eats all leading whitespace on the next source
    /// line, which would silently strip the ` ` (space) prefix that git uses
    /// for gpgsig continuation lines.
    const COMMIT_WITH_SIG: &str = concat!(
        "tree 16b8274d517c97653341495042b037c0d74ccfc3\n",
        "parent 8113dc5221881e744ef8b80597ae4da696c10e67\n",
        "author Test User <test@example.com> 1700000000 +0000\n",
        "committer Test User <test@example.com> 1700000000 +0000\n",
        "gpgsig -----BEGIN SSH SIGNATURE-----\n",
        " U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgVQuMGFzwtirJulb4hTBb39CGs2\n",
        " y7l5SUeOmXTFtZmF0AAAADZ2l0AAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5\n",
        " AAAAQJKNt8cKSbaYtOwUMSKU2dVXJMbbJBy5xEdq6TsLh+P47QI+pNDhilsn4XeDjo9B3+\n",
        " wTsG+4p0du0SnsFkUGTgU=\n",
        " -----END SSH SIGNATURE-----\n",
        "\n",
        "commit message\n",
    );

    #[test]
    fn test_extract_ssh_signature_removes_gpgsig_from_payload() {
        let (_, payload) = extract_ssh_signature(COMMIT_WITH_SIG).unwrap();
        assert!(
            !payload.contains("gpgsig"),
            "payload must not contain the gpgsig header"
        );
        assert!(
            !payload.contains("BEGIN SSH SIGNATURE"),
            "payload must not contain the signature PEM"
        );
    }

    #[test]
    fn test_extract_ssh_signature_payload_ends_with_newline() {
        // Regression: the old lines()+join("\n") approach dropped the trailing \n.
        // ssh-keygen verifies against the raw commit bytes, which end with \n.
        // A missing trailing newline causes "incorrect signature".
        let (_, payload) = extract_ssh_signature(COMMIT_WITH_SIG).unwrap();
        assert!(
            payload.ends_with('\n'),
            "payload must end with \\n to match what git signed (got: {:?})",
            &payload[payload.len().saturating_sub(10)..]
        );
    }

    #[test]
    fn test_extract_ssh_signature_payload_contains_non_sig_headers() {
        let (_, payload) = extract_ssh_signature(COMMIT_WITH_SIG).unwrap();
        assert!(payload.contains("tree "));
        assert!(payload.contains("author "));
        assert!(payload.contains("committer "));
        assert!(payload.contains("commit message\n"));
    }

    #[test]
    fn test_extract_ssh_signature_pem_stripped_of_continuation_spaces() {
        let (sig, _) = extract_ssh_signature(COMMIT_WITH_SIG).unwrap();
        // PEM lines must not start with a space (continuation prefix removed)
        for line in sig.lines() {
            assert!(
                !line.starts_with(' '),
                "signature line must not start with a space: {:?}",
                line
            );
        }
        assert!(sig.starts_with("-----BEGIN SSH SIGNATURE-----"));
        assert!(sig.contains("-----END SSH SIGNATURE-----"));
    }

    #[test]
    fn test_extract_ssh_signature_no_sig_returns_error() {
        let no_sig = "tree abc\nauthor foo <foo@bar.com> 1234 +0000\n\nmessage\n";
        assert!(extract_ssh_signature(no_sig).is_err());
    }
}
