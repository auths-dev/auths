use crate::ux::format::is_json_mode;
use anyhow::{Context, Result, anyhow};
use auths_infra_http::HttpOobiResolver;
use auths_keri::Event;
use auths_keri::witness::{SignedReceipt, WitnessReceiptLookup};
use auths_sdk::core_config::EnvironmentConfig;
use auths_sdk::ports::RegistryBackend;
use auths_sdk::storage::{GitRegistryBackend, GitWitnessReceiptLookup, RegistryConfig};
use auths_verifier::witness::{WitnessQuorum, WitnessVerifyConfig};
use auths_verifier::{
    Attestation, CommitVerdict, IdentityBundle, VerificationReport, VerifierWitnessPolicy,
    WitnessGateStatus, verify_chain_with_witnesses, verify_commit_against_kel_witnessed,
};
use clap::Parser;
use serde::Serialize;
use std::fs;
use std::path::PathBuf;

use crate::subprocess::git_command;

use super::verify_helpers::parse_witness_keys;

#[derive(Parser, Debug, Clone)]
#[command(about = "Verify Git commit signatures against Auths identity.")]
pub struct VerifyCommitCommand {
    /// Commit SHA, range (e.g., HEAD~5..HEAD), or "HEAD" (default).
    #[arg(default_value = "HEAD")]
    pub commit: String,

    /// Path to witness signatures JSON file.
    #[arg(long = "witness-signatures")]
    pub witness_receipts: Option<PathBuf>,

    /// Number of witnesses required (default: 1).
    #[arg(long = "witnesses-required", default_value = "1")]
    pub witness_threshold: usize,

    /// Witness public keys as DID:hex pairs (e.g., "did:key:z6Mk...:abcd1234...").
    #[arg(long, num_args = 1..)]
    pub witness_keys: Vec<String>,

    /// Fetch a signer's KEL from this git remote when it is absent locally
    /// (opt-in). The local registry stays the trusted floor — a remote can only
    /// advance the key-state, never roll it back. Without this flag, resolution
    /// is local-only (no network).
    #[arg(long)]
    pub remote: Option<String>,

    /// Fetch signer KELs over HTTP from this OOBI base URL (e.g.
    /// `https://registry.example`). SSRF-hardened: HTTPS-only, no redirect
    /// following, private/loopback hosts blocked. Takes precedence over
    /// `--remote`; the resolved KEL is still prefix-bound + replayed locally.
    #[arg(long)]
    pub oobi: Option<String>,

    /// Fail verification when the signer's root KEL has not reached witness
    /// quorum (fail-closed). Default: warn and continue (trust-on-first-sight).
    #[arg(long = "require-witnesses")]
    pub require_witnesses: bool,

    /// Path to an identity bundle JSON whose root `did:keri:` is pinned as a trusted
    /// root for this verification (CI/stateless commit verification). The bundle is
    /// freshness-checked; an unreadable or stale bundle fails closed.
    #[arg(long, value_parser)]
    pub identity_bundle: Option<PathBuf>,
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
    /// Receipt-gated witness quorum status for the signer's root KEL (D.7/D.9):
    /// `"met"`, or `"N of M (under quorum)"`. Absent when no witnesses are designated.
    #[serde(skip_serializing_if = "Option::is_none")]
    witness_gate: Option<String>,
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
            witness_gate: None,
            signer: None,
            oidc_binding: None,
            error: Some(error),
            warnings: Vec::new(),
        }
    }
}

/// Handle verify-commit command.
/// Exit codes: 0=valid, 1=invalid/unsigned, 2=error
#[allow(clippy::disallowed_methods)]
pub async fn handle_verify_commit(
    cmd: VerifyCommitCommand,
    env_config: &EnvironmentConfig,
) -> Result<()> {
    // KEL-native verification: the trust root is the replayed KEL + the `.auths/roots`
    // pin, not an allowlist. No `ssh-keygen` subprocess, no `allowed_signers`.
    let auths_home = match auths_sdk::paths::auths_home() {
        Ok(h) => h,
        Err(e) => return handle_error(&cmd, 2, &format!("Could not locate ~/.auths: {e}")),
    };
    // Read-only SDK context over the same global registry, for org-policy evaluation
    // (E1.1). No passphrase — loading a policy never decrypts keys.
    let sdk_ctx =
        match crate::factories::storage::build_auths_context(&auths_home, env_config, None) {
            Ok(c) => c,
            Err(e) => {
                return handle_error(
                    &cmd,
                    2,
                    &format!("Could not build context for org-policy evaluation: {e}"),
                );
            }
        };
    // The registry backend holds every identity's KEL events (in the `refs/auths/registry`
    // tree) — the source we replay to decide trust.
    let registry =
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(&auths_home));
    // Trust roots = the committed `.auths/roots` pin plus the verifier's own
    // identity (self-trust — you can always verify what you signed). A
    // `--identity-bundle` does NOT contribute a root: it supplies KEL *evidence*
    // for a root that must already be pinned here (RT-005). An unusable or
    // un-pinned bundle fails closed — trust is never left unconstrained.
    let mut pinned_roots = super::verify_helpers::load_project_pinned_roots();
    if let Some(own_root) = auths_sdk::workflows::commit_trust::local_self_root(&sdk_ctx)
        && !pinned_roots.contains(&own_root)
    {
        pinned_roots.push(own_root);
    }
    let mut bundle_kel: Option<BundleKel> = None;
    if let Some(bundle_path) = &cmd.identity_bundle {
        match load_bundle_trust(bundle_path, chrono::Utc::now()) {
            Ok((root, kel)) => {
                // Evidence-only (RT-005): the bundle is *evidence for* a root that
                // must be pinned independently (`.auths/roots` or self-trust). It
                // never becomes its own trust anchor — otherwise the anchor and the
                // evidence both come from the same attacker-supplied file. (The
                // self-certified root is additionally re-derived by replay and
                // checked against the pins, so a coherent-but-unpinned bundle is
                // still rejected.)
                if !pinned_roots.contains(&root) {
                    return handle_error(
                        &cmd,
                        2,
                        &format!(
                            "identity bundle root {root} is not independently trusted: \
                             add it to .auths/roots (or verify from the identity that \
                             controls it). A bundle is evidence for a pinned root, never \
                             the source of the pin."
                        ),
                    );
                }
                if !kel.is_empty() {
                    bundle_kel = Some(BundleKel {
                        did: root,
                        events: kel,
                    });
                }
            }
            Err(e) => return handle_error(&cmd, 2, &e),
        }
    }
    let provider = auths_crypto::RingCryptoProvider;
    // Stored witness receipts live in the identity repo; the gate reads them
    // through this lookup (D.7). Empty store → under-quorum for witnessed roots.
    let receipt_lookup = GitWitnessReceiptLookup::new(&auths_home);

    let commits = match resolve_commits(&cmd.commit) {
        Ok(c) => c,
        Err(e) => return handle_error(&cmd, 2, &e.to_string()),
    };
    let mut results = Vec::with_capacity(commits.len());
    for commit_ref in &commits {
        results.push(
            verify_one_commit(
                &registry,
                &pinned_roots,
                &provider,
                &receipt_lookup,
                &sdk_ctx,
                &cmd,
                bundle_kel.as_ref(),
                commit_ref,
            )
            .await,
        );
    }
    output_results(&results)
}

/// Load an identity bundle from `path` and return the trusted root `did:keri:` it pins
/// (freshness-checked via the SDK trust resolver) plus the KEL events it carries for
/// stateless resolution. Fails closed: any read, parse, or staleness error is returned
/// so the caller can abort rather than verify unconstrained.
/// A bundle's authenticated KEL: the identity DID it self-certifies to plus the
/// KEL events it carries. Built once by the `--identity-bundle` path and threaded
/// into [`resolve_signer_kel`] so a stateless run (no identity store) can satisfy a
/// signer lookup from the bundle. Replaces an anonymous `(String, Vec<Event>)`.
struct BundleKel {
    /// The bundle's identity DID (`did:keri:…`).
    did: String,
    /// The bundle's KEL events, oldest first — already signature-authenticated by
    /// [`load_bundle_trust`] (RT-002).
    events: Vec<Event>,
}

fn load_bundle_trust(
    path: &std::path::Path,
    now: chrono::DateTime<chrono::Utc>,
) -> std::result::Result<(String, Vec<Event>), String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("could not read identity bundle {path:?}: {e}"))?;
    let bundle: IdentityBundle = serde_json::from_str(&content)
        .map_err(|e| format!("identity bundle {path:?} is not valid JSON: {e}"))?;
    let root = auths_sdk::workflows::commit_trust::trusted_root_from_bundle(&bundle, now)
        .map_err(|e| e.to_string())?;
    // `bundle.kel` is already `Vec<Event>` — parsed at the deserialize boundary,
    // so a structurally-broken event fails the bundle parse above rather than
    // slipping through as loose JSON.
    let kel = bundle.kel;

    // Authenticate the bundle's KEL (RT-002): a bundle is attacker-controlled
    // input, so we do NOT merely replay it structurally — we verify every event
    // is signed by the controlling key-state via `validate_signed_kel`. The
    // producer ships each event's CESR signature attachment (hex); a bundle
    // missing them (length mismatch), or whose signatures don't verify, fails
    // closed HERE, before its KEL is ever used to resolve a signer.
    if !kel.is_empty() {
        if bundle.kel_attachments.len() != kel.len() {
            return Err(format!(
                "identity bundle {path:?} carries {} KEL events but {} signature \
                 attachments — cannot authenticate it; re-export with a current \
                 `auths id export-bundle`",
                kel.len(),
                bundle.kel_attachments.len()
            ));
        }
        let signed: Vec<auths_keri::SignedEvent> = kel
            .iter()
            .zip(bundle.kel_attachments.iter())
            .map(|(event, att_hex)| {
                let att = hex::decode(att_hex).map_err(|e| {
                    format!("identity bundle {path:?} has a non-hex KEL signature: {e}")
                })?;
                let sigs = auths_keri::parse_attachment(&att).map_err(|e| {
                    format!("identity bundle {path:?} has an unparseable KEL signature: {e}")
                })?;
                Ok(auths_keri::SignedEvent::new(event.clone(), sigs))
            })
            .collect::<std::result::Result<_, String>>()?;
        auths_keri::validate_signed_kel(&signed, None).map_err(|e| {
            format!("identity bundle {path:?} KEL failed signature authentication (RT-002): {e}")
        })?;
    }

    Ok((root, kel))
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

/// Resolve a signer's KEL for verification, honoring the transport flags.
///
/// `--oobi` (SSRF-hardened HTTP) takes precedence; otherwise `--remote` (git) or
/// local-first via the SDK chain. The prefix-binding guard is applied to the HTTP
/// result here (the SDK chain applies it for local/git internally), so every
/// transport returns a KEL whose inception SAID matches the requested DID.
///
/// Args:
/// * `registry`: The local registry backend (the trusted floor).
/// * `cmd`: The verify command (carries `--remote` / `--oobi`).
/// * `did`: The `did:keri:` to resolve.
async fn resolve_signer_kel(
    registry: &dyn RegistryBackend,
    cmd: &VerifyCommitCommand,
    bundle_kel: Option<&BundleKel>,
    did: &str,
) -> Result<Vec<Event>, String> {
    // Stateless first: a bundle that carries the signer's KEL satisfies
    // resolution without any identity store (CI runners). Prefix binding is
    // still enforced, so a tampered bundle cannot smuggle a foreign KEL.
    if let Some(bundle) = bundle_kel
        && bundle.did == did
    {
        let prefix = auths_sdk::keri::parse_did_keri(did).map_err(|e| e.to_string())?;
        auths_sdk::keri::verify_prefix_binding(&prefix, &bundle.events)
            .map_err(|e| e.to_string())?;
        return Ok(bundle.events.clone());
    }
    if let Some(oobi_base) = &cmd.oobi {
        let prefix = auths_sdk::keri::parse_did_keri(did).map_err(|e| e.to_string())?;
        let resolver = HttpOobiResolver::new(oobi_base.clone()).map_err(|e| e.to_string())?;
        let events = resolver
            .fetch_kel(&prefix)
            .await
            .map_err(|e| e.to_string())?;
        auths_sdk::keri::verify_prefix_binding(&prefix, &events).map_err(|e| e.to_string())?;
        Ok(events)
    } else {
        let chain = match &cmd.remote {
            Some(url) => auths_sdk::keri::KelResolverChain::with_remote(registry, url.clone()),
            None => auths_sdk::keri::KelResolverChain::local(registry),
        };
        chain.resolve_kel(did).map_err(|e| e.to_string())
    }
}

/// Verify a single commit against the replayed KEL.
///
/// Reads the in-band `Auths-Id` / `Auths-Device` trailers, replays the device + root
/// KELs from the local identity repository, and checks the SSH signature in-process
/// (no `ssh-keygen`, no `allowed_signers`). The KEL verdict is authoritative; witness
/// receipts (Epic D) remain an orthogonal opt-in check layered on top.
#[allow(clippy::too_many_arguments)]
async fn verify_one_commit(
    registry: &dyn RegistryBackend,
    pinned_roots: &[String],
    provider: &dyn auths_crypto::CryptoProvider,
    receipt_lookup: &dyn WitnessReceiptLookup,
    sdk_ctx: &auths_sdk::context::AuthsContext,
    cmd: &VerifyCommitCommand,
    bundle_kel: Option<&BundleKel>,
    commit_ref: &str,
) -> VerifyCommitResult {
    let sha = match resolve_commit_sha(commit_ref) {
        Ok(sha) => sha,
        Err(e) => {
            return VerifyCommitResult::failure(
                commit_ref.to_string(),
                format!("Failed to resolve commit: {e}"),
            );
        }
    };

    let raw_commit = match raw_commit_object(&sha) {
        Ok(c) => c,
        Err(e) => return VerifyCommitResult::failure(sha, e.to_string()),
    };

    let (root_did, device_did) =
        match auths_sdk::workflows::commit_trust::commit_signer_trailers(&raw_commit) {
            Some(pair) => pair,
            None => {
                return VerifyCommitResult::failure(
                    sha,
                    "Commit carries no Auths-Id/Auths-Device trailer. The prepare-commit-msg \
                     hook installed by `auths init` adds these on every commit — if this repo \
                     sets its own core.hooksPath (e.g. husky), the hook is bypassed; run \
                     `auths doctor` to check. Backfill existing commits with `auths sign <ref>` \
                     (rewrites the commit)."
                        .to_string(),
                );
            }
        };

    // KEL sourcing is an SDK/adapter concern: local-first, with an opt-in git
    // remote (`--remote`) or an SSRF-hardened HTTP OOBI host (`--oobi`). The
    // prefix-binding guard is applied regardless of transport. The command stays
    // presentation-thin.
    let device_kel = match resolve_signer_kel(registry, cmd, bundle_kel, &device_did).await {
        Ok(events) => events,
        Err(e) => {
            return VerifyCommitResult::failure(
                sha,
                format!("Device KEL for {device_did} could not be resolved: {e}"),
            );
        }
    };
    let root_kel = match resolve_signer_kel(registry, cmd, bundle_kel, &root_did).await {
        Ok(events) => events,
        Err(e) => {
            return VerifyCommitResult::failure(
                sha,
                format!("Root KEL for {root_did} could not be resolved: {e}"),
            );
        }
    };

    let policy = if cmd.require_witnesses {
        VerifierWitnessPolicy::RequireWitnesses
    } else {
        VerifierWitnessPolicy::Warn
    };
    let witnessed = verify_commit_against_kel_witnessed(
        raw_commit.as_bytes(),
        &device_kel,
        &root_kel,
        pinned_roots,
        provider,
        receipt_lookup,
        policy,
    )
    .await;
    let mut result = verdict_to_result(sha.clone(), witnessed.verdict);
    match witnessed.witness {
        WitnessGateStatus::NotRequired => {}
        WitnessGateStatus::Met => result.witness_gate = Some("met".to_string()),
        WitnessGateStatus::UnderQuorum {
            collected,
            required,
        } => {
            result.witness_gate = Some(format!("{collected} of {required} (under quorum)"));
            result.warnings.push(format!(
                "Witness quorum not met for the signer's root KEL: {collected} of {required} \
                 receipts (verifying anyway; pass --require-witnesses to fail closed)."
            ));
        }
    }

    if let Ok(Some(quorum)) = verify_witnesses(cmd, None).await {
        if quorum.verified < quorum.required {
            result.valid = false;
            if result.error.is_none() {
                result.error = Some(format!(
                    "Witness quorum not met: {}/{}",
                    quorum.verified, quorum.required
                ));
            }
        }
        result.witness_quorum = Some(quorum);
    }

    result.oidc_binding =
        try_load_attestation_from_ref(&sha).and_then(|att| extract_oidc_binding_display(&att));

    // E1.1 — org policy is enforced AFTER the cryptographic verdict (fail-closed
    // ordering). It can only turn a valid result into a denial, never the reverse. A
    // root that anchored no policy leaves the result unchanged (legacy allow).
    if result.valid {
        let now = chrono::Utc::now();
        match auths_sdk::workflows::commit_trust::evaluate_commit_policy(
            sdk_ctx,
            &root_did,
            &device_did,
            now,
        ) {
            Ok(auths_sdk::workflows::commit_trust::PolicyOutcome::Evaluated(decision))
                if !decision.is_allowed() =>
            {
                result.valid = false;
                result.chain_valid = Some(false);
                result.error = Some(format!(
                    "Org policy denied this commit: {} [{}]",
                    decision.message, decision.reason
                ));
            }
            Ok(_) => {}
            Err(e) => {
                // Fail closed: if policy cannot be evaluated, do not certify the commit.
                result.valid = false;
                result.error = Some(format!("Org policy could not be evaluated: {e}"));
            }
        }
    }

    result
}

/// The raw git commit object (headers + message + `gpgsig`), exactly as produced by
/// `git cat-file commit <sha>` — the bytes the SSH signature is computed over.
fn raw_commit_object(sha: &str) -> Result<String> {
    let output = git_command(&["cat-file", "commit", sha])
        .output()
        .context("Failed to run git cat-file")?;
    if !output.status.success() {
        return Err(anyhow!(
            "git cat-file commit {sha} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    String::from_utf8(output.stdout).context("Commit object is not valid UTF-8")
}

/// Map a [`CommitVerdict`] onto a CLI result row: the valid flag, the verified signer,
/// and a human-readable reason for every failure mode.
fn verdict_to_result(commit: String, verdict: CommitVerdict) -> VerifyCommitResult {
    let mut result = VerifyCommitResult::failure(commit, String::new());
    match verdict {
        CommitVerdict::Valid {
            signer_did,
            root_did,
            duplicitous_root,
        } => {
            result.valid = true;
            result.ssh_valid = Some(true);
            result.signer = Some(signer_did);
            result.error = None;
            if duplicitous_root {
                result.warnings.push(format!(
                    "Root {root_did} shows KEL duplicity (a fork) — trusting the first event \
                     seen. Resolve with `auths device remove`."
                ));
            }
        }
        CommitVerdict::Unsigned => {
            result.error = Some("No signature found".to_string());
        }
        CommitVerdict::GpgUnsupported => {
            result.error = Some("GPG signatures not supported, use SSH signing".to_string());
        }
        CommitVerdict::SshSignatureInvalid => {
            result.ssh_valid = Some(false);
            result.error = Some(
                "SSH signature is invalid (commit tampered, wrong namespace, or bad signature)"
                    .to_string(),
            );
        }
        CommitVerdict::DeviceKelInvalid(why) => {
            result.error = Some(format!("Device KEL failed to replay: {why}"));
        }
        CommitVerdict::RootKelInvalid(why) => {
            result.error = Some(format!("Root KEL failed to replay: {why}"));
        }
        CommitVerdict::RootNotPinned(root) => {
            result.error = Some(format!(
                "Root {root} is not a pinned trusted root. Pin it in .auths/roots to trust \
                 commits delegated under it."
            ));
        }
        CommitVerdict::RootAbandoned => {
            result.error =
                Some("Root identity is abandoned (its KEL was rotated to a null key)".to_string());
        }
        CommitVerdict::NotDelegatedByClaimedRoot {
            device_did,
            root_did,
        } => {
            result.error = Some(format!(
                "Device {device_did} is not delegated by the claimed root {root_did}"
            ));
        }
        CommitVerdict::DelegationSealNotFound => {
            result.error = Some(
                "Root never anchored this device's delegated inception (no delegation seal)"
                    .to_string(),
            );
        }
        CommitVerdict::DeviceRevoked => {
            result.error = Some("Device delegation has been revoked by the root".to_string());
        }
        CommitVerdict::SignedAfterRevocation {
            signed_at,
            revoked_at,
            ..
        } => {
            result.error = Some(format!(
                "Commit was signed at/after the delegator revoked it (signed at KEL position {signed_at}, revoked at {revoked_at})"
            ));
        }
        CommitVerdict::OutsideAgentScope { capability, .. } => {
            result.error = Some(format!(
                "Agent signed exercising capability '{capability}', outside its delegator-anchored scope"
            ));
        }
        CommitVerdict::AgentExpired {
            expired_at,
            signed_at,
            ..
        } => {
            result.error = Some(format!(
                "Agent delegation expired (expired at {expired_at}, signed at {signed_at})"
            ));
        }
        CommitVerdict::SignerKeyMismatch => {
            result.ssh_valid = Some(false);
            result.error = Some("Signing key is not the device's current key".to_string());
        }
        CommitVerdict::SignedBySupersededKey => {
            result.ssh_valid = Some(false);
            result.error = Some(
                "Commit was signed by a superseded device key (the device has since rotated)"
                    .to_string(),
            );
        }
        CommitVerdict::WitnessQuorumNotMet {
            root_did,
            collected,
            required,
        } => {
            result.error = Some(format!(
                "Witness quorum not met for root {root_did}: {collected} of {required} required \
                 receipts. Drop --require-witnesses to verify with a warning instead."
            ));
        }
    }
    result
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

    if let Some(ref gate) = result.witness_gate {
        parts.push(format!("witness-gate: {gate}"));
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

    if let Some(ref gate) = r.witness_gate {
        parts.push(format!("witness-gate: {gate}"));
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

fn resolve_commit_sha(commit_ref: &str) -> Result<String> {
    super::git_helpers::resolve_commit_sha(commit_ref)
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
    fn execute(&self, ctx: &crate::config::CliConfig) -> anyhow::Result<()> {
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(handle_verify_commit(self.clone(), &ctx.env_config))
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

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
            witness_gate: Some("met".into()),
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
            witness_gate: None,
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
            witness_gate: Some("met".into()),
            signer: Some("did:keri:test".into()),
            oidc_binding: None,
            error: None,
            warnings: vec![],
        };
        let text = format_result_text(&r);
        assert!(text.contains("chain: valid"));
        assert!(text.contains("witnesses: 2/2"));
        assert!(text.contains("witness-gate: met"));
    }

    #[test]
    fn verify_output_shows_quorum() {
        let mut r = VerifyCommitResult::failure("abc".into(), String::new());
        r.valid = true;
        r.error = None;
        r.witness_gate = Some("2 of 3 (under quorum)".into());

        let text = format_result_text(&r);
        assert!(text.contains("witness-gate: 2 of 3 (under quorum)"));
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"witness_gate\":\"2 of 3 (under quorum)\""));
    }

    #[test]
    fn verify_output_flags_fork() {
        // A Valid verdict on a duplicitous root must surface a non-fatal fork warning.
        let result = verdict_to_result(
            "sha".into(),
            CommitVerdict::Valid {
                signer_did: "did:keri:dev".into(),
                root_did: "did:keri:root".into(),
                duplicitous_root: true,
            },
        );
        assert!(result.valid);
        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.contains("fork") || w.contains("duplicity")),
            "expected a fork/duplicity warning, got {:?}",
            result.warnings
        );
    }

    #[test]
    fn format_result_text_invalid_with_error() {
        let r = VerifyCommitResult::failure("abc12345".into(), "No signature found".into());
        let text = format_result_text(&r);
        assert!(text.contains("INVALID"));
        assert!(text.contains("No signature found"));
    }
}
