//! Chain resolution: registry → verified chain, async and cached.
//!
//! Two hard rules (§RC-E1.3):
//! * **No synchronous subprocess or clone — ever.** All I/O is async; remote git
//!   operations run through `tokio::process`.
//! * **A DATA cache keyed by the registry head — never a verdict cache.** Fetched
//!   registry bytes are content-addressed by the remote's `refs/auths/registry`
//!   head; every byte is re-verified downstream, so a poisoned cache can only
//!   cause a false failure, never a false `authorized`. Revocation and expiry are
//!   evaluated fresh every call, off the cache.

use std::path::{Path, PathBuf};

use auths_mcp_core::PerCallGate;
use auths_sdk::storage::{GitRegistryBackend, RegistryConfig};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use crate::anchor::{
    check_trail, composite_head, first_seen_anchor, kel_digest, spend_binding_head, treasury_anchor,
};
use crate::error::EvidenceError;
use crate::types::{AnchorRef, AuditV1, BundleGrant, LogVerdict, RevocationFact};
use crate::verify_spend::{VerifiedSpend, VerifyOpts, verify_spend};

/// Where the registry comes from: a local path (no cache) or a remote git URL
/// (fetched through the head-keyed byte cache).
#[derive(Debug, Clone)]
pub enum RegistrySource {
    /// A local registry directory — used directly.
    Local(PathBuf),
    /// A remote registry URL, fetched into `cache_dir` keyed by the remote head.
    Remote {
        /// The git URL a verifier fetches the registry from.
        url: String,
        /// The cache root the fetched bytes land under.
        cache_dir: PathBuf,
    },
}

/// The treasury anchor inputs, when the deployment has a checkpoint trail.
#[derive(Debug, Clone)]
pub struct TreasuryInput {
    /// The `checkpoints.jsonl` trail path.
    pub checkpoints: PathBuf,
    /// The pinned coordinator key (compressed P-256, hex).
    pub pubkey_hex: String,
}

/// Everything `resolve_chain` needs. Grant facts (cap/ttl/policy) are the session
/// remit — supplied by the caller because they are configured at wrap time, not
/// stored in the KEL; scope IS re-derived (each call's proof carries its exercised
/// capability, judged by the verifier against the anchored seal).
#[derive(Debug, Clone)]
pub struct ChainInput {
    /// The agent's delegated `did:keri:…`.
    pub agent: String,
    /// The delegator/root `did:keri:…`.
    pub root: String,
    /// Where the registry comes from.
    pub registry: RegistrySource,
    /// The spend log path; defaults to the registry's own rotated log for `agent`.
    pub log: Option<PathBuf>,
    /// The grant facts the verdicts judge against.
    pub grant: BundleGrant,
    /// The treasury anchor trail, when available.
    pub treasury: Option<TreasuryInput>,
    /// A caller-supplied TEL/attestation revocation fact (§2.2(c)) — a revocation
    /// recorded OUTSIDE the KEL that the registry copy alone cannot surface.
    pub tel_revocation: Option<RevocationFact>,
}

/// The fully-resolved chain: records, per-record re-derived facts, both KELs, the
/// anchor, and the audit report. Pure data — the judge and the bundle builder
/// consume it without further I/O.
#[derive(Debug)]
pub struct ResolvedChain {
    /// The principal's root DID.
    pub root: String,
    /// The delegated agent DID.
    pub agent: String,
    /// The grant facts.
    pub grant: BundleGrant,
    /// The spend-log records, in order.
    pub records: Vec<auths_mcp_core::SpendLogRecord>,
    /// Per-record re-derived facts (see [`auths_mcp_core::RecordFact`]).
    pub facts: Vec<auths_mcp_core::RecordFact>,
    /// The agent's KEL, serialized for embedding.
    pub agent_kel: Vec<serde_json::Value>,
    /// The delegator's KEL, serialized for embedding.
    pub delegator_kel: Vec<serde_json::Value>,
    /// The head commitment the verdicts are "as of".
    pub anchor: AnchorRef,
    /// The revocation surface as resolved fresh at this call.
    pub revocation: Option<RevocationFact>,
    /// The whole-log verdict, surfaced from the audit.
    pub log_verdict: LogVerdict,
    /// The spend-log binding head (`bindingₙ`).
    pub log_head: String,
    /// The versioned audit report.
    pub audit: AuditV1,
}

/// Resolve a chain: fetch (or reuse) the registry bytes, re-derive the spend with
/// the one audit walk, resolve the revocation surface FRESH, and anchor the head
/// on the strongest tier available.
///
/// The judged facts are re-derived AS OF the anchor instant (verdicts are
/// "as of H"), which keeps build-time and offline re-verification byte-identical;
/// the caller stamps a separate online-freshness re-check when it needs one (D4).
///
/// Args:
/// * `input`: the chain inputs.
/// * `now`: the caller's injected clock (the anchor instant for first-seen tiers).
///
/// Usage:
/// ```ignore
/// let chain = resolve_chain(input, Utc::now()).await?;
/// let verdict = judge_call(&chain.view(), index);
/// ```
pub async fn resolve_chain(
    input: ChainInput,
    now: DateTime<Utc>,
) -> Result<ResolvedChain, EvidenceError> {
    let registry_dir = match &input.registry {
        RegistrySource::Local(path) => path.clone(),
        RegistrySource::Remote { url, cache_dir } => fetch_registry(url, cache_dir).await?,
    };
    let log = input
        .log
        .clone()
        .unwrap_or_else(|| auths_mcp_core::resolve_spend_log(&registry_dir, &input.agent));

    // The anchor instant: the treasury trail's final checkpoint when present,
    // else `now` (first-seen). Facts are re-derived as of this instant.
    let (anchor_ts, trail) = match &input.treasury {
        Some(t) => {
            let raw = tokio::fs::read_to_string(&t.checkpoints)
                .await
                .map_err(|e| {
                    EvidenceError::Treasury(format!("{}: {e}", t.checkpoints.display()))
                })?;
            let lines: Vec<String> = raw.lines().map(str::to_string).collect();
            let last = check_trail(&lines, Some(&t.pubkey_hex))?;
            (last.at, Some((lines, last, t.pubkey_hex.clone())))
        }
        None => (now, None),
    };

    let spend = verify_spend(
        VerifyOpts::new(&log, &registry_dir, &input.agent, &input.root),
        anchor_ts,
    )
    .await?;
    let VerifiedSpend {
        report,
        facts,
        records,
    } = spend;

    // KELs, resolved once through the same resolver the gate uses, serialized for
    // embedding so the bundle is self-contained.
    let registry =
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(&registry_dir));
    let gate = PerCallGate::resolve(&registry, &input.agent, &input.root)
        .map_err(|e| EvidenceError::Registry(e.to_string()))?;
    let agent_kel = crate::kel_wire::kel_to_wire(gate.agent_kel())?;
    let delegator_kel = crate::kel_wire::kel_to_wire(gate.delegator_kel())?;

    // Revocation surface, resolved FRESH (never cached): an in-KEL revocation
    // surfaces through the walk's own verdict; a TEL/attestation revocation that
    // moves no KEL tip arrives from the caller's registry probe.
    let revocation = input.tel_revocation.clone().or_else(|| {
        if let auths_mcp_core::AuditVerdict::Revoked { at } = &report.verdict {
            Some(RevocationFact {
                source: "kel".to_string(),
                seq: Some(*at as u64),
                ts: None,
            })
        } else {
            None
        }
    });

    let log_head = spend_binding_head(&records);
    let head = composite_head(
        &log_head,
        &kel_digest(&agent_kel)?,
        &kel_digest(&delegator_kel)?,
        &revocation,
    )?;
    let kel_seq = agent_kel.len() as u64;
    let anchor = match trail {
        Some((lines, last, pubkey_hex)) => {
            treasury_anchor(head, kel_seq, lines, pubkey_hex, &last)?
        }
        None => first_seen_anchor(head, kel_seq, anchor_ts),
    };

    let log_verdict = if report.consistent {
        LogVerdict::Consistent
    } else {
        LogVerdict::Inconsistent
    };

    Ok(ResolvedChain {
        root: input.root,
        agent: input.agent,
        grant: input.grant,
        records,
        facts,
        agent_kel,
        delegator_kel,
        anchor,
        revocation,
        log_verdict,
        log_head,
        audit: report,
    })
}

/// Fetch a remote registry through the head-keyed byte cache: one cheap
/// `git ls-remote` per call; a full fetch only when the head moved. Returns the
/// local registry directory.
async fn fetch_registry(url: &str, cache_dir: &Path) -> Result<PathBuf, EvidenceError> {
    let head = remote_head(url).await?;
    let url_key = {
        let digest = Sha256::digest(url.as_bytes());
        let mut hex = String::with_capacity(16);
        for byte in digest.iter().take(8) {
            use std::fmt::Write as _;
            let _ = write!(hex, "{byte:02x}");
        }
        hex
    };
    let slot = cache_dir.join(url_key).join(&head);
    let repo = slot.join("registry");
    if repo.join(".git").is_dir() {
        return Ok(repo);
    }
    tokio::fs::create_dir_all(&slot)
        .await
        .map_err(|e| EvidenceError::Fetch(format!("cache dir: {e}")))?;
    run_git(&slot, &["init", "--quiet", "registry"]).await?;
    run_git(
        &repo,
        &[
            "fetch",
            "--quiet",
            url,
            "refs/auths/*:refs/auths/*",
            "refs/heads/*:refs/heads/*",
        ],
    )
    .await?;
    // Materialize the working files (spend log, budget ledger) from the first head.
    let heads = run_git(
        &repo,
        &["for-each-ref", "--format=%(refname)", "refs/heads"],
    )
    .await?;
    if let Some(first) = heads.lines().next() {
        run_git(&repo, &["checkout", "--quiet", first.trim()]).await?;
    }
    Ok(repo)
}

/// The remote's registry head (`refs/auths/registry`, falling back to the first
/// advertised ref) — the cache key.
async fn remote_head(url: &str) -> Result<String, EvidenceError> {
    let out = tokio::process::Command::new("git")
        .args(["ls-remote", url])
        .output()
        .await
        .map_err(|e| EvidenceError::Fetch(format!("git ls-remote spawn: {e}")))?;
    if !out.status.success() {
        return Err(EvidenceError::Fetch(format!(
            "git ls-remote {url}: {}",
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    let listing = String::from_utf8_lossy(&out.stdout);
    let mut first = None;
    for line in listing.lines() {
        let mut parts = line.split_whitespace();
        let (Some(sha), Some(name)) = (parts.next(), parts.next()) else {
            continue;
        };
        if name == "refs/auths/registry" {
            return Ok(sha.to_string());
        }
        first.get_or_insert_with(|| sha.to_string());
    }
    first.ok_or_else(|| EvidenceError::Fetch(format!("{url} advertises no refs")))
}

async fn run_git(dir: &Path, args: &[&str]) -> Result<String, EvidenceError> {
    let out = tokio::process::Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .await
        .map_err(|e| EvidenceError::Fetch(format!("git spawn: {e}")))?;
    if !out.status.success() {
        return Err(EvidenceError::Fetch(format!(
            "git {}: {}",
            args.first().unwrap_or(&""),
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}
