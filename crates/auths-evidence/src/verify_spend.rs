//! The single spend re-derivation, lifted from the gateway CLI so the CLI, the
//! tool servers, and every language binding share one implementation and cannot
//! diverge. Output is the versioned, typed [`AuditV1`] report — never scraped text.

use std::path::Path;

use auths_mcp_core::{
    AnnotatedAudit, AuditResume, AuditVerdict, CounterRef, PerCallGate, RecordFact, SpendLogRecord,
    call_commit_binding, read_spend_log,
};
use auths_sdk::storage::{GitRegistryBackend, RegistryConfig};
use chrono::{DateTime, Utc};

use crate::anchor::{check_trail, treasury_check_of};
use crate::error::EvidenceError;
use crate::types::{AUDIT_VERSION, AuditCheckpoint, AuditV1};

/// Options for one spend re-derivation — the same knobs the gateway's
/// `verify-spend` CLI exposes, as a typed API.
#[derive(Debug)]
pub struct VerifyOpts<'a> {
    /// The spend log: a JSONL file or a rotated directory of period files.
    pub log: &'a Path,
    /// The issuer's registry the agent + delegator KELs resolve from.
    pub registry: &'a Path,
    /// The agent's delegated `did:keri:…`.
    pub agent: &'a str,
    /// The delegator/root `did:keri:…` (the pinned trust root).
    pub root: &'a str,
    /// A treasury checkpoint trail to cross-check, when the deployment has one.
    pub treasury_checkpoints: Option<&'a Path>,
    /// The pinned coordinator checkpoint key (compressed P-256, hex).
    pub treasury_pubkey: Option<&'a str>,
    /// Assert the final checkpointed cumulative equals this many cents.
    pub expect_cumulative: Option<u64>,
    /// Resume after an already-verified prefix.
    pub resume: Option<AuditResume>,
    /// The rail facilitator's attestation key, when captured.
    pub facilitator_pubkey: Option<&'a [u8]>,
}

impl<'a> VerifyOpts<'a> {
    /// The minimal re-derivation: log + registry + the two DIDs, no anchor trail,
    /// no resume.
    ///
    /// Args:
    /// * `log`: the spend log path.
    /// * `registry`: the issuer's registry path.
    /// * `agent` / `root`: the delegation to audit.
    ///
    /// Usage:
    /// ```ignore
    /// let report = verify_spend(VerifyOpts::new(&log, &registry, agent, root), now).await?;
    /// ```
    pub fn new(log: &'a Path, registry: &'a Path, agent: &'a str, root: &'a str) -> Self {
        VerifyOpts {
            log,
            registry,
            agent,
            root,
            treasury_checkpoints: None,
            treasury_pubkey: None,
            expect_cumulative: None,
            resume: None,
            facilitator_pubkey: None,
        }
    }
}

/// One spend re-derivation and its per-record facts — everything downstream
/// consumers (the judge, the bundle builder) need without re-walking the log.
#[derive(Debug)]
pub struct VerifiedSpend {
    /// The versioned report.
    pub report: AuditV1,
    /// Per-record re-derived facts (empty past the point a failing walk stopped).
    pub facts: Vec<RecordFact>,
    /// The records the walk covered (the suffix, under a resume).
    pub records: Vec<SpendLogRecord>,
}

/// Re-derive an agent's spend from its signed log — the gate's own check, run by
/// anyone, offline. This is the ONE implementation behind `verify-spend`,
/// `receipt_build`, and every binding.
///
/// Args:
/// * `opts`: the re-derivation inputs.
/// * `now`: the auditor's injected clock.
///
/// Usage:
/// ```ignore
/// let spend = verify_spend(VerifyOpts::new(&log, &registry, agent, root), Utc::now()).await?;
/// assert!(spend.report.consistent);
/// ```
pub async fn verify_spend(
    opts: VerifyOpts<'_>,
    now: DateTime<Utc>,
) -> Result<VerifiedSpend, EvidenceError> {
    let records = read_spend_log(opts.log)
        .map_err(|e| EvidenceError::SpendLog(format!("{}: {e}", opts.log.display())))?;
    let registry =
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(opts.registry));
    let gate = PerCallGate::resolve(&registry, opts.agent, opts.root)
        .map_err(|e| EvidenceError::Registry(format!("{}: {e}", opts.registry.display())))?;
    let counter = CounterRef::for_agent(opts.registry, opts.agent)
        .map_err(|e| EvidenceError::Counter(e.to_string()))?;

    let resume = opts.resume.clone().unwrap_or_else(AuditResume::genesis);
    if resume.prior_records > records.len() {
        return Err(EvidenceError::Input(format!(
            "resume index {} exceeds the log ({} records)",
            resume.prior_records,
            records.len()
        )));
    }
    let suffix = records[resume.prior_records..].to_vec();
    let AnnotatedAudit { verdict, facts } = auths_mcp_core::audit_spend_log_annotated(
        &suffix,
        gate.agent_kel(),
        gate.delegator_kel(),
        std::slice::from_ref(&gate.delegator_did),
        now.timestamp(),
        Some(&counter),
        opts.facilitator_pubkey,
        &resume,
    )
    .await;

    let mut report = report_of(&verdict, &records);
    if let Some(path) = opts.treasury_checkpoints {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| EvidenceError::Treasury(format!("{}: {e}", path.display())))?;
        let lines: Vec<String> = raw.lines().map(str::to_string).collect();
        let last = check_trail(&lines, opts.treasury_pubkey)?;
        if let Some(expected) = opts.expect_cumulative
            && last.cumulative_cents.get() != expected
        {
            return Err(EvidenceError::Treasury(format!(
                "checkpointed cumulative {}c != expected {}c",
                last.cumulative_cents.get(),
                expected
            )));
        }
        report.treasury = Some(treasury_check_of(&last));
    }
    Ok(VerifiedSpend {
        report,
        facts,
        records: suffix,
    })
}

/// Build the typed `audit/v1` report from a walk's verdict + the full record set.
pub fn report_of(verdict: &AuditVerdict, records: &[SpendLogRecord]) -> AuditV1 {
    let (audited, settled) = match verdict {
        AuditVerdict::Consistent(proof) => (proof.calls(), proof.settled_cents().get()),
        _ => (0, 0),
    };
    let checkpoint = records.last().map(|last| AuditCheckpoint {
        records: records.len(),
        settled_cents: settled,
        binding: call_commit_binding(&last.call_commit),
    });
    AuditV1 {
        version: AUDIT_VERSION.to_string(),
        verdict: verdict.clone(),
        code: verdict.code().to_string(),
        consistent: verdict.is_consistent(),
        records: audited,
        settled_cents: settled,
        checkpoint,
        treasury: None,
        freshness: None,
    }
}
