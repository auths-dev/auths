//! The independent spend-audit data model.
//!
//! The contract an offline `auths verify-spend` reads to re-derive an agent's true spend
//! WITHOUT trusting the operator: an append-only **spend log** of per-call records the gateway
//! persists, plus the typed [`AuditVerdict`] the audit returns.
//!
//! This module is the pure DATA layer — no I/O, no crypto, no gateway dependency — so the
//! gateway (which writes the log) and the offline auditor (which reads + verifies it) share one
//! definition. Verification itself replays each record's signed proof(s) through the SAME
//! `auths_verifier::verify_commit_against_kel_scoped` the live gate uses, and sums the
//! AGENT-SIGNED settled costs — never the operator's counter.
//!
//! Both the hermetic replay gate (`replay.rs::drive_call`) and the live `wrap` path
//! (`proxy.rs::call_tool`) sign + gate + persist a real signed commit per brokered call, so the
//! audit re-verifies the same material regardless of which path produced the log. This data model
//! is path-agnostic.

use crate::attestation::RailAttestation;
use crate::budget::CounterRef;
use crate::money::Cents;
use crate::receipt::Receipt;
use auths_id::keri::Event;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};

/// The settlement state of a brokered call: either it touched no rail, or it is metered on a
/// rail and carries whatever settlement artifacts it reached (a refused call has none; a
/// forwarded call records the rail response; a non-zero charge adds the agent-signed settlement
/// commit; an attested charge adds the facilitator attestation).
///
/// Collapsing these into one enum makes a partial state unrepresentable: a `settlement_commit`
/// can only exist alongside a `rail`, never on its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Settlement {
    /// The call touched no payment rail (refused, or a non-metered tool).
    #[default]
    Unmetered,
    /// The call is metered on `rail`, carrying whatever settlement artifacts it reached.
    Metered {
        /// The payment rail this call settled on.
        rail: String,
        /// The rail's RAW response bytes, retained so the audit re-extracts the cost via
        /// `rail::extract` and cross-checks it against the signed settlement (`None` for a refused
        /// metered call that never forwarded).
        ///
        /// ⚠️ LIVE-WIRING CAVEAT (must-review when the live path populates this): capture the
        /// response **body only** — NEVER request/response auth headers. An `Authorization: Bearer
        /// …` or the gateway's custodied downstream credential must never land in the spend log.
        /// (Hermetic today: this is a recorded fixture body, which holds no secret.)
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rail_response: Option<Vec<u8>>,
        /// Raw bytes of the agent's signed SETTLEMENT commit anchoring the actual cost
        /// `{call proof_ref, rail, actual_cents, rail_ref, cumulative}`. `None` for a zero-cost
        /// forwarded call. The audit sums the cost SIGNED here, never the receipt's claim.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        settlement_commit: Option<Vec<u8>>,
        /// The rail FACILITATOR's signed attestation of the charged amount — the rail's OWN
        /// statement of what it charged, independent of the operator/agent. When present (and a
        /// facilitator key is configured) the audit re-verifies it offline and sums the
        /// FACILITATOR-attested amount, so an operator who is also the agent cannot enter an
        /// un-attested number. `None` until the wire captures it (a follow-on).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rail_attestation: Option<RailAttestation>,
    },
}

/// One append-only record in the spend log — everything an offline audit needs to re-verify
/// ONE brokered call without the operator's cooperation. Persisted as one JSON object per line
/// (JSONL) under `<repo>/spend-log/<delegation>.jsonl`.
///
/// `call_commit` (and the `settlement_commit` inside [`Settlement::Metered`]) are the RAW signed
/// git-commit bytes (not just the SHA), so the auditor replays them through
/// `verify_commit_against_kel_scoped` offline rather than trusting the receipt's `proof_ref`. The
/// `rail_response` inside [`Settlement::Metered`] is the rail's raw response, so the audit
/// re-extracts the cost via `rail::extract` and cross-checks it against the SIGNED cost.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendLogRecord {
    /// Raw bytes of the agent's signed `tools/call` proof commit — retained so the audit
    /// re-verifies it offline rather than trusting the receipt's `proof_ref` SHA.
    pub call_commit: Vec<u8>,
    /// UNVERIFIED operator display — a hint, cross-checked against the signed material, never an
    /// input to the audited total. Serialized as `unverified_display` (not a bare `receipt`) so no
    /// reader mistakes it for vouched data: rewriting `verdict`/`tool`/`reserved_cents` here —
    /// every such mutation still audits clean, because the wire never said the block was unverified.
    #[serde(rename = "unverified_display")]
    pub receipt: Receipt,
    /// The settlement state of this call: [`Settlement::Unmetered`] when it touched no rail, else
    /// [`Settlement::Metered`] carrying the rail and whatever settlement artifacts it reached.
    #[serde(default)]
    pub settlement: Settlement,
}

/// The settled high-water read from the verifier-held DURABLE counter — the figure the audit
/// cross-checks the re-derived total against. A newtype so "the durable counter's settled" cannot be
/// confused with "the total re-derived from the log"; the two are compared, never swapped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurableSettled(Cents);

impl DurableSettled {
    /// The durable settled amount.
    pub fn get(self) -> Cents {
        self.0
    }
}

/// Proof that a spend log re-derived CONSISTENT — minted only by [`audit_spend_log`] after the
/// per-record proof checks, the back-link continuity check, AND the durable-counter cross-check all
/// pass. Its fields are private and it has no public constructor, so a "consistent" verdict cannot be
/// fabricated from a bare number: holding a [`ConsistentProof`] means a real audit produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[must_use]
pub struct ConsistentProof {
    calls: usize,
    settled_cents: Cents,
    /// The final commit binding the log re-derived to — the anti-rollback anchor a caller
    /// pins against a witness to detect a tail truncation offline. `None` for an empty log.
    #[serde(default)]
    head: Option<String>,
    /// The VERIFIED counterparty the last metered call settled with (the payee signed into
    /// `Auths-Settle-Ref`, cross-checked against the rail response) — never `receipt.charge_ref`.
    /// `None` when nothing metered settled.
    #[serde(default)]
    counterparty: Option<String>,
}

impl ConsistentProof {
    /// Mint a proof — `pub(crate)` so ONLY this crate's audit, after every check has passed, can
    /// construct one.
    pub(crate) fn new(
        calls: usize,
        settled_cents: Cents,
        head: Option<String>,
        counterparty: Option<String>,
    ) -> Self {
        Self {
            calls,
            settled_cents,
            head,
            counterparty,
        }
    }

    /// Number of brokered calls the audit covered.
    pub fn calls(&self) -> usize {
        self.calls
    }

    /// The proven cross-rail settled total (equal to both the signed cumulative and the durable
    /// counter).
    pub fn settled_cents(&self) -> Cents {
        self.settled_cents
    }

    /// The final commit binding the log re-derived to — the head a caller pins against a witness
    /// (offline audit cannot prove completeness; pinning this detects a later rollback).
    pub fn head(&self) -> Option<&str> {
        self.head.as_deref()
    }

    /// The verified counterparty the last metered call settled with (`Auths-Settle-Ref`), or
    /// `None` when nothing metered settled.
    pub fn counterparty(&self) -> Option<&str> {
        self.counterparty.as_deref()
    }
}

/// The typed result of an offline spend audit. Every failure mode is a NAMED case the caller
/// must handle — never a bool. Only [`AuditVerdict::Consistent`] passes, and it carries a
/// [`ConsistentProof`] only the audit can mint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "kebab-case")]
#[must_use]
pub enum AuditVerdict {
    /// Every proof verified, the back-link chain is complete, every signed cost matched its rail
    /// response, and the re-derived cross-rail total equals BOTH the claimed cumulative AND the
    /// durable verifier-held counter. Carries the proof of that re-derivation.
    Consistent(ConsistentProof),
    /// A call or settlement proof failed `verify_commit_against_kel_scoped` (forged, altered, or
    /// signed-after-revocation). `at` is the record's positional index (an auditor-fixed number a
    /// tamperer cannot choose); `proof_ref` is the offending commit's operator-forgeable display id,
    /// kept only as a secondary hint.
    TamperedProof {
        /// The record index that failed verification — the primary, un-forgeable locator.
        at: usize,
        /// The proof reference (commit SHA) that failed verification — a secondary hint.
        proof_ref: String,
    },
    /// A settlement commit's SIGNED cost disagrees with the cost re-extracted from the
    /// recorded rail response — the operator signed one number but logged another response.
    CostMismatch {
        /// The record index at fault — the primary, un-forgeable locator.
        at: usize,
        /// The cost the agent SIGNED in the settlement commit.
        signed_cents: Cents,
        /// The cost re-extracted from the recorded rail response.
        recomputed_cents: Cents,
        /// The settlement commit at fault — a secondary hint.
        proof_ref: String,
    },
    /// The rail response's charge id disagrees with the counterparty the agent SIGNED in
    /// `Auths-Settle-Ref` — the recorded payee was rewritten after signing.
    CounterpartyMismatch {
        /// The record index at fault — the primary, un-forgeable locator.
        at: usize,
        /// The counterparty the agent SIGNED in `Auths-Settle-Ref`.
        signed_counterparty: String,
        /// The counterparty the recorded rail response actually paid.
        response_counterparty: String,
        /// The settlement commit at fault — a secondary hint.
        proof_ref: String,
    },
    /// The re-derived cross-rail total (summed from the SIGNED costs) disagrees with the
    /// operator's claimed cumulative.
    BudgetMismatch {
        /// The true total re-derived from the signed costs.
        recomputed_cents: Cents,
        /// The cumulative the operator's counter/receipt claimed.
        claimed_cents: Cents,
    },
    /// The signed proof chain broke at record index `at` — a record is missing, out of order, or
    /// duplicated (distinguished by `kind`). `more` counts any further breaks past the first, so a
    /// combined middle-delete + tail-truncation reports both, not only the first gap.
    ChainBreak {
        /// The record index where continuity broke.
        at: usize,
        /// What kind of break it is — missing, reordered, or duplicated.
        kind: ChainBreakKind,
        /// How many additional breaks the walk found past this one.
        #[serde(default)]
        more: usize,
    },
    /// The agent's delegation was revoked as of record index `at`; calls at/after it are
    /// unauthorized.
    Revoked {
        /// The record index at/after which the delegation was revoked.
        at: usize,
    },
}

/// How a spend-log chain broke, decided off the set of commit bindings already seen: a
/// prev-link into nowhere is [`ChainBreakKind::Missing`], a prev-link back into the log is
/// [`ChainBreakKind::OutOfOrder`], and a re-seen binding is [`ChainBreakKind::Duplicate`].
/// A duplicate is an EXTRA record and a reorder drops NOTHING — distinct attacks the old
/// single `dropped-call` code conflated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChainBreakKind {
    /// The record's `Auths-Prev` points to a binding the log does not hold — a record was dropped.
    Missing,
    /// The record's `Auths-Prev` points BACK into the log — records were reordered.
    OutOfOrder,
    /// The record's own binding was already seen earlier — a record was duplicated.
    Duplicate,
}

impl AuditVerdict {
    /// True ONLY for [`AuditVerdict::Consistent`] — the audit passed.
    pub fn is_consistent(&self) -> bool {
        matches!(self, AuditVerdict::Consistent(_))
    }

    /// A stable kebab-case code (for logs, the CLI, and exit-code mapping).
    pub fn code(&self) -> &'static str {
        match self {
            // "self-consistent", never a bare "consistent": an offline audit proves the log
            // agrees with itself, NOT that it is complete (a $0/refused tail truncation is
            // invisible offline). Completeness needs a witnessed head pin — see Display.
            AuditVerdict::Consistent(_) => "self-consistent",
            AuditVerdict::TamperedProof { .. } => "tampered-proof",
            AuditVerdict::CostMismatch { .. } => "cost-mismatch",
            AuditVerdict::CounterpartyMismatch { .. } => "counterparty-mismatch",
            AuditVerdict::BudgetMismatch { .. } => "budget-mismatch",
            AuditVerdict::ChainBreak { .. } => "chain-break",
            AuditVerdict::Revoked { .. } => "revoked",
        }
    }
}

impl fmt::Display for AuditVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuditVerdict::Consistent(proof) => write!(
                f,
                "self-consistent — {} call(s), ${}.{:02} re-derived from signed costs \
                 (completeness unproven offline — pin head {} against a witness to detect rollback)",
                proof.calls(),
                proof.settled_cents().get() / 100,
                proof.settled_cents().get() % 100,
                proof.head().unwrap_or("<empty>"),
            ),
            AuditVerdict::TamperedProof { at, proof_ref } => {
                write!(
                    f,
                    "tampered-proof — record {at} failed verification (proof_ref hint {proof_ref})"
                )
            }
            AuditVerdict::CostMismatch {
                at,
                signed_cents,
                recomputed_cents,
                proof_ref,
            } => write!(
                f,
                "cost-mismatch — record {at} signed {}c but the rail response is {}c \
                 (proof_ref hint {proof_ref})",
                signed_cents.get(),
                recomputed_cents.get()
            ),
            AuditVerdict::CounterpartyMismatch {
                at,
                signed_counterparty,
                response_counterparty,
                proof_ref,
            } => write!(
                f,
                "counterparty-mismatch — record {at} signed payee {signed_counterparty} \
                 but the rail response paid {response_counterparty} (proof_ref hint {proof_ref})"
            ),
            AuditVerdict::BudgetMismatch {
                recomputed_cents,
                claimed_cents,
            } => write!(
                f,
                "budget-mismatch — re-derived {}c, operator claimed {}c",
                recomputed_cents.get(),
                claimed_cents.get()
            ),
            AuditVerdict::ChainBreak { at, kind, more } => {
                let extra = if *more > 0 {
                    format!(" (plus {more} more)")
                } else {
                    String::new()
                };
                write!(
                    f,
                    "chain-break — record {at}: {kind:?}{extra} \
                     (re-fetch the canonical log and diff)"
                )
            }
            AuditVerdict::Revoked { at } => {
                write!(f, "revoked — delegation revoked as of record {at}")
            }
        }
    }
}

/// The spend-log file for one agent delegation under `repo` (the verifier-held registry path):
/// `<repo>/spend-log/<delegation>.jsonl`. Shared by the gateway (which appends records) and the
/// offline auditor (which reads them) so there is ONE definition of where the log lives.
pub fn spend_log_path(repo: &Path, delegation: &str) -> PathBuf {
    repo.join("spend-log")
        .join(format!("{}.jsonl", safe_key(delegation)))
}

/// The delegation's ROTATED spend-log directory: `spend-log/<delegation>/` holding
/// one period-named file per UTC month. Rotation bounds any single file without
/// weakening tamper evidence — the `Auths-Prev` chain runs across files, so a
/// missing middle period still breaks re-derivation.
///
/// Args:
/// * `repo`: the verifier registry root.
/// * `delegation`: the agent delegation the log belongs to.
///
/// Usage:
/// ```ignore
/// let dir = spend_log_dir(repo, "did:keri:Eagent…");
/// ```
pub fn spend_log_dir(repo: &Path, delegation: &str) -> PathBuf {
    repo.join("spend-log").join(safe_key(delegation))
}

/// The period file a record stamped `at` lands in (UTC month, lexicographically
/// ordered so a sorted directory walk replays in append order).
///
/// Args:
/// * `repo`: the verifier registry root.
/// * `delegation`: the agent delegation.
/// * `at`: the record's own timestamp (injected clock).
///
/// Usage:
/// ```ignore
/// let file = spend_log_period_path(repo, delegation, now);
/// ```
pub fn spend_log_period_path(
    repo: &Path,
    delegation: &str,
    at: chrono::DateTime<chrono::Utc>,
) -> PathBuf {
    spend_log_dir(repo, delegation).join(format!("{}.jsonl", at.format("%Y-%m")))
}

/// Resolve where a delegation's log actually lives: the rotated directory when it
/// exists, else the legacy single file.
///
/// Args:
/// * `repo`: the verifier registry root.
/// * `delegation`: the agent delegation.
///
/// Usage:
/// ```ignore
/// let records = read_spend_log(&resolve_spend_log(repo, delegation))?;
/// ```
pub fn resolve_spend_log(repo: &Path, delegation: &str) -> PathBuf {
    let dir = spend_log_dir(repo, delegation);
    if dir.is_dir() {
        dir
    } else {
        spend_log_path(repo, delegation)
    }
}

/// Read every [`SpendLogRecord`] from a delegation's spend log, in order (for the offline
/// auditor). `path` may be a single JSONL file or a ROTATED directory of period files —
/// a directory is walked in sorted (chronological) order and its files concatenate into
/// one record stream, which the `Auths-Prev` chain then proves complete across the
/// rotation boundary. A blank trailing line is ignored; a non-blank line that fails to
/// parse is `InvalidData` — a corrupted or edited log fails closed rather than silently
/// dropping a call.
pub fn read_spend_log(path: &Path) -> std::io::Result<Vec<SpendLogRecord>> {
    let files: Vec<PathBuf> = if path.is_dir() {
        let mut period_files: Vec<PathBuf> = std::fs::read_dir(path)?
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|ext| ext == "jsonl"))
            .collect();
        period_files.sort();
        period_files
    } else {
        vec![path.to_path_buf()]
    };
    let mut records = Vec::new();
    for file in files {
        let raw = std::fs::read_to_string(&file)?;
        let non_empty: Vec<&str> = raw.lines().filter(|l| !l.trim().is_empty()).collect();
        for (line_idx, line) in non_empty.iter().enumerate() {
            match serde_json::from_str::<SpendLogRecord>(line) {
                Ok(record) => records.push(record),
                // A bad line is a READ failure, never a `tampered-proof` — the audit must SPEAK
                // (corrupt / not-JSONL / crash-truncated), not emit raw serde noise.
                Err(e) => {
                    let is_last = line_idx + 1 == non_empty.len();
                    let malformed = LogReadError::classify(records.len() + 1, is_last, &e);
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        malformed.to_string(),
                    ));
                }
            }
        }
    }
    Ok(records)
}

/// Why a spend log could not be READ — a first-class, non-tamper outcome that SPEAKS the cause so a
/// naive operator who `jq .`'d their own log (or hit a crash-truncated tail) gets a fix, never raw
/// serde noise mistaken for fraud. Kept firmly OUT of the `tampered-proof`/`cost-mismatch` family
/// (corruption is not conflated with tampering).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogReadError {
    /// A record spans multiple lines — almost always a `jq .` pretty-print. JSONL is one record
    /// per line.
    NotOneLineJson {
        /// The 1-based record position that could not be read as one line.
        record: usize,
    },
    /// The final record is a partial write — the file was cut off (a crash mid-append).
    TruncatedRecord {
        /// The 1-based record position that was truncated.
        record: usize,
    },
    /// A record is neither multiline nor a clean truncation — some other corruption.
    CorruptRecord {
        /// The 1-based record position that could not be parsed.
        record: usize,
        /// The underlying parse detail.
        detail: String,
    },
}

impl LogReadError {
    /// Classify a failed line parse off the serde error and whether it was the LAST non-empty line:
    /// an unexpected-end error on a NON-last line is a multiline (`jq .`) record; on the LAST line
    /// it is a crash-truncated tail; anything else is other corruption.
    ///
    /// Args:
    /// * `record`: the 1-based record position that failed.
    /// * `is_last`: whether the failing line was the last non-empty line of its file.
    /// * `err`: the serde parse error.
    ///
    /// Usage:
    /// ```ignore
    /// let malformed = LogReadError::classify(3, true, &serde_err);
    /// ```
    pub fn classify(record: usize, is_last: bool, err: &serde_json::Error) -> LogReadError {
        if err.is_eof() {
            if is_last {
                LogReadError::TruncatedRecord { record }
            } else {
                LogReadError::NotOneLineJson { record }
            }
        } else {
            LogReadError::CorruptRecord {
                record,
                detail: err.to_string(),
            }
        }
    }
}

impl fmt::Display for LogReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogReadError::NotOneLineJson { record } => write!(
                f,
                "malformed-log — record {record} is not one-line JSON \
                 (did you `jq .` this? JSONL is one record per line)"
            ),
            LogReadError::TruncatedRecord { record } => write!(
                f,
                "malformed-log — the final record ({record}) is truncated; \
                 the file may have been cut off by a crash"
            ),
            LogReadError::CorruptRecord { record, detail } => {
                write!(
                    f,
                    "malformed-log — record {record} could not be parsed: {detail}"
                )
            }
        }
    }
}

/// A filesystem-safe single component from a delegation id: strip the `did:keri:` scheme and map
/// anything that is not `[A-Za-z0-9_-]` to `_` (defensive — a `did:keri:E…` tail is base64url and
/// already safe; this only guards a malformed key from escaping the directory).
fn safe_key(delegation: &str) -> String {
    let parsed = auths_verifier::IdentityDID::parse(delegation).ok();
    let tail = parsed.as_ref().map(|d| d.prefix()).unwrap_or(delegation);
    if tail.is_empty() || tail == "." || tail == ".." {
        return "_".to_string();
    }
    tail.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Independently re-verify an agent's spend log. The PROOF leg is operator-proof: replay each
/// record's signed `call_commit` through the SAME `verify_commit_against_kel_scoped` the live gate
/// uses — a forged/tampered proof → [`AuditVerdict::TamperedProof`], a revoked-key proof →
/// [`AuditVerdict::Revoked`] — so a hostile operator cannot forge or alter a proof undetected. The
/// SPEND leg sums each settled call's cost, re-extracted from its recorded `rail_response` via
/// [`crate::rail::extract`], and cross-checks it against the operator's claimed cumulative (catching
/// internal inconsistency). Once a call carries a `settlement_commit`, the cost is taken from the
/// agent's signature instead — un-forgeable even by a colluding operator.
///
/// `now` is unix-epoch seconds (the auditor's injected clock — the verifier holds none). The
/// agent/delegator KELs + `pinned_roots` are resolved the SAME way `PerCallGate::resolve` does (from
/// the issuer's registry), so the audit is the gate's own check, re-run by anyone, offline.
///
/// A legitimately refused call (out-of-scope / over-cap) carries an AUTHENTIC proof and is NOT a
/// tamper.
///
/// `counter` is the durable verifier-held counter to cross-check the re-derived total against.
/// Pass `None` ONLY when the caller anchors log completeness some other way (an anchored head
/// commitment over the embedded log, as an `EvidenceBundle` does) — with no counter AND no
/// anchor, a tail truncation is undetectable.
pub async fn audit_spend_log(
    records: &[SpendLogRecord],
    agent_kel: &[Event],
    delegator_kel: &[Event],
    pinned_roots: &[String],
    now: i64,
    counter: Option<&CounterRef>,
    facilitator_pubkey: Option<&[u8]>,
) -> AuditVerdict {
    audit_spend_log_resumed(
        records,
        agent_kel,
        delegator_kel,
        pinned_roots,
        now,
        counter,
        facilitator_pubkey,
        &AuditResume::genesis(),
    )
    .await
}

/// Where a resumed audit picks up: the state a PRIOR full verification of the log's
/// prefix established. Sound because the `Auths-Prev` chain forces the suffix's
/// first record to link to `prior_binding`, and every suffix signature is still
/// re-verified — only work already proven by the caller's own earlier audit is
/// skipped, never trust in the operator.
#[derive(Debug, Clone)]
pub struct AuditResume {
    /// Records already verified (the suffix's index offset in the full log).
    pub prior_records: usize,
    /// The verified prefix's final commit binding (`Auths-Prev` for the next record).
    pub prior_binding: String,
    /// The settled total the verified prefix re-derived.
    pub prior_settled_cents: Cents,
}

impl AuditResume {
    /// A from-the-top audit: genesis binding, zero prior spend.
    ///
    /// Usage:
    /// ```ignore
    /// let verdict = audit_spend_log_resumed(records, …, &AuditResume::genesis()).await;
    /// ```
    pub fn genesis() -> AuditResume {
        AuditResume {
            prior_records: 0,
            prior_binding: SPEND_LOG_GENESIS.to_string(),
            prior_settled_cents: Cents::ZERO,
        }
    }
}

/// [`audit_spend_log`], resuming after an already-verified prefix: `records` is the
/// SUFFIX, and `resume` carries the prefix's proven end state. The final verdict
/// reports whole-log totals (prefix + suffix).
#[allow(clippy::too_many_arguments)]
pub async fn audit_spend_log_resumed(
    records: &[SpendLogRecord],
    agent_kel: &[Event],
    delegator_kel: &[Event],
    pinned_roots: &[String],
    now: i64,
    counter: Option<&CounterRef>,
    facilitator_pubkey: Option<&[u8]>,
    resume: &AuditResume,
) -> AuditVerdict {
    audit_walk(
        records,
        agent_kel,
        delegator_kel,
        pinned_roots,
        now,
        counter,
        facilitator_pubkey,
        resume,
        None,
    )
    .await
}

/// The per-record facts one audited spend-log record established — everything the walk
/// RE-DERIVED for that record, as opposed to what the operator's receipt merely claims.
/// A downstream judge (the evidence layer's per-call verdict) consumes these instead of
/// re-running the walk, so there stays exactly one audit implementation.
#[derive(Debug, Clone)]
pub struct RecordFact {
    /// The record's index in the WHOLE log (prefix + suffix under a resumed audit).
    pub index: usize,
    /// The verdict RE-DERIVED from the record's signed proof by the verifier replay —
    /// never the receipt's claimed verdict.
    pub rederived_verdict: crate::gate::Verdict,
    /// This record's commit binding (the value the next record's `Auths-Prev` links to).
    pub binding: String,
    /// The re-derived cross-rail SETTLED total STRICTLY BEFORE this record.
    pub settled_cents_before: Cents,
    /// The agent-signed (facilitator-attested when available) settled cost of this
    /// record — `None` for an unmetered or zero-cost call.
    pub signed_cents: Option<Cents>,
    /// The VERIFIED counterparty this record settled with — the payee signed into
    /// `Auths-Settle-Ref` and cross-checked against the rail response. `None` for an unmetered
    /// or zero-cost call. A consumer acts on THIS, never on the operator-controlled display.
    pub counterparty: Option<String>,
}

/// An audit verdict together with the per-record [`RecordFact`]s the walk established
/// up to the point it stopped (all records on `Consistent`; the verified prefix on a
/// failure — the failing record has no fact, its defect is the verdict itself).
#[derive(Debug)]
#[must_use]
pub struct AnnotatedAudit {
    /// The whole-log verdict.
    pub verdict: AuditVerdict,
    /// Per-record re-derived facts, in log order.
    pub facts: Vec<RecordFact>,
}

/// [`audit_spend_log_resumed`], additionally collecting a [`RecordFact`] per verified
/// record. Same walk, same checks, one implementation — the annotation is a side
/// channel, never a second authority.
#[allow(clippy::too_many_arguments)]
pub async fn audit_spend_log_annotated(
    records: &[SpendLogRecord],
    agent_kel: &[Event],
    delegator_kel: &[Event],
    pinned_roots: &[String],
    now: i64,
    counter: Option<&CounterRef>,
    facilitator_pubkey: Option<&[u8]>,
    resume: &AuditResume,
) -> AnnotatedAudit {
    let mut facts = Vec::with_capacity(records.len());
    let verdict = audit_walk(
        records,
        agent_kel,
        delegator_kel,
        pinned_roots,
        now,
        counter,
        facilitator_pubkey,
        resume,
        Some(&mut facts),
    )
    .await;
    AnnotatedAudit { verdict, facts }
}

#[allow(clippy::too_many_arguments)]
async fn audit_walk(
    records: &[SpendLogRecord],
    agent_kel: &[Event],
    delegator_kel: &[Event],
    pinned_roots: &[String],
    now: i64,
    counter: Option<&CounterRef>,
    facilitator_pubkey: Option<&[u8]>,
    resume: &AuditResume,
    mut facts: Option<&mut Vec<RecordFact>>,
) -> AuditVerdict {
    let provider = auths_crypto::default_provider();
    let mut settled = resume.prior_settled_cents;
    // The binding each record's `Auths-Prev` must match — the prior record's commit hash, the
    // resumed prefix's final binding, or the genesis sentinel for a from-the-top audit.
    let mut expected_prev = resume.prior_binding.clone();
    // Every call binding seen so far — a re-seen OWN binding is a duplicate.
    let mut seen_bindings: std::collections::HashSet<String> = std::collections::HashSet::new();
    // Every binding the log holds (any position). A broken prev-link that STILL points into this
    // set is a reorder (the record exists, just not as the immediate predecessor); one that points
    // NOWHERE in the set is a genuinely missing/dropped record.
    let all_bindings: std::collections::HashSet<String> = records
        .iter()
        .map(|r| call_commit_binding(&r.call_commit))
        .collect();
    // Structural breaks are collected (not returned on the first) so a combined middle-delete +
    // tail-truncation reports both; the first is the verdict, the rest are the `more` count.
    let mut breaks: Vec<(usize, ChainBreakKind)> = Vec::new();
    // The last verified counterparty (`Auths-Settle-Ref`) — surfaced on the ConsistentProof so a
    // consumer acts on the proven payee, never the operator-controlled display.
    let mut last_counterparty: Option<String> = None;
    for (i, rec) in records.iter().enumerate() {
        let settled_before = settled;
        let mut fact_signed_cents: Option<Cents> = None;
        let mut fact_counterparty: Option<String> = None;
        // Re-verify the SIGNED proof bytes — the gate's own authenticity check, re-run offline.
        let commit_verdict = auths_verifier::verify_commit_against_kel_scoped(
            &rec.call_commit,
            agent_kel,
            delegator_kel,
            pinned_roots,
            provider,
            now,
        )
        .await;
        // Reuse the EXACT CommitVerdict→Verdict mapping the gate uses (DRY — one source of truth).
        // The RE-DERIVED verdict is the authority for everything below; the receipt's CLAIMED
        // verdict is operator-controlled and is NEVER an input here.
        let verdict = crate::gate::Verdict::from_commit_verdict(&commit_verdict);
        match &verdict {
            crate::gate::Verdict::ProofUnauthentic { .. } => {
                return AuditVerdict::TamperedProof {
                    at: i,
                    proof_ref: rec.receipt.proof_ref.clone(),
                };
            }
            crate::gate::Verdict::Revoked => return AuditVerdict::Revoked { at: i },
            // Allowed / OutsideAgentScope / AgentExpired / Stale are AUTHENTIC proofs — a legit
            // refusal (including a stale-freshness one) is not a tamper; only forgery and
            // revocation are audit failures of the proof itself.
            _ => {}
        }
        // Continuity: each record's SIGNED `Auths-Prev` links to the prior record's commit (the
        // first to the genesis sentinel). A DROPPED, reordered, or DUPLICATED record breaks the
        // chain — distinguished by whether the prev-link points nowhere (missing), back into the
        // log (reorder), or the record's own binding was already seen (duplicate). The proof was
        // just verified authentic, so this trailer is signed and trustworthy.
        let this_binding = call_commit_binding(&rec.call_commit);
        let claimed_prev = commit_trailer(&rec.call_commit, "Auths-Prev").unwrap_or("");
        if claimed_prev != expected_prev {
            let kind = if seen_bindings.contains(&this_binding) {
                ChainBreakKind::Duplicate
            } else if all_bindings.contains(claimed_prev) {
                ChainBreakKind::OutOfOrder
            } else {
                ChainBreakKind::Missing
            };
            breaks.push((i, kind));
            // Resync so the walk continues past the break, counting any further breaks rather than
            // reporting only the first — still fail-closed (any break blocks `Consistent`).
            seen_bindings.insert(this_binding.clone());
            expected_prev = this_binding;
            continue;
        }
        seen_bindings.insert(this_binding.clone());
        expected_prev = this_binding;
        // Sum the settled cost for a call that (a) carries an AUTHENTIC, IN-SCOPE proof —
        // `Allowed`/`AgentExpired`, both PROOF-DETERMINED, so the operator cannot relabel a settled
        // call as refused without breaking its signature (`OutsideAgentScope` never settled) — AND
        // (b) is metered with a recorded rail response (set only for calls that forwarded; see
        // replay.rs). Unmetered, or metered without a response, skips this branch.
        if let Settlement::Metered {
            rail,
            rail_response: Some(resp),
            settlement_commit,
            rail_attestation,
        } = &rec.settlement
            && matches!(
                verdict,
                crate::gate::Verdict::Allowed | crate::gate::Verdict::AgentExpired
            )
        {
            let rail = rail.as_str();
            let resp = resp.as_slice();
            // The cost + reference the rail's own recorded response reports. The response is
            // operator-held and unsigned, so it is only a cross-check — the authoritative amount
            // and payee are the ones the agent SIGNED in the settlement below.
            // Re-derivation of a RECORDED response (a cross-check of the SIGNED amount): its
            // network is a fact already settled, so the mainnet gate is permissive here
            // (PaymentMode::Real) — the sandbox gate guards a live settle, not an offline re-check.
            let extracted =
                match crate::rail::extract(rail, resp, crate::paymode::PaymentMode::Real) {
                    Ok(c) => c,
                    // A settled call whose recorded response no longer extracts is a tampered response.
                    Err(_) => {
                        return AuditVerdict::CostMismatch {
                            at: i,
                            signed_cents: Cents::ZERO,
                            recomputed_cents: Cents::ZERO,
                            proof_ref: rec.receipt.proof_ref.clone(),
                        };
                    }
                };
            let recomputed = extracted.amount_cents;
            // A non-zero settled cost MUST come from a settlement the agent signed. Requiring it
            // closes the downgrade where an operator strips the settlement and falls back to a rail
            // response it authored. (A zero-cost forwarded call settles nothing and needs none.)
            if !recomputed.is_zero() {
                let Some(settle_commit) = settlement_commit.as_deref() else {
                    return AuditVerdict::TamperedProof {
                        at: i,
                        proof_ref: rec.receipt.proof_ref.clone(),
                    };
                };
                // 1. The settlement is an authentic, in-scope commit by the agent. Its signature
                //    covers every trailer read below, so a flipped byte anywhere breaks it here.
                let settle_verdict = auths_verifier::verify_commit_against_kel_scoped(
                    settle_commit,
                    agent_kel,
                    delegator_kel,
                    pinned_roots,
                    provider,
                    now,
                )
                .await;
                if !matches!(
                    crate::gate::Verdict::from_commit_verdict(&settle_verdict),
                    crate::gate::Verdict::Allowed | crate::gate::Verdict::AgentExpired
                ) {
                    return AuditVerdict::TamperedProof {
                        at: i,
                        proof_ref: rec.receipt.proof_ref.clone(),
                    };
                }
                // 2. The settlement is BOUND to THIS call: its signed call-binding trailer is the
                //    hash of this record's own call commit. Without this an operator could move a
                //    genuinely-signed settlement from a cheap call onto an expensive one.
                if commit_trailer(settle_commit, "Auths-Settle-Call")
                    != Some(call_commit_binding(&rec.call_commit).as_str())
                {
                    return AuditVerdict::TamperedProof {
                        at: i,
                        proof_ref: rec.receipt.proof_ref.clone(),
                    };
                }
                // 3. The COUNTERPARTY: the payee the agent SIGNED in `Auths-Settle-Ref` must equal
                //    the charge id the rail response actually paid. A disagreement means the recorded
                //    payee was rewritten after signing — the committed-but-unaudited counterparty.
                let signed_ref = commit_trailer(settle_commit, "Auths-Settle-Ref").unwrap_or("");
                if signed_ref != extracted.reference {
                    return AuditVerdict::CounterpartyMismatch {
                        at: i,
                        signed_counterparty: signed_ref.to_string(),
                        response_counterparty: extracted.reference.clone(),
                        proof_ref: rec.receipt.proof_ref.clone(),
                    };
                }
                fact_counterparty = Some(signed_ref.to_string());
                last_counterparty = fact_counterparty.clone();
                // 4. The agent-signed cost, cross-checked against the rail's own response — a
                //    disagreement means the operator swapped the response (or the signed amount).
                // The signed cents trailer is a decimal string — parse to u64 then wrap at this
                // commit-trailer boundary.
                let Some(signed) = commit_trailer(settle_commit, "Auths-Settle-Cents")
                    .and_then(|v| v.parse::<u64>().ok())
                    .map(Cents::new)
                else {
                    return AuditVerdict::TamperedProof {
                        at: i,
                        proof_ref: rec.receipt.proof_ref.clone(),
                    };
                };
                if signed != recomputed {
                    return AuditVerdict::CostMismatch {
                        at: i,
                        signed_cents: signed,
                        recomputed_cents: recomputed,
                        proof_ref: rec.receipt.proof_ref.clone(),
                    };
                }
                // When the rail FACILITATOR independently attested this charge, the audited cost must
                // be the facilitator-attested amount — a value the operator cannot mint — not just the
                // agent-signed number. Verify it offline against the pinned facilitator key and require
                // it agrees with the signed cost; an altered attestation or a disagreement fails closed.
                // With no facilitator key configured the attestation leg is skipped (the offline audit
                // still runs; capturing the attestation on the wire is a follow-on), so the summand is
                // the agent-signed cost — already cross-checked against the rail response above.
                let summand = match (rail_attestation.as_ref(), facilitator_pubkey) {
                    (Some(attestation), Some(key)) => {
                        let attested = match crate::attestation::Attested::from_facilitator(
                            attestation,
                            key,
                        ) {
                            Ok(a) => a,
                            Err(_) => {
                                return AuditVerdict::TamperedProof {
                                    at: i,
                                    proof_ref: rec.receipt.proof_ref.clone(),
                                };
                            }
                        };
                        if attested.amount() != signed {
                            return AuditVerdict::CostMismatch {
                                at: i,
                                signed_cents: signed,
                                recomputed_cents: attested.amount(),
                                proof_ref: rec.receipt.proof_ref.clone(),
                            };
                        }
                        attested.amount()
                    }
                    _ => signed,
                };
                settled = settled.saturating_add(summand);
                fact_signed_cents = Some(summand);
                // 5. The signed running total ties the cumulative to signed material, so the budget
                //    leg does not rest on the operator's own (unsigned) receipt cumulative. The
                //    trailer is a decimal string — parse to u64 then wrap at this boundary.
                let Some(signed_cumulative) =
                    commit_trailer(settle_commit, "Auths-Settle-Cumulative")
                        .and_then(|v| v.parse::<u64>().ok())
                        .map(Cents::new)
                else {
                    return AuditVerdict::TamperedProof {
                        at: i,
                        proof_ref: rec.receipt.proof_ref.clone(),
                    };
                };
                if signed_cumulative != settled {
                    return AuditVerdict::BudgetMismatch {
                        recomputed_cents: settled,
                        claimed_cents: signed_cumulative,
                    };
                }
            }
        }
        if let Some(list) = facts.as_deref_mut() {
            list.push(RecordFact {
                index: resume.prior_records + i,
                rederived_verdict: verdict.clone(),
                binding: expected_prev.clone(),
                settled_cents_before: settled_before,
                signed_cents: fact_signed_cents,
                counterparty: fact_counterparty,
            });
        }
    }
    // A structural break (missing / reordered / duplicated record) blocks a clean verdict — report
    // the first with a count of any further breaks, BEFORE the budget/counter cross-checks below.
    if let Some(&(at, kind)) = breaks.first() {
        return AuditVerdict::ChainBreak {
            at,
            kind,
            more: breaks.len().saturating_sub(1),
        };
    }
    // The operator's claimed cross-rail total is the last record's cumulative — an UNTRUSTED hint we
    // compare against the cost we re-derived from the rail responses. An EMPTY resumed suffix has
    // no new claim to compare (the prefix's claim was checked when it was verified); the durable
    // counter below still cross-checks the carried total.
    if let Some(last) = records.last()
        && settled != last.receipt.cumulative_cents
    {
        return AuditVerdict::BudgetMismatch {
            recomputed_cents: settled,
            claimed_cents: last.receipt.cumulative_cents,
        };
    }
    // Cross-check the re-derived total against the DURABLE verifier-held counter the wire advanced —
    // which truncating the LOG does not touch. Dropping the tail lowers the re-derived total AND the
    // claimed cumulative above together (so that check passes), but the counter still holds the full
    // settled high-water, so a truncated tail makes re-derived < durable → caught here. A counter
    // that cannot be read confirms nothing, so it fails closed. (Caveat: an operator who ALSO holds
    // the counter could roll it back to match a truncated log — see the residual note in spend_log.)
    // A caller passing NO counter must anchor completeness elsewhere (an anchored head commitment
    // over the embedded log); this skip is that caller's explicit, documented trade.
    if let Some(counter) = counter {
        let durable = match counter.open_counter().settled_cents() {
            Ok(cents) => DurableSettled(cents),
            Err(_) => {
                return AuditVerdict::BudgetMismatch {
                    recomputed_cents: settled,
                    claimed_cents: Cents::ZERO,
                };
            }
        };
        if settled != durable.get() {
            return AuditVerdict::BudgetMismatch {
                recomputed_cents: settled,
                claimed_cents: durable.get(),
            };
        }
    }
    AuditVerdict::Consistent(ConsistentProof::new(
        resume.prior_records + records.len(),
        settled,
        // The head the caller pins against a witness to detect a later rollback (offline audit
        // cannot prove completeness). `None` for an empty log — nothing to be consistent with.
        records.last().map(|r| call_commit_binding(&r.call_commit)),
        last_counterparty,
    ))
}

/// The first record in a spend log has no predecessor; its signed `Auths-Prev` trailer carries this
/// fixed sentinel instead of a prior commit's hash. The audit requires record 0 to match it, so an
/// operator cannot drop the head of the log and pass off a later record as the first.
pub const SPEND_LOG_GENESIS: &str = "genesis";

/// The hex SHA-256 of a call's signed commit bytes — the value that binds a settlement to the one
/// call it settles, and that the next record's `Auths-Prev` links back to. The gateway stamps this
/// into the settlement's signed `Auths-Settle-Call` trailer; the audit recomputes it from the
/// record's own `call_commit` and requires a match, so a settlement signed for a cheap call cannot
/// be moved onto an expensive one.
pub fn call_commit_binding(call_commit: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(call_commit);
    let mut hex = String::with_capacity(digest.len() * 2);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

/// Read a single signed trailer value (`Token: value`) from a commit's message body. The bytes are
/// the raw git commit object; the SSH signature covers the message, so the caller verifies the
/// signature BEFORE trusting any value. The token must be followed immediately by `:` (optionally
/// after whitespace), so e.g. `Auths-Settle-Cents` never matches `Auths-Settle-Cumulative`. Returns
/// the FIRST match's trimmed value, or `None` when absent or the bytes are not UTF-8.
fn commit_trailer<'a>(commit_bytes: &'a [u8], token: &str) -> Option<&'a str> {
    let text = std::str::from_utf8(commit_bytes).ok()?;
    text.lines().find_map(|line| {
        line.trim()
            .strip_prefix(token)?
            .trim_start()
            .strip_prefix(':')
            .map(str::trim)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate::{ToolCall, Verdict};
    use chrono::DateTime;
    use std::path::Path;

    fn sample_receipt() -> Receipt {
        let call = ToolCall {
            tool: "read_file".to_string(),
            args: serde_json::json!({ "path": "src/lib.rs" }),
            cost_cents: Cents::ZERO,
        };
        Receipt::for_call(
            "did:keri:Eagent",
            "did:keri:Eroot",
            &call,
            "abc123commitsha",
            Verdict::Allowed,
            Some("x402"),
            Some("0xtx"),
            Cents::ZERO,
            Cents::new(150),
            DateTime::from_timestamp(0, 0).unwrap(),
        )
    }

    #[test]
    fn audit_verdict_code_and_is_consistent() {
        let ok = AuditVerdict::Consistent(ConsistentProof::new(
            3,
            Cents::new(450),
            Some("deadbeefhead".to_string()),
            None,
        ));
        assert!(ok.is_consistent());
        // The offline audit proves self-consistency, never completeness — the code says so.
        assert_eq!(ok.code(), "self-consistent");

        let bad = AuditVerdict::TamperedProof {
            at: 0,
            proof_ref: "deadbeef".into(),
        };
        assert!(!bad.is_consistent());
        assert_eq!(bad.code(), "tampered-proof");
        assert_eq!(
            AuditVerdict::CostMismatch {
                at: 1,
                signed_cents: Cents::new(10),
                recomputed_cents: Cents::new(5),
                proof_ref: "s".into()
            }
            .code(),
            "cost-mismatch"
        );
        assert_eq!(
            AuditVerdict::ChainBreak {
                at: 2,
                kind: ChainBreakKind::Missing,
                more: 0
            }
            .code(),
            "chain-break"
        );
        assert_eq!(AuditVerdict::Revoked { at: 4 }.code(), "revoked");
    }

    #[test]
    fn consistent_display_carries_the_completeness_caveat_and_head() {
        // The success line must never be a bare `consistent` — it names self-consistency, the
        // completeness caveat, and the head to pin against a witness.
        let proof = ConsistentProof::new(7, Cents::new(0), Some("abc123head".to_string()), None);
        let shown = AuditVerdict::Consistent(proof).to_string();
        assert!(shown.starts_with("self-consistent"), "{shown}");
        assert!(shown.contains("completeness unproven"), "{shown}");
        assert!(shown.contains("abc123head"), "{shown}");
        // An empty log names `<empty>` as the head — an empty log proves nothing.
        let empty = ConsistentProof::new(0, Cents::ZERO, None, None);
        let shown_empty = AuditVerdict::Consistent(empty).to_string();
        assert!(shown_empty.contains("0 call(s)"), "{shown_empty}");
        assert!(
            shown_empty.contains("completeness unproven"),
            "{shown_empty}"
        );
        assert!(shown_empty.contains("<empty>"), "{shown_empty}");
    }

    #[test]
    fn counterparty_mismatch_code_and_display() {
        let v = AuditVerdict::CounterpartyMismatch {
            at: 3,
            signed_counterparty: "ch_3Mml".into(),
            response_counterparty: "ch_ATTACKERxxx".into(),
            proof_ref: "deadbeef".into(),
        };
        assert_eq!(v.code(), "counterparty-mismatch");
        let shown = v.to_string();
        assert!(shown.contains("record 3"), "{shown}");
        assert!(shown.contains("ch_3Mml"), "{shown}");
        assert!(shown.contains("ch_ATTACKERxxx"), "{shown}");
    }

    #[test]
    fn tampered_proof_display_leads_with_the_positional_index() {
        // A tamperer forges `proof_ref` to any string; the auditor-fixed positional `at` leads the
        // Display so the record named is not attacker-chosen.
        let v = AuditVerdict::TamperedProof {
            at: 5,
            proof_ref: "deadbeefATTACKER".into(),
        };
        let shown = v.to_string();
        assert!(shown.starts_with("tampered-proof — record 5"), "{shown}");
    }

    #[test]
    fn chain_break_kinds_are_distinct_on_the_wire() {
        for kind in [
            ChainBreakKind::Missing,
            ChainBreakKind::OutOfOrder,
            ChainBreakKind::Duplicate,
        ] {
            let v = AuditVerdict::ChainBreak {
                at: 0,
                kind,
                more: 0,
            };
            let json = serde_json::to_string(&v).unwrap();
            assert!(json.contains("\"verdict\":\"chain-break\""), "{json}");
            assert_eq!(serde_json::from_str::<AuditVerdict>(&json).unwrap(), v);
        }
    }

    #[test]
    fn audit_verdict_serde_roundtrips_tagged_kebab() {
        let v = AuditVerdict::CostMismatch {
            at: 2,
            signed_cents: Cents::new(60),
            recomputed_cents: Cents::new(50),
            proof_ref: "p".into(),
        };
        let json = serde_json::to_string(&v).unwrap();
        assert!(
            json.contains("\"verdict\":\"cost-mismatch\""),
            "tagged kebab-case: {json}"
        );
        assert_eq!(serde_json::from_str::<AuditVerdict>(&json).unwrap(), v);
    }

    #[test]
    fn spend_log_record_roundtrips_as_one_jsonl_line() {
        let rec = SpendLogRecord {
            call_commit: b"signed call commit bytes".to_vec(),
            receipt: sample_receipt(),
            settlement: Settlement::Metered {
                rail: "x402".to_string(),
                rail_response: Some(b"{\"requirements\":{}}".to_vec()),
                settlement_commit: Some(b"signed settlement commit bytes".to_vec()),
                rail_attestation: None,
            },
        };
        let line = serde_json::to_string(&rec).unwrap();
        assert!(
            !line.contains('\n'),
            "a record must serialize to a single JSONL line"
        );
        // The operator's per-call block is named `unverified_display` on the wire — never a bare
        // `receipt` — so no reader mistakes it for vouched data.
        assert!(
            line.contains("\"unverified_display\""),
            "the operator block must announce it is unverified: {line}"
        );
        assert!(
            !line.contains("\"receipt\""),
            "the wire must not carry a bare `receipt` key: {line}"
        );
        // Round-trips stably (Receipt isn't PartialEq, so compare the canonical serialization).
        let back: SpendLogRecord = serde_json::from_str(&line).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), line);
    }

    #[tokio::test]
    async fn empty_log_audits_self_consistent_with_records_zero() {
        // An empty log is NOT a clean bill of health — it re-derives self-consistent with a
        // records:0 signal and the completeness caveat, never a bare `consistent — 0 call(s)`.
        let verdict = audit_spend_log(
            &[],
            &[],
            &[],
            &["did:keri:Eroot".to_string()],
            0,
            None,
            None,
        )
        .await;
        match &verdict {
            AuditVerdict::Consistent(proof) => {
                assert_eq!(proof.calls(), 0);
                assert!(proof.head().is_none(), "an empty log pins no head");
            }
            other => panic!("empty log should be self-consistent, got {other:?}"),
        }
        let shown = verdict.to_string();
        assert!(shown.contains("completeness unproven"), "{shown}");
        assert!(
            !shown.starts_with("consistent —"),
            "no bare consistent: {shown}"
        );
    }

    #[test]
    fn non_metered_record_omits_rail_fields() {
        let rec = SpendLogRecord {
            call_commit: b"c".to_vec(),
            receipt: sample_receipt(),
            settlement: Settlement::Unmetered,
        };
        let json = serde_json::to_string(&rec).unwrap();
        assert!(
            !json.contains("rail_response") && !json.contains("settlement_commit"),
            "an unmetered call carries no rail/settlement artifacts: {json}"
        );
        let back: SpendLogRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), json);
    }

    #[test]
    fn spend_log_path_strips_scheme_and_stays_in_one_component() {
        let p = spend_log_path(Path::new("/repo"), "did:keri:EabC-_9");
        assert!(p.ends_with("spend-log/EabC-_9.jsonl"), "{p:?}");
        // a malformed delegation cannot escape the spend-log dir
        let evil = spend_log_path(Path::new("/repo"), "../../etc/passwd");
        assert!(!evil.to_string_lossy().contains(".."), "{evil:?}");
    }

    #[test]
    fn read_spend_log_parses_in_order_and_fails_closed_on_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.jsonl");
        let line = serde_json::to_string(&SpendLogRecord {
            call_commit: b"a".to_vec(),
            receipt: sample_receipt(),
            settlement: Settlement::Unmetered,
        })
        .unwrap();
        // two records + a blank line (ignored)
        std::fs::write(&path, format!("{line}\n\n{line}\n")).unwrap();
        assert_eq!(read_spend_log(&path).unwrap().len(), 2);
        // a corrupted/edited line fails closed, never silently drops a record
        std::fs::write(&path, format!("{line}\nnot json\n")).unwrap();
        assert!(read_spend_log(&path).is_err());

        // A pretty-printed (`jq .`) log — a record split across many lines — SPEAKS as a
        // not-one-line-JSON malformed-log, never raw serde noise or `tampered-proof`.
        let record: SpendLogRecord = serde_json::from_str(&line).unwrap();
        let pretty = serde_json::to_string_pretty(&record).unwrap();
        std::fs::write(&path, format!("{pretty}\n")).unwrap();
        let err = read_spend_log(&path).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("malformed-log"), "{msg}");
        assert!(
            msg.contains("not one-line JSON") || msg.contains("jq"),
            "{msg}"
        );
        assert!(
            !msg.contains("tampered"),
            "a read error must not read as tamper: {msg}"
        );

        // A crash-truncated final record — the last line cut off mid-object — SPEAKS as truncated.
        let half = &line[..line.len() / 2];
        std::fs::write(&path, format!("{line}\n{half}")).unwrap();
        let err = read_spend_log(&path).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("malformed-log") && msg.contains("truncated"),
            "{msg}"
        );
    }

    #[test]
    fn log_read_error_classification_distinguishes_the_causes() {
        // The typed classification: an unexpected-end on a NON-last
        // line is a multiline `jq .` record; on the LAST line it is a crash-truncated tail; a
        // value error is other corruption. All three are read errors, never `tampered-proof`.
        let eof = serde_json::from_str::<SpendLogRecord>("{").unwrap_err();
        assert!(matches!(
            LogReadError::classify(1, false, &eof),
            LogReadError::NotOneLineJson { record: 1 }
        ));
        assert!(matches!(
            LogReadError::classify(2, true, &eof),
            LogReadError::TruncatedRecord { record: 2 }
        ));
        let bad = serde_json::from_str::<SpendLogRecord>("not json").unwrap_err();
        assert!(matches!(
            LogReadError::classify(3, true, &bad),
            LogReadError::CorruptRecord { record: 3, .. }
        ));
    }

    #[test]
    fn commit_trailer_matches_the_token_exactly() {
        let commit =
            b"tree abc\n\ntools/settle\n\nAuths-Settle-Call:def\nAuths-Settle-Cents: 175\nAuths-Settle-Ref:ch_3MmlLrLkdIwHu7ix\nAuths-Settle-Cumulative:500\n";
        // Exact token match, with or without a space after the colon.
        assert_eq!(commit_trailer(commit, "Auths-Settle-Cents"), Some("175"));
        assert_eq!(commit_trailer(commit, "Auths-Settle-Call"), Some("def"));
        // The SIGNED payee reads back exactly — the counterparty the audit cross-checks against
        // the rail response's charge id.
        assert_eq!(
            commit_trailer(commit, "Auths-Settle-Ref"),
            Some("ch_3MmlLrLkdIwHu7ix")
        );
        // `Auths-Settle-Cents` must NOT match the longer `Auths-Settle-Cumulative` line.
        assert_eq!(
            commit_trailer(commit, "Auths-Settle-Cumulative"),
            Some("500")
        );
        // Absent token, or non-UTF-8, yields None.
        assert_eq!(
            commit_trailer(b"tree abc\n\ntools/call\n", "Auths-Settle-Cents"),
            None
        );
        assert_eq!(commit_trailer(&[0xff, 0xfe], "Auths-Settle-Cents"), None);
    }

    #[test]
    fn call_commit_binding_is_stable_and_distinguishes_calls() {
        // The binding is the hex SHA-256 of the call bytes: 64 hex chars, deterministic, and
        // different for different calls — so a settlement cannot be reused across calls.
        let a = call_commit_binding(b"call-A-commit-bytes");
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(a, call_commit_binding(b"call-A-commit-bytes"));
        assert_ne!(a, call_commit_binding(b"call-B-commit-bytes"));
    }
}
