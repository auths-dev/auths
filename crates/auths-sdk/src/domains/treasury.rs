//! Aggregate treasury cap — a parent-anchored quantitative ceiling across a set of
//! sub-delegations, with reallocation.
//!
//! `auths` ships a **per-delegation** quantitative cap (the AGT-4 usage ledger:
//! one credential SAID, one `calls:<N>` bound). A fund-of-agents needs the
//! *aggregate* dimension: a manager holds a parent cap and allots **slices** to
//! sub-agents, with the invariant `Σ(committed slices) ≤ parent_cap` enforced at
//! every allotment, and the budget **reallocatable** between sub-agents without
//! ever exceeding the parent.
//!
//! This module is the aggregate analogue of [`crate::domains::credentials::usage_ledger`]:
//! a verifier-held, repo-rooted record — a small JSON file under
//! `<repo>/treasury-ledger/<manager>.json`, written atomically (temp-write +
//! rename), keyed by a path-safe manager alias. Two invariants, both fail-closed:
//!
//! 1. **Aggregate cap** — an allotment that would push `Σ slices + amount` over the
//!    parent cap is refused [`Verdict::AggregateCapExceeded`]; the swarm's committed
//!    authority can never exceed the parent.
//! 2. **Reallocation is constant-sum** — moving `Δ` from slice A to slice B keeps
//!    `Σ` invariant, and is refused if A holds `< Δ` (pulling more than a slice holds
//!    would fabricate budget on the destination). A revoke frees a slice back to the
//!    free pool (`parent_cap − Σ live slices`), re-allocatable but never
//!    double-counted.
//!
//! Like the usage ledger, this is the stateful resolution layer (F.4): it remembers
//! across invocations, so it lives here, not in the pure (WASM-safe) verifier.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The repo-relative directory holding per-manager aggregate treasury records.
const TREASURY_LEDGER_DIR: &str = "treasury-ledger";

/// Failures of treasury bookkeeping (distinct from the *verdicts* below, which are
/// successful measurements of a refusal).
#[derive(Debug, Error)]
pub enum TreasuryError {
    /// No cap was established for this manager — `open` must run first.
    #[error("no treasury cap established for manager '{0}' — run `auths treasury open` first")]
    NotOpened(String),
    /// A cap already exists and cannot be re-opened with different terms.
    #[error("a treasury cap is already established for manager '{0}'")]
    AlreadyOpen(String),
    /// The manager alias is not a safe single-filename component.
    #[error("unsafe manager key for treasury ledger: '{0}'")]
    UnsafeKey(String),
    /// The named sub-agent has no slice under this manager.
    #[error("unknown sub-agent slice: '{0}'")]
    UnknownSlice(String),
    /// Reading/writing the ledger record failed.
    #[error("treasury ledger persistence failed: {0}")]
    Persistence(String),
}

/// One sub-agent's committed slice of the treasury.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Slice {
    /// The sub-agent's `did:keri:` (the slice key).
    pub agent_did: String,
    /// The committed amount (call-count units).
    pub amount: u64,
}

/// The persisted per-manager aggregate record.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct TreasuryRecord {
    /// The manager this record bounds (self-describing for audit).
    manager: String,
    /// The aggregate ceiling: `Σ slices` must never exceed this.
    parent_cap: u64,
    /// The live committed slices.
    slices: Vec<Slice>,
}

impl TreasuryRecord {
    fn committed(&self) -> u64 {
        self.slices.iter().map(|s| s.amount).sum()
    }
    fn slice_mut(&mut self, did: &str) -> Option<&mut Slice> {
        self.slices.iter_mut().find(|s| s.agent_did == did)
    }
}

/// The outcome of a treasury mutation — a measurement, not an error. The CLI maps
/// [`Verdict::status`] to the `--json` `data.status` field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The aggregate cap was established.
    Opened {
        /// The aggregate ceiling that was set.
        parent_cap: u64,
    },
    /// A slice was committed to a sub-agent within the cap.
    Allotted {
        /// The sub-agent the slice was committed to.
        agent_did: String,
        /// The committed amount.
        amount: u64,
    },
    /// A slice was moved between two sub-agents (constant-sum).
    Reallocated {
        /// The source sub-agent the budget was pulled from.
        from: String,
        /// The destination sub-agent the budget was fed to.
        to: String,
        /// The amount moved.
        amount: u64,
    },
    /// A sub-agent sub-delegated a child slice within its own holding.
    Subdelegated {
        /// The sub-agent doing the sub-delegation.
        parent: String,
        /// The child worker receiving the slice.
        child: String,
        /// The child slice amount.
        amount: u64,
    },
    /// A (revoked) sub-agent's slice was released back to the free pool.
    Reclaimed {
        /// The sub-agent whose slice was freed.
        agent_did: String,
        /// The amount returned to the free pool.
        freed: u64,
    },
    /// The sub-agent holds no slice to reclaim — idempotent, no double-count.
    NothingToReclaim,
    /// The aggregate cap (or a slice's holdings) would be breached — refused, no commit.
    AggregateCapExceeded {
        /// The aggregate ceiling.
        parent_cap: u64,
        /// The sum currently committed across live slices.
        committed: u64,
        /// The amount whose admission would have breached the cap.
        requested: u64,
    },
}

impl Verdict {
    /// The stable machine token surfaced as `data.status`.
    pub fn status(&self) -> &'static str {
        match self {
            Verdict::Opened { .. } => "opened",
            Verdict::Allotted { .. } => "allotted",
            Verdict::Reallocated { .. } => "reallocated",
            Verdict::Subdelegated { .. } => "subdelegated",
            Verdict::Reclaimed { .. } => "reclaimed",
            Verdict::NothingToReclaim => "nothing_to_reclaim",
            Verdict::AggregateCapExceeded { .. } => "aggregate_cap_exceeded",
        }
    }
}

/// A read-only view of the treasury for `status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TreasuryStatus {
    /// `"valid"` while `Σ slices ≤ parent_cap`, else `"aggregate_cap_exceeded"`.
    pub status: &'static str,
    /// The aggregate ceiling.
    pub parent_cap: u64,
    /// The sum committed across live slices (`Σ slices`).
    pub committed: u64,
    /// Budget not yet committed (`parent_cap − committed`), re-allocatable.
    pub free_pool: u64,
    /// The live committed slices.
    pub slices: Vec<Slice>,
}

/// The verifier's aggregate treasury ledger, rooted at a repo path (sibling of the
/// per-delegation usage ledger).
pub struct TreasuryLedger {
    dir: PathBuf,
}

impl TreasuryLedger {
    /// Open the ledger rooted at a repo path (e.g. `ctx.repo_path`).
    pub fn new(repo_path: &Path) -> Self {
        Self {
            dir: repo_path.join(TREASURY_LEDGER_DIR),
        }
    }

    fn record_path(&self, manager: &str) -> Result<PathBuf, TreasuryError> {
        Ok(self.dir.join(format!("{}.json", safe_key(manager)?)))
    }

    fn read(&self, manager: &str) -> Result<Option<TreasuryRecord>, TreasuryError> {
        let path = self.record_path(manager)?;
        match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|e| TreasuryError::Persistence(format!("record parse failed: {e}"))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(TreasuryError::Persistence(format!("read failed: {e}"))),
        }
    }

    fn write(&self, rec: &TreasuryRecord) -> Result<(), TreasuryError> {
        fs::create_dir_all(&self.dir)
            .map_err(|e| TreasuryError::Persistence(format!("mkdir failed: {e}")))?;
        let key = safe_key(&rec.manager)?;
        let path = self.dir.join(format!("{key}.json"));
        let body = serde_json::to_vec_pretty(rec)
            .map_err(|e| TreasuryError::Persistence(format!("encode failed: {e}")))?;
        // Atomic publish: temp-write then rename over the canonical path.
        let tmp = self.dir.join(format!(".{key}.tmp"));
        fs::write(&tmp, &body)
            .map_err(|e| TreasuryError::Persistence(format!("temp write failed: {e}")))?;
        fs::rename(&tmp, &path)
            .map_err(|e| TreasuryError::Persistence(format!("commit (rename) failed: {e}")))?;
        Ok(())
    }

    /// Establish the aggregate cap for a manager. Re-opening with the same cap and no
    /// allotments is idempotent; re-opening with different terms is refused.
    pub fn open(&self, manager: &str, parent_cap: u64) -> Result<Verdict, TreasuryError> {
        if let Some(existing) = self.read(manager)? {
            if existing.parent_cap == parent_cap && existing.slices.is_empty() {
                return Ok(Verdict::Opened { parent_cap });
            }
            return Err(TreasuryError::AlreadyOpen(manager.to_string()));
        }
        self.write(&TreasuryRecord {
            manager: manager.to_string(),
            parent_cap,
            slices: Vec::new(),
        })?;
        Ok(Verdict::Opened { parent_cap })
    }

    /// Commit a slice of `amount` to `agent_did`. Refused if `Σ + amount > parent_cap`.
    pub fn allot(
        &self,
        manager: &str,
        agent_did: &str,
        amount: u64,
    ) -> Result<Verdict, TreasuryError> {
        let mut rec = self
            .read(manager)?
            .ok_or_else(|| TreasuryError::NotOpened(manager.to_string()))?;
        let committed = rec.committed();
        if committed.saturating_add(amount) > rec.parent_cap {
            return Ok(Verdict::AggregateCapExceeded {
                parent_cap: rec.parent_cap,
                committed,
                requested: amount,
            });
        }
        match rec.slice_mut(agent_did) {
            Some(s) => s.amount += amount,
            None => rec.slices.push(Slice {
                agent_did: agent_did.to_string(),
                amount,
            }),
        }
        self.write(&rec)?;
        Ok(Verdict::Allotted {
            agent_did: agent_did.to_string(),
            amount,
        })
    }

    /// Move `amount` from slice `from` to slice `to` (constant-sum). Refused if `from`
    /// holds `< amount` — pulling more than a slice holds would fabricate budget on the
    /// destination and push `Σ` over the parent.
    pub fn reallocate(
        &self,
        manager: &str,
        from: &str,
        to: &str,
        amount: u64,
    ) -> Result<Verdict, TreasuryError> {
        let mut rec = self
            .read(manager)?
            .ok_or_else(|| TreasuryError::NotOpened(manager.to_string()))?;
        let held = rec
            .slice_mut(from)
            .ok_or_else(|| TreasuryError::UnknownSlice(from.to_string()))?
            .amount;
        if held < amount {
            return Ok(Verdict::AggregateCapExceeded {
                parent_cap: rec.parent_cap,
                committed: rec.committed(),
                requested: amount,
            });
        }
        if rec.slice_mut(to).is_none() {
            rec.slices.push(Slice {
                agent_did: to.to_string(),
                amount: 0,
            });
        }
        rec.slice_mut(from)
            .ok_or_else(|| TreasuryError::UnknownSlice(from.to_string()))?
            .amount -= amount;
        rec.slice_mut(to)
            .ok_or_else(|| TreasuryError::UnknownSlice(to.to_string()))?
            .amount += amount;
        self.write(&rec)?;
        Ok(Verdict::Reallocated {
            from: from.to_string(),
            to: to.to_string(),
            amount,
        })
    }

    /// Report the aggregate invariant, the free pool, and the live slices.
    pub fn status(&self, manager: &str) -> Result<TreasuryStatus, TreasuryError> {
        let rec = self
            .read(manager)?
            .ok_or_else(|| TreasuryError::NotOpened(manager.to_string()))?;
        let committed = rec.committed();
        Ok(TreasuryStatus {
            status: if committed <= rec.parent_cap {
                "valid"
            } else {
                "aggregate_cap_exceeded"
            },
            parent_cap: rec.parent_cap,
            committed,
            free_pool: rec.parent_cap.saturating_sub(committed),
            slices: rec.slices,
        })
    }

    /// Release a (revoked) sub-agent's slice back to the free pool. Removing the slice
    /// returns its amount to `parent_cap − Σ live slices`, re-allocatable. Idempotent: a
    /// second reclaim finds no slice and is a no-op — the freed budget can be recommitted
    /// but never double-counted.
    pub fn reclaim(&self, manager: &str, agent_did: &str) -> Result<Verdict, TreasuryError> {
        let mut rec = self
            .read(manager)?
            .ok_or_else(|| TreasuryError::NotOpened(manager.to_string()))?;
        match rec.slices.iter().position(|s| s.agent_did == agent_did) {
            Some(pos) => {
                let freed = rec.slices.remove(pos).amount;
                self.write(&rec)?;
                Ok(Verdict::Reclaimed {
                    agent_did: agent_did.to_string(),
                    freed,
                })
            }
            None => Ok(Verdict::NothingToReclaim),
        }
    }
}

/// Derive a path-safe single filename component from a manager alias/DID (mirrors the
/// `budget.rs` / usage-ledger safe-key discipline: strip a `did:keri:` prefix, then
/// require alphanumeric plus `-`/`_`).
fn safe_key(manager: &str) -> Result<String, TreasuryError> {
    let tail = manager.strip_prefix("did:keri:").unwrap_or(manager);
    let safe = !tail.is_empty()
        && tail != "."
        && tail != ".."
        && tail
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if !safe {
        return Err(TreasuryError::UnsafeKey(manager.to_string()));
    }
    Ok(tail.to_string())
}

// ── Thin free functions the CLI calls (one ledger op each) ────────────────────

/// Establish a manager's aggregate cap.
pub fn open(repo_path: &Path, manager: &str, parent_cap: u64) -> Result<Verdict, TreasuryError> {
    TreasuryLedger::new(repo_path).open(manager, parent_cap)
}
/// Commit a slice to a sub-agent within the aggregate cap.
pub fn allot(
    repo_path: &Path,
    manager: &str,
    agent_did: &str,
    amount: u64,
) -> Result<Verdict, TreasuryError> {
    TreasuryLedger::new(repo_path).allot(manager, agent_did, amount)
}
/// Move a slice between two sub-agents (constant-sum, refused on source underflow).
pub fn reallocate(
    repo_path: &Path,
    manager: &str,
    from: &str,
    to: &str,
    amount: u64,
) -> Result<Verdict, TreasuryError> {
    TreasuryLedger::new(repo_path).reallocate(manager, from, to, amount)
}
/// Read the aggregate invariant + free pool + slices.
pub fn status(repo_path: &Path, manager: &str) -> Result<TreasuryStatus, TreasuryError> {
    TreasuryLedger::new(repo_path).status(manager)
}
/// Release a revoked sub-agent's slice back to the free pool (idempotent).
pub fn reclaim(repo_path: &Path, manager: &str, agent_did: &str) -> Result<Verdict, TreasuryError> {
    TreasuryLedger::new(repo_path).reclaim(manager, agent_did)
}

/// The repo-relative directory holding per-sub-agent inbound (earn) P&L credits.
const CREDIT_LEDGER_DIR: &str = "credit-ledger";

/// The outcome of crediting an inbound x402 settlement to a sub-agent's P&L.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreditVerdict {
    /// The recorded settlement amount (in cents) was credited inbound.
    Credited {
        /// The cents extracted from the recorded settlement and credited.
        cents: u64,
    },
    /// A claimed amount did not match the recorded settlement — rejected, no credit.
    CreditMismatch {
        /// The amount the recorded settlement actually pays (cents).
        recorded_cents: u64,
        /// The (padded) amount that was claimed.
        claimed_cents: u64,
    },
}

impl CreditVerdict {
    /// The stable machine token surfaced as `data.status`.
    pub fn status(&self) -> &'static str {
        match self {
            CreditVerdict::Credited { .. } => "credited",
            CreditVerdict::CreditMismatch { .. } => "credit_mismatch",
        }
    }
    /// The cents credited (0 for a rejected mismatch).
    pub fn credited_cents(&self) -> u64 {
        match self {
            CreditVerdict::Credited { cents } => *cents,
            CreditVerdict::CreditMismatch { .. } => 0,
        }
    }
}

/// Extract the paid amount (atomic USDC → cents) from a **recorded** x402
/// SettlementResponse and credit it inbound to a sub-agent's receipted P&L
/// (`direction=inbound`, `rail=x402`). A claimed amount that does not match the
/// recorded settlement is rejected — a padded earn cannot pump a sub-agent's P&L.
/// Hermetic: reads a recorded fixture, never a live wallet/network.
pub fn credit(
    repo_path: &Path,
    agent_did: &str,
    settlement_path: &Path,
    claim_cents: Option<u64>,
) -> Result<CreditVerdict, TreasuryError> {
    let bytes = fs::read(settlement_path)
        .map_err(|e| TreasuryError::Persistence(format!("settlement read failed: {e}")))?;
    let v: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| TreasuryError::Persistence(format!("settlement parse failed: {e}")))?;
    let decimals = v
        .get("decimals")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(6);
    let atomic_str = v
        .pointer("/settlement/amountAtomic")
        .or_else(|| v.pointer("/requirements/maxAmountRequired"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| TreasuryError::Persistence("settlement missing amountAtomic".into()))?;
    let atomic: u128 = atomic_str.parse().map_err(|_| {
        TreasuryError::Persistence(format!("non-numeric settlement amount '{atomic_str}'"))
    })?;
    // atomic USDC at `decimals` places → cents (2 places): atomic * 100 / 10^decimals. `decimals`
    // and `atomic` come from the settlement payload, so the scale, the multiply, and the narrowing to
    // cents are all checked — an out-of-range amount is rejected, never silently truncated to a
    // smaller credit.
    let scale = u32::try_from(decimals)
        .ok()
        .and_then(|d| 10u128.checked_pow(d))
        .ok_or_else(|| {
            TreasuryError::Persistence(format!("settlement decimals {decimals} out of range"))
        })?;
    let cents = atomic
        .checked_mul(100)
        .map(|scaled| scaled / scale)
        .and_then(|c| u64::try_from(c).ok())
        .ok_or_else(|| {
            TreasuryError::Persistence(format!("settlement amount '{atomic_str}' out of range"))
        })?;

    if let Some(claimed) = claim_cents
        && claimed != cents
    {
        return Ok(CreditVerdict::CreditMismatch {
            recorded_cents: cents,
            claimed_cents: claimed,
        });
    }

    // Persist the cumulative inbound credit for the sub-agent (the P&L credit side).
    let dir = repo_path.join(CREDIT_LEDGER_DIR);
    let key = safe_key(agent_did)?;
    fs::create_dir_all(&dir)
        .map_err(|e| TreasuryError::Persistence(format!("mkdir failed: {e}")))?;
    let path = dir.join(format!("{key}.json"));
    let prior = fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|j| j.get("credited_cents").and_then(serde_json::Value::as_u64))
        .unwrap_or(0);
    let body = serde_json::to_vec_pretty(&serde_json::json!({
        "agent_did": agent_did,
        "credited_cents": prior.saturating_add(cents),
        "rail": "x402",
        "direction": "inbound",
    }))
    .map_err(|e| TreasuryError::Persistence(format!("encode failed: {e}")))?;
    let tmp = dir.join(format!(".{key}.tmp"));
    fs::write(&tmp, &body)
        .map_err(|e| TreasuryError::Persistence(format!("temp write failed: {e}")))?;
    fs::rename(&tmp, &path)
        .map_err(|e| TreasuryError::Persistence(format!("commit (rename) failed: {e}")))?;
    Ok(CreditVerdict::Credited { cents })
}

/// The repo-relative directory holding per-sub-agent sub-delegation (depth) records.
const SUBDELEGATION_LEDGER_DIR: &str = "subdelegation-ledger";

/// A parent sub-agent's sub-delegated child slices (kept beside the aggregate ledger
/// so the top-level [`Slice`] shape is unchanged).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct SubdelRecord {
    parent: String,
    children: Vec<Slice>,
}

/// A sub-agent (`parent_did`) sub-delegates a child a slice within its own holding.
/// The transitive invariant: `Σ(child slices) ≤ the parent's own slice`. Refused
/// `aggregate_cap_exceeded` if the child would push the children's sum over what the
/// parent holds — a mid-swarm key-holder cannot mint budget it was never given, at
/// any depth. The parent's own slice is read from the manager's aggregate ledger.
pub fn subdelegate(
    repo_path: &Path,
    manager: &str,
    parent_did: &str,
    child_did: &str,
    amount: u64,
) -> Result<Verdict, TreasuryError> {
    let parent_held = TreasuryLedger::new(repo_path)
        .status(manager)?
        .slices
        .into_iter()
        .find(|s| s.agent_did == parent_did)
        .ok_or_else(|| TreasuryError::UnknownSlice(parent_did.to_string()))?
        .amount;

    let dir = repo_path.join(SUBDELEGATION_LEDGER_DIR);
    let key = safe_key(parent_did)?;
    let path = dir.join(format!("{key}.json"));
    let mut rec: SubdelRecord = match fs::read(&path) {
        Ok(b) => serde_json::from_slice(&b)
            .map_err(|e| TreasuryError::Persistence(format!("subdel parse failed: {e}")))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => SubdelRecord {
            parent: parent_did.to_string(),
            children: Vec::new(),
        },
        Err(e) => {
            return Err(TreasuryError::Persistence(format!(
                "subdel read failed: {e}"
            )));
        }
    };
    let children_sum: u64 = rec
        .children
        .iter()
        .fold(0u64, |acc, c| acc.saturating_add(c.amount));
    if children_sum.saturating_add(amount) > parent_held {
        return Ok(Verdict::AggregateCapExceeded {
            parent_cap: parent_held,
            committed: children_sum,
            requested: amount,
        });
    }
    rec.children.push(Slice {
        agent_did: child_did.to_string(),
        amount,
    });
    fs::create_dir_all(&dir)
        .map_err(|e| TreasuryError::Persistence(format!("mkdir failed: {e}")))?;
    let body = serde_json::to_vec_pretty(&rec)
        .map_err(|e| TreasuryError::Persistence(format!("encode failed: {e}")))?;
    let tmp = dir.join(format!(".{key}.tmp"));
    fs::write(&tmp, &body)
        .map_err(|e| TreasuryError::Persistence(format!("temp write failed: {e}")))?;
    fs::rename(&tmp, &path)
        .map_err(|e| TreasuryError::Persistence(format!("commit (rename) failed: {e}")))?;
    Ok(Verdict::Subdelegated {
        parent: parent_did.to_string(),
        child: child_did.to_string(),
        amount,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn led() -> (tempfile::TempDir, TreasuryLedger) {
        let dir = tempfile::tempdir().unwrap();
        let l = TreasuryLedger::new(dir.path());
        (dir, l)
    }

    #[test]
    fn allotments_within_cap_hold_and_overflow_is_refused() {
        let (_d, l) = led();
        l.open("manager", 10).unwrap();
        for (a, n) in [("flip", 4), ("x402", 1), ("yield", 3), ("arb", 2)] {
            assert!(matches!(
                l.allot("manager", a, n).unwrap(),
                Verdict::Allotted { .. }
            ));
        }
        let st = l.status("manager").unwrap();
        assert_eq!(st.committed, 10);
        assert_eq!(st.free_pool, 0);
        assert_eq!(st.status, "valid");
        // A fifth slice over the cap is refused, no commit.
        assert!(matches!(
            l.allot("manager", "extra", 1).unwrap(),
            Verdict::AggregateCapExceeded { .. }
        ));
        assert_eq!(l.status("manager").unwrap().committed, 10);
    }

    #[test]
    fn an_allotment_whose_sum_would_wrap_past_u64_max_is_refused() {
        let (_d, l) = led();
        l.open("manager", 100).unwrap();
        assert!(matches!(
            l.allot("manager", "a", 50).unwrap(),
            Verdict::Allotted { .. }
        ));
        // 50 + (u64::MAX - 10) exceeds u64::MAX; an unchecked add would wrap to a small sum that
        // slips under the cap, so this allotment must be refused.
        assert!(matches!(
            l.allot("manager", "b", u64::MAX - 10).unwrap(),
            Verdict::AggregateCapExceeded { .. }
        ));
        assert_eq!(l.status("manager").unwrap().committed, 50);
    }

    #[test]
    fn reallocation_is_constant_sum_and_underflow_is_refused() {
        let (_d, l) = led();
        l.open("m", 10).unwrap();
        l.allot("m", "flip", 4).unwrap();
        l.allot("m", "yield", 3).unwrap();
        l.allot("m", "arb", 2).unwrap();
        // Move 2 yield→flip: flip 4→6, yield 3→1, Σ unchanged.
        assert!(matches!(
            l.reallocate("m", "yield", "flip", 2).unwrap(),
            Verdict::Reallocated { .. }
        ));
        let st = l.status("m").unwrap();
        assert_eq!(st.committed, 9);
        assert_eq!(
            st.slices
                .iter()
                .find(|s| s.agent_did == "flip")
                .unwrap()
                .amount,
            6
        );
        // Pull 4 from arb (holds 2) — would fabricate budget; refused, no commit.
        assert!(matches!(
            l.reallocate("m", "arb", "flip", 4).unwrap(),
            Verdict::AggregateCapExceeded { .. }
        ));
        assert_eq!(
            l.status("m")
                .unwrap()
                .slices
                .iter()
                .find(|s| s.agent_did == "flip")
                .unwrap()
                .amount,
            6
        );
    }

    #[test]
    fn unsafe_manager_key_is_refused() {
        let (_d, l) = led();
        assert!(matches!(
            l.open("../escape", 10),
            Err(TreasuryError::UnsafeKey(_))
        ));
    }

    #[test]
    fn x402_credit_extracts_cents_and_rejects_a_padded_claim() {
        let dir = tempfile::tempdir().unwrap();
        let settlement = dir.path().join("s.json");
        // 2.50 USDC = 2_500_000 atomic (6 decimals) = 250 cents.
        std::fs::write(
            &settlement,
            br#"{"decimals":6,"settlement":{"amountAtomic":"2500000"}}"#,
        )
        .unwrap();
        let v = credit(dir.path(), "did:keri:Ex402", &settlement, None).unwrap();
        assert_eq!(v, CreditVerdict::Credited { cents: 250 });
        // A padded claim (≠ the recorded settlement) is rejected, no credit.
        let v = credit(dir.path(), "did:keri:Ex402", &settlement, Some(99999)).unwrap();
        assert!(matches!(
            v,
            CreditVerdict::CreditMismatch {
                recorded_cents: 250,
                ..
            }
        ));
    }

    #[test]
    fn subdelegation_within_parent_holding_holds_and_overflow_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let l = TreasuryLedger::new(dir.path());
        l.open("m", 10).unwrap();
        l.allot("m", "flip", 4).unwrap();
        // A child of 2 ≤ flip's slice of 4 → sub-delegated.
        assert!(matches!(
            subdelegate(dir.path(), "m", "flip", "child1", 2).unwrap(),
            Verdict::Subdelegated { .. }
        ));
        // A child of 3 (Σ children 2+3=5 > flip's 4) → refused, no commit.
        assert!(matches!(
            subdelegate(dir.path(), "m", "flip", "child2", 3).unwrap(),
            Verdict::AggregateCapExceeded { .. }
        ));
        // The first child still stands (the refusal did not corrupt the record).
        assert!(matches!(
            subdelegate(dir.path(), "m", "flip", "child3", 2).unwrap(),
            Verdict::Subdelegated { .. }
        ));
    }

    #[test]
    fn reclaim_frees_a_slice_to_the_pool_and_is_idempotent() {
        let (_d, l) = led();
        l.open("m", 10).unwrap();
        l.allot("m", "flip", 4).unwrap();
        l.allot("m", "arb", 2).unwrap();
        assert_eq!(l.status("m").unwrap().free_pool, 4);
        // Reclaim arb's slice → the free pool rises by 2, committed drops to 4.
        assert!(matches!(
            l.reclaim("m", "arb").unwrap(),
            Verdict::Reclaimed { freed: 2, .. }
        ));
        let st = l.status("m").unwrap();
        assert_eq!(st.committed, 4);
        assert_eq!(st.free_pool, 6);
        // A second reclaim is a no-op — the freed budget is never double-counted.
        assert!(matches!(
            l.reclaim("m", "arb").unwrap(),
            Verdict::NothingToReclaim
        ));
        assert_eq!(l.status("m").unwrap().free_pool, 6);
    }
}
