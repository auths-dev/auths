//! The cross-rail budget engine (D8) — one quantitative cap, un-exceedable across a
//! session *and across rails*, by pre-authorization against a two-part counter.
//!
//! ## Why this exists (and what it supersedes)
//!
//! The former `SessionLedger` was a gateway-held, in-RAM per-session tally: it summed
//! every paid call against one undifferentiated counter. That is enough to make
//! the verdict *sequence* look right (in-budget calls pass, the cap-crossing one is
//! refused), but it cannot express the D8 property the product is sold on:
//!
//! - the counter is the **verifier-held** monotonic SETTLED high-water total keyed to
//!   the **agent delegation** (not a gateway RAM tally, not per-credential, not
//!   per-rail), so a crashed-and-restored gateway that reloads a stale snapshot and
//!   tries to settle *below* the recorded high-water is refused
//!   [`crate::Verdict::UsageCounterRolledBack`] — the same anti-replay monotonicity AGT-4's
//!   `usage_ledger.rs` gives a call-count cap, here in cents;
//! - spend on **two different payment rails** sums into that **one** counter, so a
//!   call that would reserve past the cap *across* rails is refused even when a
//!   per-rail-siloed budget would each still read in-budget (the moat);
//! - enforcement is **pre-authorization**: before the rail is touched the call
//!   RESERVES its ceiling as a transient hold; only if `available = cap − settled −
//!   Σ(holds)` admits the hold does the call proceed; on the response the *actual* is
//!   SETTLED into the monotonic total and the **slack is released**.
//!
//! So this module is the D8 budget engine; `SessionLedger` is the v0 it replaces for
//! the paid path. The two-part split is the whole point: **monotonicity applies to
//! settled only**; *reserved* is the transient auth-hold, so the two never conflict.
//!
//! ## The two parts
//!
//! 1. **SETTLED** — [`SettledCounter`]: a verifier-held monotonic high-water total in
//!    cents, persisted atomically (temp-write + rename) under the same repo the
//!    verifier replays the KELs from, keyed by the agent delegation's identifier. It
//!    only ever rises; a settle of a *lower* cumulative is a rollback and is refused.
//!    This mirrors `auths-sdk`'s `usage_ledger.rs` mechanism exactly (the AGT-4 reuse
//!    D8 calls for), in cents rather than a call count.
//! 2. **RESERVED** — [`ReservedHolds`]: a transient in-memory set of active holds. A
//!    hold is taken before the rail is touched and dropped (released) on settle, or
//!    expires if the call never returns. `available = cap − settled − Σ(holds)`.
//!
//! ## Checkpoint-anchoring (the durability layer) — PARKED
//!
//! D8's full durability story checkpoint-anchors the settled total's digest to the
//! chain periodically (every N calls / $X / T), so the running total is tamper-evident
//! and offline-verifiable *without* a per-call chain write. That anchoring is a
//! follow-on layer: the *prevention* this probe tests (cross-rail un-exceedability +
//! reserve/settle/release + rollback refusal) is fully built here and does not depend
//! on it. The settled digest [`SettledCounter::digest`] is exposed so a checkpointer
//! can anchor it, but the periodic anchor + the on-mismatch halt/revoke/alarm is not
//! wired in this cycle. **Failure bound:** until anchoring lands, a counter-integrity
//! failure (a compromised or stale-snapshot-restored gateway) can roll the settled
//! total back to the last *persisted* high-water; the monotonic ledger refuses a
//! settle below it, so the uncaught-overspend window is bounded by how stale a
//! reloaded snapshot can be — D8 pins this to ≤ one checkpoint interval once anchoring
//! lands (detection ≠ reversal).

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::money::{Actual, Ceiling, Cents};

/// The repo-relative directory holding the per-delegation settled-cents high-water
/// records — the verifier-held counter, alongside the KELs/registry the verifier
/// replays (the same placement `usage_ledger.rs` uses for its per-credential marks).
const BUDGET_LEDGER_DIR: &str = "budget-ledger";

/// Errors from the cross-rail budget engine that abort accounting before a verdict
/// (could-not-measure, not a fail-closed refusal). Reserve/settle *refusals* are
/// values ([`ReserveOutcome`] / [`SettleOutcome`]), not errors.
#[derive(Debug, thiserror::Error)]
pub enum BudgetError {
    #[error("settled-counter persistence failed: {0}")]
    Persistence(String),
    #[error("refusing unsafe delegation key for the settled counter: {0}")]
    UnsafeKey(String),
}

/// The verifier-held monotonic SETTLED counter for one agent delegation, in cents.
///
/// The high-water mark only ever rises. A settle of a cumulative total at or above the
/// mark advances it (atomically); a settle *below* it is a rollback ([`SettleOutcome::
/// RolledBack`]) — a replayed/stale total that the monotonic counter refuses, exactly
/// as AGT-4's `usage_ledger.rs` refuses a replayed lower call count. Persisted under
/// `<repo>/budget-ledger/<key>.json`.
#[derive(Debug, Clone)]
pub struct SettledCounter {
    /// `<repo>/budget-ledger` — created on first write.
    dir: PathBuf,
    /// The delegation key this counter is bound to (a filesystem-safe id derived from
    /// the agent delegation's identifier — NOT per-credential, NOT per-rail).
    key: String,
}

/// The persisted per-delegation settled-cents high-water record (self-describing for
/// audit, mirroring `usage_ledger.rs`'s `UsageRecord`).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SettledRecord {
    /// The agent-delegation key this record bounds.
    delegation: String,
    /// The highest cumulative cents this verifier has ever settled for the delegation.
    /// The on-disk ledger value is a plain `u64`; it is wrapped into [`Cents`] at the
    /// read boundary and unwrapped at the write boundary.
    settled_high_water_cents: u64,
}

/// The outcome of settling an actual cost into the monotonic counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettleOutcome {
    /// The cumulative total advanced (or held steady) — the new monotonic high-water.
    Advanced { new_settled_cents: Cents },
    /// The presented cumulative total was *below* the recorded high-water: a
    /// replayed/stale settled total. Refused so a crashed-and-restored gateway cannot
    /// roll the spend back (the D8 rollback guard → `usage-counter-rolled-back`).
    RolledBack {
        presented_cents: Cents,
        high_water_cents: Cents,
    },
}

impl SettledCounter {
    /// Open the settled counter at a located [`CounterRef`] — the verifier's registry path plus a
    /// validated [`CounterKey`]. Infallible: the key already carries its proof, so a counter can
    /// only be opened at a location derived ONE way from an agent delegation (never from a sentinel
    /// or an arbitrary string). Build a [`CounterRef`] with [`CounterRef::for_agent`].
    fn at(registry: &Path, key: CounterKey) -> Self {
        Self {
            dir: registry.join(BUDGET_LEDGER_DIR),
            key: key.into_string(),
        }
    }

    /// The current settled high-water for this delegation (zero if unseen).
    pub fn settled_cents(&self) -> Result<Cents, BudgetError> {
        Ok(self.read_high_water()?.unwrap_or(Cents::ZERO))
    }

    fn record_path(&self) -> PathBuf {
        self.dir.join(format!("{}.json", self.key))
    }

    fn read_high_water(&self) -> Result<Option<Cents>, BudgetError> {
        let path = self.record_path();
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(BudgetError::Persistence(format!("read {path:?}: {e}"))),
        };
        let record: SettledRecord = serde_json::from_slice(&bytes)
            .map_err(|e| BudgetError::Persistence(format!("parse {path:?}: {e}")))?;
        // The on-disk ledger value is a plain `u64` — wrap it into Cents at this read boundary.
        Ok(Some(Cents::new(record.settled_high_water_cents)))
    }

    /// Atomically publish a new high-water mark (temp-write + rename), exactly the
    /// crash-safe publish `usage_ledger.rs` uses: a concurrent reader sees either the
    /// old record or the complete new one, never a half-written mark.
    fn write_high_water(&self, cents: Cents) -> Result<(), BudgetError> {
        fs::create_dir_all(&self.dir)
            .map_err(|e| BudgetError::Persistence(format!("mkdir {:?}: {e}", self.dir)))?;
        let record = SettledRecord {
            delegation: self.key.clone(),
            // The on-disk ledger value is a plain `u64` — unwrap Cents at this write boundary.
            settled_high_water_cents: cents.get(),
        };
        let body = serde_json::to_vec_pretty(&record)
            .map_err(|e| BudgetError::Persistence(format!("encode: {e}")))?;
        let tmp = self.dir.join(format!(".{}.tmp", self.key));
        fs::write(&tmp, &body)
            .map_err(|e| BudgetError::Persistence(format!("temp write {tmp:?}: {e}")))?;
        fs::rename(&tmp, self.record_path())
            .map_err(|e| BudgetError::Persistence(format!("commit (rename): {e}")))?;
        Ok(())
    }

    /// Settle a new cumulative SETTLED total into the monotonic counter.
    ///
    /// `new_cumulative_cents` is the running cross-rail total *after* this call's
    /// actual cost is added. The single monotonicity decision point:
    ///
    /// - `new_cumulative < high_water` → [`SettleOutcome::RolledBack`] (the counter is
    ///   NOT lowered; the rollback is refused and the high-water is left untouched);
    /// - otherwise advance the high-water to `new_cumulative` and admit.
    ///
    /// The caller is responsible for the cap/reservation check *before* the rail is
    /// touched (see [`available`]); this method only enforces monotonicity on settle.
    pub fn settle(&self, new_cumulative_cents: Cents) -> Result<SettleOutcome, BudgetError> {
        if let Some(mark) = self.read_high_water()?
            && new_cumulative_cents < mark
        {
            return Ok(SettleOutcome::RolledBack {
                presented_cents: new_cumulative_cents,
                high_water_cents: mark,
            });
        }
        self.write_high_water(new_cumulative_cents)?;
        Ok(SettleOutcome::Advanced {
            new_settled_cents: new_cumulative_cents,
        })
    }

    /// The settled total's digest — the tamper-evident value a checkpointer anchors to
    /// the chain periodically (D8). Built over the canonical record so a stranger
    /// can re-derive it from the persisted counter alone. (The periodic *anchoring* is
    /// the parked follow-on; this exposes the digest the anchor would carry.)
    pub fn digest(&self) -> Result<String, BudgetError> {
        let cents = self.settled_cents()?;
        let mut h = Sha256::new();
        h.update(self.key.as_bytes());
        h.update(b":");
        // The digest is built over the raw cent count — unwrap at this byte boundary.
        h.update(cents.get().to_le_bytes());
        Ok(hex_lower(&h.finalize()))
    }
}

/// A transient pre-authorization hold: cents reserved against `available` before the
/// rail is touched, released on settle (or on expiry if the call never returns).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hold {
    /// An opaque id so a settle/release targets the right hold.
    pub id: u64,
    /// The ceiling reserved (the call's known cost, or its metered ceiling).
    pub ceiling_cents: Ceiling,
}

/// The transient set of active RESERVED holds for one session. Pure in-memory — a hold
/// is taken before a paid call and dropped on settle/expiry; nothing here is durable
/// (only the SETTLED counter is). `Σ(active holds)` is the second term of `available`.
#[derive(Debug, Clone, Default)]
pub struct ReservedHolds {
    holds: Vec<Hold>,
    next_id: u64,
}

impl ReservedHolds {
    /// A fresh, empty hold set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Total cents currently held (the `Σ(active holds)` term of `available`).
    pub fn reserved_cents(&self) -> Cents {
        self.holds.iter().fold(Cents::ZERO, |acc, h| {
            acc.saturating_add(h.ceiling_cents.cents())
        })
    }

    /// Take a hold for `ceiling` (the caller must have checked `available`
    /// first). Returns the hold so the caller can settle/release it.
    pub fn reserve(&mut self, ceiling: Ceiling) -> Hold {
        let hold = Hold {
            id: self.next_id,
            ceiling_cents: ceiling,
        };
        self.next_id = self.next_id.wrapping_add(1);
        self.holds.push(hold);
        hold
    }

    /// Release a hold (on settle, or on expiry if the call never returned). Releasing
    /// the slack means the difference between the ceiling and the actual is NOT
    /// permanently consumed — a later in-budget call is not starved by an
    /// over-reserved earlier one. Idempotent: releasing an unknown id is a no-op.
    pub fn release(&mut self, hold: Hold) {
        self.holds.retain(|h| h.id != hold.id);
    }

    /// Number of active holds (for tests/observability).
    pub fn active(&self) -> usize {
        self.holds.len()
    }
}

/// `available = cap − settled − Σ(active holds)`, saturating at 0 — the cents this
/// delegation may still RESERVE. The cross-rail invariant: one `cap`, one `settled`
/// (summed across rails), one holds set.
pub fn available(cap_cents: Cents, settled_cents: Cents, reserved_cents: Cents) -> Cents {
    Cents::new(
        cap_cents
            .get()
            .saturating_sub(settled_cents.get())
            .saturating_sub(reserved_cents.get()),
    )
}

/// The outcome of pre-authorizing (reserving) a paid call against the cross-rail
/// budget, *before* the rail is touched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReserveOutcome {
    /// The reservation fits within `available` — the hold is taken and the call may
    /// proceed to the rail.
    Reserved { hold: Hold, available_after: Cents },
    /// The reservation would push `settled + Σ(holds) + ceiling` past the cap —
    /// refused BEFORE the rail is touched (the metered downstream is never charged).
    /// Carries the cap and the would-be cross-rail total for the verdict.
    Refused {
        cap_cents: Cents,
        would_be_cents: Cents,
    },
}

/// When the in-memory authoritative SETTLED total is flushed durably to disk.
///
/// The live budget holds the settled high-water in memory (read once at open, advanced on
/// each settle). `FlushPolicy` governs how often that authoritative value is persisted — the
/// `fs::rename` that `verify-spend` later reads. It is the ONE knob that trades per-call
/// durable-write cost against the crash-overspend window.
#[derive(Debug, Clone, Copy)]
pub enum FlushPolicy {
    /// Persist on EVERY settle (crash window = 0 — full D8 overspend safety). The default,
    /// and the only policy that preserves the exact durability the disk-authoritative
    /// counter gave before: a crashed-and-restored gateway can never re-grant settled spend.
    EverySettle,
    /// Group-commit: persist at most once per `every_n` settles (and always on clean
    /// shutdown via `Drop`). Removes the per-call `rename` from the hot path at the price of
    /// a BOUNDED crash-overspend window — after an unclean crash the persisted high-water can
    /// lag the true settled total by up to `every_n` un-flushed settles, which a restarted
    /// gateway could re-grant. Opt-in only; the operator accepts the window. This is the same
    /// bounded-window tradeoff the module header documents for the parked checkpoint layer.
    GroupCommit { every_n: u32 },
}

/// The cross-rail budget for one agent delegation across one session: the durable
/// SETTLED counter + the transient RESERVED holds, enforcing ONE cap across all rails
/// by pre-authorization. This is the D8 engine the gate drives per paid call.
///
/// The settled high-water is held in memory (`cached_settled`, seeded once from disk at
/// open) and is authoritative for reserve/settle decisions, so the hot path never re-reads
/// disk to know the total. It is persisted per [`FlushPolicy`]. Not `Clone`: a session owns
/// exactly one budget (the gateway holds it behind `Arc<Mutex<…>>`), and duplicating the
/// authoritative in-memory total would let two owners' blind persists race the high-water.
#[derive(Debug)]
pub struct CrossRailBudget {
    cap_cents: Cents,
    settled: SettledCounter,
    holds: ReservedHolds,
    /// The authoritative in-memory settled high-water (seeded from disk at open, advanced on
    /// settle). Reserve/settle read THIS, not disk — monotonic within the session's lifetime.
    cached_settled: Cents,
    flush: FlushPolicy,
    /// Settles since the last durable flush (drives [`FlushPolicy::GroupCommit`]).
    unflushed: u32,
}

impl CrossRailBudget {
    /// The cap, in cents.
    pub fn cap_cents(&self) -> Cents {
        self.cap_cents
    }

    /// The current SETTLED total (summed across all rails) — the authoritative in-memory
    /// high-water, which reserve/settle also use.
    pub fn settled_cents(&self) -> Result<Cents, BudgetError> {
        Ok(self.cached_settled)
    }

    /// `Σ(active holds)` — the transient reserved cents.
    pub fn reserved_cents(&self) -> Cents {
        self.holds.reserved_cents()
    }

    /// `available = cap − settled − Σ(holds)`.
    pub fn available_cents(&self) -> Result<Cents, BudgetError> {
        Ok(available(
            self.cap_cents,
            self.cached_settled,
            self.holds.reserved_cents(),
        ))
    }

    /// The settled total's checkpoint digest (the value a periodic anchor carries).
    pub fn settled_digest(&self) -> Result<String, BudgetError> {
        self.settled.digest()
    }

    /// PRE-AUTHORIZE a paid call: reserve `ceiling_cents` against `available` BEFORE
    /// the rail is touched. If the reservation would push the cross-rail total past the
    /// cap it is [`ReserveOutcome::Refused`] (and no hold is taken — the rail is never
    /// touched); otherwise the hold is taken and returned in [`ReserveOutcome::
    /// Reserved`]. This is the cap-enforcement boundary — refusing here is the
    /// `usage-cap-exceeded` the gate surfaces before the downstream is invoked.
    pub fn reserve(&mut self, ceiling: Ceiling) -> Result<ReserveOutcome, BudgetError> {
        let settled = self.cached_settled;
        let reserved = self.holds.reserved_cents();
        let would_be = settled
            .saturating_add(reserved)
            .saturating_add(ceiling.cents());
        if would_be > self.cap_cents {
            return Ok(ReserveOutcome::Refused {
                cap_cents: self.cap_cents,
                would_be_cents: would_be,
            });
        }
        let hold = self.holds.reserve(ceiling);
        Ok(ReserveOutcome::Reserved {
            hold,
            available_after: available(self.cap_cents, settled, self.holds.reserved_cents()),
        })
    }

    /// SETTLE a held call's ACTUAL cost: release the hold (returning the slack between
    /// the reserved ceiling and the actual to `available`), advance the authoritative
    /// in-memory SETTLED total by `actual_cents`, and persist per [`FlushPolicy`]. The hold
    /// is released REGARDLESS of the flush outcome so a persist error does not strand the
    /// reservation. The in-memory total only ever rises (`actual >= 0`), so a live settle
    /// always [`SettleOutcome::Advanced`]s; the monotonic rollback guard governs *resume*
    /// (a fresh open re-reading the persisted high-water), enforced by [`SettledCounter`].
    pub fn settle(&mut self, hold: Hold, actual: Actual) -> Result<SettleOutcome, BudgetError> {
        self.holds.release(hold);
        let new_cumulative = self.cached_settled.saturating_add(actual.cents());
        self.cached_settled = new_cumulative;
        self.maybe_flush()?;
        Ok(SettleOutcome::Advanced {
            new_settled_cents: new_cumulative,
        })
    }

    /// Persist the authoritative in-memory high-water per the flush policy.
    fn maybe_flush(&mut self) -> Result<(), BudgetError> {
        let should_flush = match self.flush {
            FlushPolicy::EverySettle => true,
            FlushPolicy::GroupCommit { every_n } => {
                self.unflushed = self.unflushed.saturating_add(1);
                self.unflushed >= every_n.max(1)
            }
        };
        if should_flush {
            self.flush_now()?;
        }
        Ok(())
    }

    /// Blind-persist the authoritative in-memory high-water (a temp-write + `rename`). Safe
    /// because `cached_settled` is monotonic within the session and this budget is the sole
    /// writer of its counter file; the on-disk value it publishes is exactly what
    /// `verify-spend` re-derives.
    fn flush_now(&mut self) -> Result<(), BudgetError> {
        self.settled.write_high_water(self.cached_settled)?;
        self.unflushed = 0;
        Ok(())
    }

    /// Force a durable flush of the authoritative in-memory high-water (e.g. at a checkpoint
    /// boundary). A no-op's cost under [`FlushPolicy::EverySettle`] since nothing is pending.
    pub fn flush(&mut self) -> Result<(), BudgetError> {
        self.flush_now()
    }

    /// Release a hold WITHOUT settling — the auth-hold expiry path for a call that
    /// never returned. The reserved cents are returned to `available`; nothing is added
    /// to the monotonic settled total (the rail was never charged).
    pub fn expire(&mut self, hold: Hold) {
        self.holds.release(hold);
    }
}

impl Drop for CrossRailBudget {
    /// Flush any un-flushed group-committed settles on clean shutdown, so a graceful exit
    /// never loses settled spend. Monotonicity-safe: [`SettledCounter::settle`] re-reads the
    /// persisted high-water and refuses to lower it, so a drop can only ever advance (never
    /// roll back) the durable total.
    fn drop(&mut self) {
        if self.unflushed > 0 {
            let _ = self.settled.settle(self.cached_settled);
        }
    }
}

/// The filesystem-safe key a durable counter is bound to, derived ONE way from an agent
/// delegation's `did:keri:` identifier. There is no `Default` and no constructor from an arbitrary
/// string: a counter can only be keyed to a parsed agent delegation, never to a sentinel (this is
/// what retires the `"wrap-session"` placeholder the live wire used to key its counter by).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterKey(String);

impl CounterKey {
    /// Derive the counter key for an agent delegation. The `did:keri:` scheme is stripped and the
    /// tail (base64url) is validated as a single safe path component; anything else is refused
    /// ([`BudgetError::UnsafeKey`]) so a malformed delegation can neither escape the ledger dir nor
    /// silently become a different counter.
    pub fn for_agent(agent_did: &str) -> Result<CounterKey, BudgetError> {
        Ok(CounterKey(safe_key(agent_did)?))
    }

    /// Consume into the inner path component (for the on-disk ledger filename).
    fn into_string(self) -> String {
        self.0
    }
}

/// A located durable counter: the verifier's registry path plus an agent's [`CounterKey`]. The live
/// wire, the hermetic replay gate, the offline `verify-spend` CLI, and the audit all build this the
/// SAME way from `(registry, agent_did)`, so every party opens the SAME on-disk counter — the live
/// counter can no longer be keyed (or rooted) differently from where the audit looks for it.
#[derive(Debug, Clone)]
pub struct CounterRef {
    registry: PathBuf,
    key: CounterKey,
}

impl CounterRef {
    /// Locate the counter for `agent_did` under the verifier's `registry` (the repo the KELs and the
    /// spend log resolve from). The one derivation every path uses.
    pub fn for_agent(registry: &Path, agent_did: &str) -> Result<CounterRef, BudgetError> {
        Ok(CounterRef {
            registry: registry.to_path_buf(),
            key: CounterKey::for_agent(agent_did)?,
        })
    }

    /// Open the monotonic SETTLED counter at this location.
    pub fn open_counter(&self) -> SettledCounter {
        SettledCounter::at(&self.registry, self.key.clone())
    }

    /// Open the cross-rail budget at this location with cap `cap_cents`, persisting on every
    /// settle ([`FlushPolicy::EverySettle`] — full overspend safety).
    ///
    /// The holds start empty and the authoritative in-memory settled total resumes from the
    /// persisted high-water (read ONCE here, not per call).
    ///
    /// Args:
    /// * `cap_cents`: the cross-rail cap for the session.
    ///
    /// Usage:
    /// ```ignore
    /// let budget = counter_ref.open_budget(Cents::new(500))?;
    /// ```
    pub fn open_budget(&self, cap_cents: Cents) -> Result<CrossRailBudget, BudgetError> {
        self.open_budget_with_policy(cap_cents, FlushPolicy::EverySettle)
    }

    /// Open the cross-rail budget with an explicit [`FlushPolicy`]. Use
    /// [`FlushPolicy::GroupCommit`] to remove the per-settle `rename` from the hot path,
    /// accepting the bounded crash-overspend window it documents.
    ///
    /// Args:
    /// * `cap_cents`: the cross-rail cap for the session.
    /// * `flush`: when the authoritative in-memory total is persisted durably.
    ///
    /// Usage:
    /// ```ignore
    /// let budget = counter_ref.open_budget_with_policy(
    ///     Cents::new(500),
    ///     FlushPolicy::GroupCommit { every_n: 64 },
    /// )?;
    /// ```
    pub fn open_budget_with_policy(
        &self,
        cap_cents: Cents,
        flush: FlushPolicy,
    ) -> Result<CrossRailBudget, BudgetError> {
        let settled = self.open_counter();
        let cached_settled = settled.settled_cents()?;
        Ok(CrossRailBudget {
            cap_cents,
            settled,
            holds: ReservedHolds::new(),
            cached_settled,
            flush,
            unflushed: 0,
        })
    }

    /// The on-disk path of the counter record — so a caller (and the gate's locatability check) can
    /// confirm the wire advanced the SAME file the `verify-spend` args resolve to.
    pub fn record_path(&self) -> PathBuf {
        self.registry
            .join(BUDGET_LEDGER_DIR)
            .join(format!("{}.json", self.key.0))
    }
}

/// Derive a filesystem-safe key from an agent-delegation identifier. A `did:keri:E…`
/// is base64url after the prefix (alphanumeric + `-`/`_`), so the tail is already
/// safe; we strip the scheme and reject anything that is not a safe single path
/// component (defensive — the same guard `usage_ledger.rs` applies to a SAID).
fn safe_key(delegation: &str) -> Result<String, BudgetError> {
    let parsed = auths_verifier::IdentityDID::parse(delegation).ok();
    let tail = parsed.as_ref().map(|d| d.prefix()).unwrap_or(delegation);
    let safe = !tail.is_empty()
        && tail != "."
        && tail != ".."
        && tail
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if !safe {
        return Err(BudgetError::UnsafeKey(delegation.to_string()));
    }
    Ok(tail.to_string())
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const DLG: &str = "did:keri:EAgentDelegationXYZ";

    fn budget(dir: &Path, cap: u64) -> CrossRailBudget {
        CounterRef::for_agent(dir, DLG)
            .unwrap()
            .open_budget(Cents::new(cap))
            .unwrap()
    }

    #[test]
    fn cross_rail_summing_one_cap_two_rails() {
        // The transcript scenario: $5 cap, $3 on stripe + $1.50 on x402 = $4.50 settled,
        // then a $0.60 x402 call that would reserve to $5.10 ACROSS rails is refused —
        // even though x402 ALONE is only $1.50 (the moat a per-rail silo cannot express).
        let dir = tempfile::tempdir().unwrap();
        let mut b = budget(dir.path(), 500);

        // Rail 1 (stripe): reserve $3.00, settle $3.00.
        let h0 = match b.reserve(Ceiling::new(Cents::new(300))).unwrap() {
            ReserveOutcome::Reserved { hold, .. } => hold,
            o => panic!("call 0 should reserve, got {o:?}"),
        };
        assert!(matches!(
            b.settle(h0, Actual::new(Cents::new(300))).unwrap(),
            SettleOutcome::Advanced {
                new_settled_cents
            } if new_settled_cents == Cents::new(300)
        ));

        // Rail 2 (x402): reserve $1.50, settle $1.50.
        let h1 = match b.reserve(Ceiling::new(Cents::new(150))).unwrap() {
            ReserveOutcome::Reserved { hold, .. } => hold,
            o => panic!("call 1 should reserve, got {o:?}"),
        };
        assert!(matches!(
            b.settle(h1, Actual::new(Cents::new(150))).unwrap(),
            SettleOutcome::Advanced {
                new_settled_cents
            } if new_settled_cents == Cents::new(450)
        ));
        assert_eq!(b.settled_cents().unwrap(), Cents::new(450));

        // Rail 2 again (x402): $0.60 would reserve to $5.10 across rails — refused,
        // before the rail is touched, even though x402-only spend is just $1.50.
        match b.reserve(Ceiling::new(Cents::new(60))).unwrap() {
            ReserveOutcome::Refused {
                cap_cents,
                would_be_cents,
            } => {
                assert_eq!(cap_cents, Cents::new(500));
                assert_eq!(would_be_cents, Cents::new(510));
            }
            o => panic!("the cross-rail over-cap call must be refused, got {o:?}"),
        }
        // The refused reservation took no hold and never advanced settled.
        assert_eq!(b.reserved_cents(), Cents::ZERO);
        assert_eq!(b.settled_cents().unwrap(), Cents::new(450));
    }

    #[test]
    fn concurrent_calls_never_exceed_the_cross_rail_cap() {
        // The cap-enforcement boundary must hold under REAL parallel access through the
        // `Arc<Mutex<CrossRailBudget>>` the live gateway uses: 50 agents race ONE $1.00
        // reserve→settle each against a $10.00 cap, with the "rail" touched OUTSIDE the lock
        // (the genuine concurrency window between reserve and settle). Under ANY interleaving,
        // exactly 10 settle (consuming the cap) and 40 are refused BEFORE the rail — the
        // cross-rail total never exceeds the cap, and no reservation is left stranded.
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::{Arc, Mutex};

        let dir = tempfile::tempdir().unwrap();
        let (cap, amount, agents) = (1000u64, 100u64, 50u64);
        let b = Arc::new(Mutex::new(budget(dir.path(), cap)));
        let settled = Arc::new(AtomicU64::new(0));
        let refused = Arc::new(AtomicU64::new(0));

        let handles: Vec<_> = (0..agents)
            .map(|_| {
                let b = Arc::clone(&b);
                let settled = Arc::clone(&settled);
                let refused = Arc::clone(&refused);
                std::thread::spawn(move || {
                    // RESERVE under the lock — the pre-auth boundary. The guard drops at the
                    // end of this statement, releasing the lock before the "rail".
                    let hold = match b
                        .lock()
                        .unwrap()
                        .reserve(Ceiling::new(Cents::new(amount)))
                        .unwrap()
                    {
                        ReserveOutcome::Reserved { hold, .. } => Some(hold),
                        ReserveOutcome::Refused { .. } => None,
                    };
                    match hold {
                        Some(hold) => {
                            std::thread::yield_now(); // "rail" touched WITHOUT the lock
                            match b
                                .lock()
                                .unwrap()
                                .settle(hold, Actual::new(Cents::new(amount)))
                                .unwrap()
                            {
                                SettleOutcome::Advanced { .. } => {
                                    settled.fetch_add(1, Ordering::SeqCst);
                                }
                                SettleOutcome::RolledBack { .. } => {
                                    panic!("a fresh settle must not roll back")
                                }
                            }
                        }
                        None => {
                            refused.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }

        let g = b.lock().unwrap();
        // The hard invariant: the cross-rail total NEVER exceeds the cap, under any race.
        assert!(
            g.settled_cents().unwrap() <= Cents::new(cap),
            "cross-rail cap exceeded under concurrency"
        );
        // And it is fully + exactly consumed: cap/amount settle, the rest refused, none stranded.
        assert_eq!(g.settled_cents().unwrap(), Cents::new(cap));
        assert_eq!(settled.load(Ordering::SeqCst), cap / amount);
        assert_eq!(refused.load(Ordering::SeqCst), agents - cap / amount);
        assert_eq!(g.reserved_cents(), Cents::ZERO);
    }

    #[test]
    fn exact_exhaust_allowed_one_over_refused() {
        // The budget boundary rule is locked here: the rule is strictly-over
        // (`would_be > cap`), so a call that reserves EXACTLY to the cap is allowed and the next
        // call — even 1 cent — is refused. This locks `>` against ever drifting to `>=`.
        let dir = tempfile::tempdir().unwrap();
        let mut b = budget(dir.path(), 1000);
        // Reserve+settle exactly to the cap (cumulative == cap): allowed.
        let h = match b.reserve(Ceiling::new(Cents::new(1000))).unwrap() {
            ReserveOutcome::Reserved { hold, .. } => hold,
            o => panic!("the exact-exhaust reserve must be admitted, got {o:?}"),
        };
        b.settle(h, Actual::new(Cents::new(1000))).unwrap();
        assert_eq!(b.settled_cents().unwrap(), Cents::new(1000));
        // One cent over the exhausted cap: refused BEFORE the rail is touched.
        match b.reserve(Ceiling::new(Cents::new(1))).unwrap() {
            ReserveOutcome::Refused {
                cap_cents,
                would_be_cents,
            } => {
                assert_eq!(cap_cents, Cents::new(1000));
                assert_eq!(would_be_cents, Cents::new(1001));
            }
            o => panic!("one cent over the cap must be refused, got {o:?}"),
        }
    }

    #[test]
    fn reserve_settle_releases_slack() {
        // Call reserves a $2.00 ceiling but settles $1.50 — the $0.50 slack must be
        // RELEASED so a later in-budget call is not starved by the over-reservation.
        let dir = tempfile::tempdir().unwrap();
        let mut b = budget(dir.path(), 500);

        let h0 = match b.reserve(Ceiling::new(Cents::new(300))).unwrap() {
            ReserveOutcome::Reserved { hold, .. } => hold,
            o => panic!("got {o:?}"),
        };
        b.settle(h0, Actual::new(Cents::new(300))).unwrap(); // settled = 300

        // Over-reserve: ceiling $2.00, actual $1.50.
        let h1 = match b.reserve(Ceiling::new(Cents::new(200))).unwrap() {
            ReserveOutcome::Reserved {
                hold,
                available_after,
            } => {
                assert_eq!(available_after, Cents::ZERO); // 500 − 300 − 200
                hold
            }
            o => panic!("got {o:?}"),
        };
        b.settle(h1, Actual::new(Cents::new(150))).unwrap(); // settled = 450; the $0.50 slack released

        // available is now 500 − 450 = 50 (the slack came back, not permanently lost):
        assert_eq!(b.available_cents().unwrap(), Cents::new(50));
        // A $0.50 call fits exactly — it would NOT fit if the slack were consumed.
        assert!(matches!(
            b.reserve(Ceiling::new(Cents::new(50))).unwrap(),
            ReserveOutcome::Reserved { .. }
        ));
    }

    #[test]
    fn a_zero_actual_settle_still_releases_the_hold() {
        // A metered call that ends up costing nothing still RELEASES its reserve hold: the slack
        // returns to available and the monotonic counter does not advance. (The writer signs no
        // settlement for a zero actual — that is enforced by the non-zero settlement type, not here.)
        let dir = tempfile::tempdir().unwrap();
        let mut b = budget(dir.path(), 500);
        let h = match b.reserve(Ceiling::new(Cents::new(200))).unwrap() {
            ReserveOutcome::Reserved { hold, .. } => hold,
            o => panic!("got {o:?}"),
        };
        assert_eq!(b.reserved_cents(), Cents::new(200));
        b.settle(h, Actual::new(Cents::ZERO)).unwrap();
        assert_eq!(b.reserved_cents(), Cents::ZERO, "the hold must be released");
        assert_eq!(
            b.settled_cents().unwrap(),
            Cents::ZERO,
            "a zero actual advances nothing"
        );
    }

    #[test]
    fn settled_counter_is_monotonic_rollback_refused() {
        // A crashed-and-restored gateway reloads a STALE snapshot and tries to settle a
        // cumulative total BELOW the recorded high-water — the monotonic counter refuses
        // it (the usage-counter-rolled-back guard D8).
        let dir = tempfile::tempdir().unwrap();
        let counter = CounterRef::for_agent(dir.path(), DLG)
            .unwrap()
            .open_counter();

        assert!(matches!(
            counter.settle(Cents::new(300)).unwrap(),
            SettleOutcome::Advanced {
                new_settled_cents
            } if new_settled_cents == Cents::new(300)
        ));
        assert!(matches!(
            counter.settle(Cents::new(450)).unwrap(),
            SettleOutcome::Advanced {
                new_settled_cents
            } if new_settled_cents == Cents::new(450)
        ));
        // Replay a lower cumulative (the stale-snapshot rollback): refused.
        match counter.settle(Cents::new(400)).unwrap() {
            SettleOutcome::RolledBack {
                presented_cents,
                high_water_cents,
            } => {
                assert_eq!(presented_cents, Cents::new(400));
                assert_eq!(high_water_cents, Cents::new(450));
            }
            o => panic!("a lower settle must be rolled-back, got {o:?}"),
        }
        // The high-water was NOT lowered by the refused rollback.
        assert_eq!(counter.settled_cents().unwrap(), Cents::new(450));
        // Re-presenting the exact high-water is admitted (not a rollback).
        assert!(matches!(
            counter.settle(Cents::new(450)).unwrap(),
            SettleOutcome::Advanced {
                new_settled_cents
            } if new_settled_cents == Cents::new(450)
        ));
    }

    #[test]
    fn settled_counter_persists_across_reopen() {
        // The counter is verifier-held (durable on disk), not a gateway RAM tally: a
        // fresh open of the same delegation sees the persisted high-water.
        let dir = tempfile::tempdir().unwrap();
        {
            let c = CounterRef::for_agent(dir.path(), DLG)
                .unwrap()
                .open_counter();
            c.settle(Cents::new(420)).unwrap();
        }
        let c2 = CounterRef::for_agent(dir.path(), DLG)
            .unwrap()
            .open_counter();
        assert_eq!(c2.settled_cents().unwrap(), Cents::new(420));
    }

    #[test]
    fn holds_sum_and_release() {
        let mut h = ReservedHolds::new();
        let a = h.reserve(Ceiling::new(Cents::new(300)));
        let b = h.reserve(Ceiling::new(Cents::new(200)));
        assert_eq!(h.reserved_cents(), Cents::new(500));
        assert_eq!(h.active(), 2);
        h.release(a);
        assert_eq!(h.reserved_cents(), Cents::new(200));
        h.release(b);
        assert_eq!(h.reserved_cents(), Cents::ZERO);
        // Releasing an already-released hold is a no-op.
        h.release(a);
        assert_eq!(h.reserved_cents(), Cents::ZERO);
    }

    #[test]
    fn expired_hold_returns_to_available_without_settling() {
        // A call that never returns: its hold expires, the cents return to available,
        // and nothing is added to the monotonic settled total.
        let dir = tempfile::tempdir().unwrap();
        let mut b = budget(dir.path(), 500);
        let h = match b.reserve(Ceiling::new(Cents::new(400))).unwrap() {
            ReserveOutcome::Reserved { hold, .. } => hold,
            o => panic!("got {o:?}"),
        };
        assert_eq!(b.available_cents().unwrap(), Cents::new(100));
        b.expire(h);
        assert_eq!(b.available_cents().unwrap(), Cents::new(500));
        assert_eq!(b.settled_cents().unwrap(), Cents::ZERO);
    }

    #[test]
    fn unsafe_delegation_key_refused() {
        let dir = tempfile::tempdir().unwrap();
        assert!(CounterRef::for_agent(dir.path(), "../escape").is_err());
        assert!(CounterRef::for_agent(dir.path(), "did:keri:../escape").is_err());
    }

    #[test]
    fn every_settle_persists_each_settle_and_resumes() {
        // The default policy persists the authoritative in-memory total on every settle, so
        // a fresh open (crash-restore) resumes from the exact last-settled high-water — no
        // overspend window (identical durability to the disk-authoritative counter).
        let dir = tempfile::tempdir().unwrap();
        {
            let mut b = budget(dir.path(), 500);
            let h = match b.reserve(Ceiling::new(Cents::new(300))).unwrap() {
                ReserveOutcome::Reserved { hold, .. } => hold,
                o => panic!("got {o:?}"),
            };
            b.settle(h, Actual::new(Cents::new(300))).unwrap();
            // The counter file already holds 300 BEFORE drop (persisted on the settle).
            let disk = CounterRef::for_agent(dir.path(), DLG)
                .unwrap()
                .open_counter()
                .settled_cents()
                .unwrap();
            assert_eq!(disk, Cents::new(300), "EverySettle persists on the settle");
        }
        // A fresh open resumes from the persisted high-water.
        let b2 = budget(dir.path(), 500);
        assert_eq!(b2.settled_cents().unwrap(), Cents::new(300));
    }

    #[test]
    fn group_commit_defers_persist_then_flushes_on_threshold_and_drop() {
        // GroupCommit persists at most once per N settles; the durable value lags the
        // in-memory total between flushes, and the remainder is flushed on clean drop.
        let dir = tempfile::tempdir().unwrap();
        let counter_on_disk = || {
            CounterRef::for_agent(dir.path(), DLG)
                .unwrap()
                .open_counter()
                .settled_cents()
                .unwrap()
        };
        {
            let mut b = CounterRef::for_agent(dir.path(), DLG)
                .unwrap()
                .open_budget_with_policy(Cents::new(1000), FlushPolicy::GroupCommit { every_n: 3 })
                .unwrap();
            let settle_one = |b: &mut CrossRailBudget| {
                let h = match b.reserve(Ceiling::new(Cents::new(100))).unwrap() {
                    ReserveOutcome::Reserved { hold, .. } => hold,
                    o => panic!("got {o:?}"),
                };
                b.settle(h, Actual::new(Cents::new(100))).unwrap();
            };
            // Two settles: in-memory total is 200, but disk is still behind the threshold.
            settle_one(&mut b);
            settle_one(&mut b);
            assert_eq!(b.settled_cents().unwrap(), Cents::new(200));
            assert_eq!(counter_on_disk(), Cents::ZERO, "not yet flushed (2 < 3)");
            // The third settle hits the threshold and flushes 300 durably.
            settle_one(&mut b);
            assert_eq!(counter_on_disk(), Cents::new(300), "flushed at every_n=3");
            // A fourth settle is un-flushed again; drop must persist the remainder (400).
            settle_one(&mut b);
            assert_eq!(
                counter_on_disk(),
                Cents::new(300),
                "still behind before drop"
            );
        }
        assert_eq!(
            counter_on_disk(),
            Cents::new(400),
            "drop flushed the remainder"
        );
    }

    #[test]
    fn group_commit_drop_never_rolls_the_high_water_back() {
        // A drop can only ADVANCE the durable high-water: if the persisted value is already
        // ahead of this budget's in-memory total, the monotonic guard refuses the lowering.
        let dir = tempfile::tempdir().unwrap();
        // Seed the counter to 900 on disk.
        CounterRef::for_agent(dir.path(), DLG)
            .unwrap()
            .open_counter()
            .settle(Cents::new(900))
            .unwrap();
        {
            let mut b = CounterRef::for_agent(dir.path(), DLG)
                .unwrap()
                .open_budget_with_policy(
                    Cents::new(2000),
                    FlushPolicy::GroupCommit { every_n: 100 },
                )
                .unwrap();
            // Resumed at 900; one $1 settle → in-memory 1000, un-flushed.
            let h = match b.reserve(Ceiling::new(Cents::new(100))).unwrap() {
                ReserveOutcome::Reserved { hold, .. } => hold,
                o => panic!("got {o:?}"),
            };
            b.settle(h, Actual::new(Cents::new(100))).unwrap();
        }
        // Drop advanced 900 → 1000 (never lowered).
        let disk = CounterRef::for_agent(dir.path(), DLG)
            .unwrap()
            .open_counter()
            .settled_cents()
            .unwrap();
        assert_eq!(disk, Cents::new(1000));
    }
}
