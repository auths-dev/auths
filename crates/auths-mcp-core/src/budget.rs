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
//! ## Checkpoint-anchoring (the §12 durability layer) — PARKED
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
//! lands (detection ≠ reversal, §12).

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
    settled_high_water_cents: u64,
}

/// The outcome of settling an actual cost into the monotonic counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettleOutcome {
    /// The cumulative total advanced (or held steady) — the new monotonic high-water.
    Advanced { new_settled_cents: u64 },
    /// The presented cumulative total was *below* the recorded high-water: a
    /// replayed/stale settled total. Refused so a crashed-and-restored gateway cannot
    /// roll the spend back (the D8 rollback guard → `usage-counter-rolled-back`).
    RolledBack {
        presented_cents: u64,
        high_water_cents: u64,
    },
}

impl SettledCounter {
    /// Open the settled counter for an agent delegation, rooted at the verifier's repo
    /// path (the same repo the KELs resolve from). `delegation` is the agent
    /// delegation identifier (e.g. its `did:keri:` / SAID) — the counter is keyed to
    /// the DELEGATION, summing all rails, never per-credential or per-rail.
    pub fn open(repo_path: &Path, delegation: &str) -> Result<Self, BudgetError> {
        let key = safe_key(delegation)?;
        Ok(Self {
            dir: repo_path.join(BUDGET_LEDGER_DIR),
            key,
        })
    }

    /// The current settled high-water for this delegation (0 if unseen).
    pub fn settled_cents(&self) -> Result<u64, BudgetError> {
        Ok(self.read_high_water()?.unwrap_or(0))
    }

    fn record_path(&self) -> PathBuf {
        self.dir.join(format!("{}.json", self.key))
    }

    fn read_high_water(&self) -> Result<Option<u64>, BudgetError> {
        let path = self.record_path();
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(BudgetError::Persistence(format!("read {path:?}: {e}"))),
        };
        let record: SettledRecord = serde_json::from_slice(&bytes)
            .map_err(|e| BudgetError::Persistence(format!("parse {path:?}: {e}")))?;
        Ok(Some(record.settled_high_water_cents))
    }

    /// Atomically publish a new high-water mark (temp-write + rename), exactly the
    /// crash-safe publish `usage_ledger.rs` uses: a concurrent reader sees either the
    /// old record or the complete new one, never a half-written mark.
    fn write_high_water(&self, cents: u64) -> Result<(), BudgetError> {
        fs::create_dir_all(&self.dir)
            .map_err(|e| BudgetError::Persistence(format!("mkdir {:?}: {e}", self.dir)))?;
        let record = SettledRecord {
            delegation: self.key.clone(),
            settled_high_water_cents: cents,
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
    pub fn settle(&self, new_cumulative_cents: u64) -> Result<SettleOutcome, BudgetError> {
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
    /// the chain periodically (D8, §12). Built over the canonical record so a stranger
    /// can re-derive it from the persisted counter alone. (The periodic *anchoring* is
    /// the parked follow-on; this exposes the digest the anchor would carry.)
    pub fn digest(&self) -> Result<String, BudgetError> {
        let cents = self.settled_cents()?;
        let mut h = Sha256::new();
        h.update(self.key.as_bytes());
        h.update(b":");
        h.update(cents.to_le_bytes());
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
    pub ceiling_cents: u64,
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
    pub fn reserved_cents(&self) -> u64 {
        self.holds
            .iter()
            .fold(0u64, |acc, h| acc.saturating_add(h.ceiling_cents))
    }

    /// Take a hold for `ceiling_cents` (the caller must have checked `available`
    /// first). Returns the hold so the caller can settle/release it.
    pub fn reserve(&mut self, ceiling_cents: u64) -> Hold {
        let hold = Hold {
            id: self.next_id,
            ceiling_cents,
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
pub fn available(cap_cents: u64, settled_cents: u64, reserved_cents: u64) -> u64 {
    cap_cents
        .saturating_sub(settled_cents)
        .saturating_sub(reserved_cents)
}

/// The outcome of pre-authorizing (reserving) a paid call against the cross-rail
/// budget, *before* the rail is touched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReserveOutcome {
    /// The reservation fits within `available` — the hold is taken and the call may
    /// proceed to the rail.
    Reserved { hold: Hold, available_after: u64 },
    /// The reservation would push `settled + Σ(holds) + ceiling` past the cap —
    /// refused BEFORE the rail is touched (the metered downstream is never charged).
    /// Carries the cap and the would-be cross-rail total for the verdict.
    Refused { cap_cents: u64, would_be_cents: u64 },
}

/// The cross-rail budget for one agent delegation across one session: the durable
/// SETTLED counter + the transient RESERVED holds, enforcing ONE cap across all rails
/// by pre-authorization. This is the D8 engine the gate drives per paid call.
#[derive(Debug, Clone)]
pub struct CrossRailBudget {
    cap_cents: u64,
    settled: SettledCounter,
    holds: ReservedHolds,
}

impl CrossRailBudget {
    /// Open the cross-rail budget for `delegation` with cap `cap_cents`, rooted at the
    /// verifier's repo path (where the SETTLED counter persists). The holds start
    /// empty; the settled total is whatever the persisted high-water already records
    /// (so a resumed session continues from the durable counter, never below it).
    pub fn open(repo_path: &Path, delegation: &str, cap_cents: u64) -> Result<Self, BudgetError> {
        Ok(Self {
            cap_cents,
            settled: SettledCounter::open(repo_path, delegation)?,
            holds: ReservedHolds::new(),
        })
    }

    /// The cap, in cents.
    pub fn cap_cents(&self) -> u64 {
        self.cap_cents
    }

    /// The current durable SETTLED total (summed across all rails).
    pub fn settled_cents(&self) -> Result<u64, BudgetError> {
        self.settled.settled_cents()
    }

    /// `Σ(active holds)` — the transient reserved cents.
    pub fn reserved_cents(&self) -> u64 {
        self.holds.reserved_cents()
    }

    /// `available = cap − settled − Σ(holds)`.
    pub fn available_cents(&self) -> Result<u64, BudgetError> {
        Ok(available(
            self.cap_cents,
            self.settled.settled_cents()?,
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
    pub fn reserve(&mut self, ceiling_cents: u64) -> Result<ReserveOutcome, BudgetError> {
        let settled = self.settled.settled_cents()?;
        let reserved = self.holds.reserved_cents();
        let would_be = settled
            .saturating_add(reserved)
            .saturating_add(ceiling_cents);
        if would_be > self.cap_cents {
            return Ok(ReserveOutcome::Refused {
                cap_cents: self.cap_cents,
                would_be_cents: would_be,
            });
        }
        let hold = self.holds.reserve(ceiling_cents);
        Ok(ReserveOutcome::Reserved {
            hold,
            available_after: available(self.cap_cents, settled, self.holds.reserved_cents()),
        })
    }

    /// SETTLE a held call's ACTUAL cost: release the hold (returning the slack between
    /// the reserved ceiling and the actual to `available`), then advance the monotonic
    /// SETTLED counter by `actual_cents`. Returns the settle outcome (advanced, or a
    /// refused [`SettleOutcome::RolledBack`] if the new cumulative would fall below the
    /// recorded high-water). The hold is released REGARDLESS of the monotonicity
    /// outcome so a rolled-back settle does not leak the reservation.
    pub fn settle(&mut self, hold: Hold, actual_cents: u64) -> Result<SettleOutcome, BudgetError> {
        // Release the auth-hold first: the slack (ceiling − actual) returns to
        // available, and a rolled-back settle below does not strand the reservation.
        self.holds.release(hold);
        let new_cumulative = self.settled.settled_cents()?.saturating_add(actual_cents);
        self.settled.settle(new_cumulative)
    }

    /// Release a hold WITHOUT settling — the auth-hold expiry path for a call that
    /// never returned. The reserved cents are returned to `available`; nothing is added
    /// to the monotonic settled total (the rail was never charged).
    pub fn expire(&mut self, hold: Hold) {
        self.holds.release(hold);
    }
}

/// Derive a filesystem-safe key from an agent-delegation identifier. A `did:keri:E…`
/// is base64url after the prefix (alphanumeric + `-`/`_`), so the tail is already
/// safe; we strip the scheme and reject anything that is not a safe single path
/// component (defensive — the same guard `usage_ledger.rs` applies to a SAID).
fn safe_key(delegation: &str) -> Result<String, BudgetError> {
    let tail = delegation.strip_prefix("did:keri:").unwrap_or(delegation);
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
        CrossRailBudget::open(dir, DLG, cap).unwrap()
    }

    #[test]
    fn cross_rail_summing_one_cap_two_rails() {
        // The transcript scenario: $5 cap, $3 on stripe + $1.50 on x402 = $4.50 settled,
        // then a $0.60 x402 call that would reserve to $5.10 ACROSS rails is refused —
        // even though x402 ALONE is only $1.50 (the moat a per-rail silo cannot express).
        let dir = tempfile::tempdir().unwrap();
        let mut b = budget(dir.path(), 500);

        // Rail 1 (stripe): reserve $3.00, settle $3.00.
        let h0 = match b.reserve(300).unwrap() {
            ReserveOutcome::Reserved { hold, .. } => hold,
            o => panic!("call 0 should reserve, got {o:?}"),
        };
        assert!(matches!(
            b.settle(h0, 300).unwrap(),
            SettleOutcome::Advanced {
                new_settled_cents: 300
            }
        ));

        // Rail 2 (x402): reserve $1.50, settle $1.50.
        let h1 = match b.reserve(150).unwrap() {
            ReserveOutcome::Reserved { hold, .. } => hold,
            o => panic!("call 1 should reserve, got {o:?}"),
        };
        assert!(matches!(
            b.settle(h1, 150).unwrap(),
            SettleOutcome::Advanced {
                new_settled_cents: 450
            }
        ));
        assert_eq!(b.settled_cents().unwrap(), 450);

        // Rail 2 again (x402): $0.60 would reserve to $5.10 across rails — refused,
        // before the rail is touched, even though x402-only spend is just $1.50.
        match b.reserve(60).unwrap() {
            ReserveOutcome::Refused {
                cap_cents,
                would_be_cents,
            } => {
                assert_eq!(cap_cents, 500);
                assert_eq!(would_be_cents, 510);
            }
            o => panic!("the cross-rail over-cap call must be refused, got {o:?}"),
        }
        // The refused reservation took no hold and never advanced settled.
        assert_eq!(b.reserved_cents(), 0);
        assert_eq!(b.settled_cents().unwrap(), 450);
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
                    let hold = match b.lock().unwrap().reserve(amount).unwrap() {
                        ReserveOutcome::Reserved { hold, .. } => Some(hold),
                        ReserveOutcome::Refused { .. } => None,
                    };
                    match hold {
                        Some(hold) => {
                            std::thread::yield_now(); // "rail" touched WITHOUT the lock
                            match b.lock().unwrap().settle(hold, amount).unwrap() {
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
            g.settled_cents().unwrap() <= cap,
            "cross-rail cap exceeded under concurrency"
        );
        // And it is fully + exactly consumed: cap/amount settle, the rest refused, none stranded.
        assert_eq!(g.settled_cents().unwrap(), cap);
        assert_eq!(settled.load(Ordering::SeqCst), cap / amount);
        assert_eq!(refused.load(Ordering::SeqCst), agents - cap / amount);
        assert_eq!(g.reserved_cents(), 0);
    }

    #[test]
    fn reserve_settle_releases_slack() {
        // Call reserves a $2.00 ceiling but settles $1.50 — the $0.50 slack must be
        // RELEASED so a later in-budget call is not starved by the over-reservation.
        let dir = tempfile::tempdir().unwrap();
        let mut b = budget(dir.path(), 500);

        let h0 = match b.reserve(300).unwrap() {
            ReserveOutcome::Reserved { hold, .. } => hold,
            o => panic!("got {o:?}"),
        };
        b.settle(h0, 300).unwrap(); // settled = 300

        // Over-reserve: ceiling $2.00, actual $1.50.
        let h1 = match b.reserve(200).unwrap() {
            ReserveOutcome::Reserved {
                hold,
                available_after,
            } => {
                assert_eq!(available_after, 0); // 500 − 300 − 200
                hold
            }
            o => panic!("got {o:?}"),
        };
        b.settle(h1, 150).unwrap(); // settled = 450; the $0.50 slack released

        // available is now 500 − 450 = 50 (the slack came back, not permanently lost):
        assert_eq!(b.available_cents().unwrap(), 50);
        // A $0.50 call fits exactly — it would NOT fit if the slack were consumed.
        assert!(matches!(
            b.reserve(50).unwrap(),
            ReserveOutcome::Reserved { .. }
        ));
    }

    #[test]
    fn settled_counter_is_monotonic_rollback_refused() {
        // A crashed-and-restored gateway reloads a STALE snapshot and tries to settle a
        // cumulative total BELOW the recorded high-water — the monotonic counter refuses
        // it (the usage-counter-rolled-back guard D8).
        let dir = tempfile::tempdir().unwrap();
        let counter = SettledCounter::open(dir.path(), DLG).unwrap();

        assert!(matches!(
            counter.settle(300).unwrap(),
            SettleOutcome::Advanced {
                new_settled_cents: 300
            }
        ));
        assert!(matches!(
            counter.settle(450).unwrap(),
            SettleOutcome::Advanced {
                new_settled_cents: 450
            }
        ));
        // Replay a lower cumulative (the stale-snapshot rollback): refused.
        match counter.settle(400).unwrap() {
            SettleOutcome::RolledBack {
                presented_cents,
                high_water_cents,
            } => {
                assert_eq!(presented_cents, 400);
                assert_eq!(high_water_cents, 450);
            }
            o => panic!("a lower settle must be rolled-back, got {o:?}"),
        }
        // The high-water was NOT lowered by the refused rollback.
        assert_eq!(counter.settled_cents().unwrap(), 450);
        // Re-presenting the exact high-water is admitted (not a rollback).
        assert!(matches!(
            counter.settle(450).unwrap(),
            SettleOutcome::Advanced {
                new_settled_cents: 450
            }
        ));
    }

    #[test]
    fn settled_counter_persists_across_reopen() {
        // The counter is verifier-held (durable on disk), not a gateway RAM tally: a
        // fresh open of the same delegation sees the persisted high-water.
        let dir = tempfile::tempdir().unwrap();
        {
            let c = SettledCounter::open(dir.path(), DLG).unwrap();
            c.settle(420).unwrap();
        }
        let c2 = SettledCounter::open(dir.path(), DLG).unwrap();
        assert_eq!(c2.settled_cents().unwrap(), 420);
    }

    #[test]
    fn holds_sum_and_release() {
        let mut h = ReservedHolds::new();
        let a = h.reserve(300);
        let b = h.reserve(200);
        assert_eq!(h.reserved_cents(), 500);
        assert_eq!(h.active(), 2);
        h.release(a);
        assert_eq!(h.reserved_cents(), 200);
        h.release(b);
        assert_eq!(h.reserved_cents(), 0);
        // Releasing an already-released hold is a no-op.
        h.release(a);
        assert_eq!(h.reserved_cents(), 0);
    }

    #[test]
    fn expired_hold_returns_to_available_without_settling() {
        // A call that never returns: its hold expires, the cents return to available,
        // and nothing is added to the monotonic settled total.
        let dir = tempfile::tempdir().unwrap();
        let mut b = budget(dir.path(), 500);
        let h = match b.reserve(400).unwrap() {
            ReserveOutcome::Reserved { hold, .. } => hold,
            o => panic!("got {o:?}"),
        };
        assert_eq!(b.available_cents().unwrap(), 100);
        b.expire(h);
        assert_eq!(b.available_cents().unwrap(), 500);
        assert_eq!(b.settled_cents().unwrap(), 0);
    }

    #[test]
    fn unsafe_delegation_key_refused() {
        let dir = tempfile::tempdir().unwrap();
        assert!(SettledCounter::open(dir.path(), "../escape").is_err());
        assert!(SettledCounter::open(dir.path(), "did:keri:../escape").is_err());
    }
}
