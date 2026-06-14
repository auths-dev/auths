//! Verifier-side monotonic usage ledger for quantitative capability caps (Epic F.4).
//!
//! A capability of the form `calls:<N>` is a *quantitative* predicate: the
//! credential admits at most `N` exercises. Enforcing it at verify time needs more
//! than reading the bound off the credential — it needs a record of how many
//! exercises have already been observed, so the `(N+1)`-th presentation becomes
//! unverifiable rather than merely logged. That record is this ledger.
//!
//! ## What the ledger is, and why it is trustworthy
//!
//! The ledger is the verifier's own append-only audit trail, kept under the repo it
//! verifies against (alongside `commit-trailers`, `root-pin`, the registry refs). It
//! stores, per credential SAID, the **high-water mark**: the highest call count this
//! verifier has ever accepted. It is the verifier's monotonic source of truth — not
//! the presented counter, which is untrusted caller input.
//!
//! On each verification the caller presents an *observed* count (e.g. drawn from the
//! agent's signed usage report). The ledger enforces two rules against its
//! high-water mark, both fail-closed:
//!
//! 1. **Cap** — an observed count that has reached the bound (`observed >= cap`) is
//!    rejected: the budget is spent.
//! 2. **Monotonicity (anti-replay)** — an observed count *below* the high-water mark
//!    is rejected: a replayed earlier counter cannot roll the budget back. Only a
//!    count at or above the highest already accepted advances the ledger.
//!
//! Because the high-water mark only ever rises and is never taken from the presented
//! value when that value is lower, an attacker who replays the opening `count=0`
//! snapshot after the cap is spent is refused — the ledger already records a higher
//! water mark and the rollback is detected. This is the anti-replay property the
//! quantitative-cap claim requires.
//!
//! ## Why this lives in F.4, not the pure verifier
//!
//! The pure verifier (F.5) is WASM-safe: no clock, no I/O, no persistent state. The
//! usage ledger is inherently stateful (it must remember across invocations), so it
//! belongs in the resolution layer (F.4), exactly like the freshness decision. The
//! pure verifier still establishes the credential's authenticity and surfaces the
//! cap (it is part of the SAID-bound capability claim); F.4 enforces consumption.

use std::fs;
use std::path::{Path, PathBuf};

use auths_keri::{Said, UsageCap};
use serde::{Deserialize, Serialize};

use crate::domains::credentials::error::CredentialError;

/// The repo-relative directory holding the per-credential usage high-water records.
const USAGE_LEDGER_DIR: &str = "usage-ledger";

/// An observed usage count presented to the verifier for cap enforcement.
///
/// This is *untrusted* caller input (the agent's reported call count). The ledger
/// checks it against the verifier's own monotonic high-water mark; it is never
/// trusted to lower the mark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsageObservation {
    /// The number of calls the presenter claims have been made before this one.
    pub calls_used: u64,
}

/// The outcome of enforcing a quantitative cap against the usage ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsageDecision {
    /// Within budget: the observed count is admitted and the high-water mark advanced.
    Admitted {
        /// The cap that was enforced.
        cap: UsageCap,
        /// The observed count that was admitted (the new high-water mark).
        admitted_at: u64,
    },
    /// The cap is spent: the observed count has reached the bound.
    CapExceeded {
        /// The cap that was exceeded.
        cap: UsageCap,
        /// The observed count that exceeded it (`>= cap.max_calls()`).
        observed: u64,
    },
    /// The observed count is below the highest already accepted — a replayed/rolled-back
    /// counter. Refused so the budget cannot be reset by replaying an earlier snapshot.
    RolledBack {
        /// The (lower) observed count presented.
        observed: u64,
        /// The verifier's recorded high-water mark the observation fell below.
        high_water: u64,
    },
}

/// The persisted per-credential high-water record.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct UsageRecord {
    /// The credential SAID this record bounds (self-describing for audit).
    said: String,
    /// The highest call count this verifier has accepted for the credential.
    high_water: u64,
}

/// The verifier's monotonic usage ledger, rooted at a repo path.
///
/// Each credential's high-water mark is a small JSON file under
/// `<repo>/usage-ledger/<said>.json`. Reads and writes are file-local; there is no
/// shared in-memory state, so two verifications of different credentials never
/// contend, and a verification of the same credential reads the latest committed mark.
pub struct UsageLedger {
    /// `<repo>/usage-ledger` — created on first write.
    dir: PathBuf,
}

impl UsageLedger {
    /// Open the ledger rooted at a repo path (e.g. `ctx.repo_path`).
    pub fn new(repo_path: &Path) -> Self {
        Self {
            dir: repo_path.join(USAGE_LEDGER_DIR),
        }
    }

    /// The high-water record path for a credential SAID.
    ///
    /// The SAID is a CESR Base64URL string (`E…`) — alphanumeric plus `-`/`_`, never
    /// a path separator — so it is a safe single filename component. We still guard
    /// against an empty/dotted SAID defensively.
    fn record_path(&self, said: &Said) -> Result<PathBuf, CredentialError> {
        let name = said.as_str();
        let safe = !name.is_empty()
            && name != "."
            && name != ".."
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
        if !safe {
            return Err(CredentialError::StaleOrUnresolvable {
                reason: format!("usage ledger: refusing unsafe credential SAID '{name}'"),
            });
        }
        Ok(self.dir.join(format!("{name}.json")))
    }

    /// Read the current high-water mark for a credential, or `None` if unseen.
    fn read_high_water(&self, said: &Said) -> Result<Option<u64>, CredentialError> {
        let path = self.record_path(said)?;
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(CredentialError::StaleOrUnresolvable {
                    reason: format!("usage ledger read failed: {e}"),
                });
            }
        };
        let record: UsageRecord =
            serde_json::from_slice(&bytes).map_err(|e| CredentialError::StaleOrUnresolvable {
                reason: format!("usage ledger record parse failed: {e}"),
            })?;
        Ok(Some(record.high_water))
    }

    /// Persist a new high-water mark for a credential, atomically.
    ///
    /// Writes to a temp file in the ledger dir and renames over the record, so a
    /// concurrent reader never observes a half-written mark. The mark only ever rises
    /// (callers pass a value `>=` the prior mark), so the rename is monotone.
    fn write_high_water(&self, said: &Said, high_water: u64) -> Result<(), CredentialError> {
        fs::create_dir_all(&self.dir).map_err(|e| CredentialError::StaleOrUnresolvable {
            reason: format!("usage ledger mkdir failed: {e}"),
        })?;
        let path = self.record_path(said)?;
        let record = UsageRecord {
            said: said.as_str().to_string(),
            high_water,
        };
        let body = serde_json::to_vec_pretty(&record).map_err(|e| {
            CredentialError::StaleOrUnresolvable {
                reason: format!("usage ledger record encode failed: {e}"),
            }
        })?;
        // Atomic publish: write the full record to a temp file, then rename it over
        // the canonical path. The rename is the atomic step — a concurrent reader sees
        // either the old record or the complete new one, never a half-written mark.
        let tmp = self.dir.join(format!(".{}.tmp", said.as_str()));
        fs::write(&tmp, &body).map_err(|e| CredentialError::StaleOrUnresolvable {
            reason: format!("usage ledger temp write failed: {e}"),
        })?;
        fs::rename(&tmp, &path).map_err(|e| CredentialError::StaleOrUnresolvable {
            reason: format!("usage ledger commit (rename) failed: {e}"),
        })?;
        Ok(())
    }

    /// Enforce a quantitative cap against the ledger, advancing it on admission.
    ///
    /// The single decision point for the `(N+1)`-th-use guarantee:
    ///
    /// - `observed >= cap.max_calls()` → [`UsageDecision::CapExceeded`] (budget spent).
    /// - `observed < high_water` → [`UsageDecision::RolledBack`] (replayed counter).
    /// - otherwise → [`UsageDecision::Admitted`], and the high-water mark advances to
    ///   `observed` so a later replay of a lower count is refused.
    ///
    /// The cap check precedes the monotonicity advance, so reaching the cap never
    /// raises the high-water mark to the over-budget value: the ledger records only
    /// admitted (within-budget) counts.
    pub fn enforce(
        &self,
        said: &Said,
        cap: UsageCap,
        observed: UsageObservation,
    ) -> Result<UsageDecision, CredentialError> {
        let used = observed.calls_used;

        // Cap first: a count that has reached the bound is spent, regardless of the
        // ledger state. This is the (N+1)-th-use rejection.
        if used >= cap.max_calls() {
            return Ok(UsageDecision::CapExceeded {
                cap,
                observed: used,
            });
        }

        // Monotonicity: an observed count below the highest already accepted is a
        // replayed/rolled-back counter — refuse it so the budget cannot reset.
        let high_water = self.read_high_water(said)?;
        if let Some(mark) = high_water
            && used < mark
        {
            return Ok(UsageDecision::RolledBack {
                observed: used,
                high_water: mark,
            });
        }

        // Within budget and not a rollback: advance the high-water mark to the
        // observed count (it only ever rises) and admit.
        self.write_high_water(said, used)?;
        Ok(UsageDecision::Admitted {
            cap,
            admitted_at: used,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_keri::Capability;

    fn said(s: &str) -> Said {
        Said::new_unchecked(s.to_string())
    }

    fn cap3() -> UsageCap {
        UsageCap::from_capability(&Capability::parse("calls:3").unwrap()).unwrap()
    }

    #[test]
    fn within_cap_counts_are_admitted_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = UsageLedger::new(dir.path());
        let s = said("ECredOne");
        for n in 0..3 {
            let d = ledger
                .enforce(&s, cap3(), UsageObservation { calls_used: n })
                .unwrap();
            assert!(
                matches!(d, UsageDecision::Admitted { admitted_at, .. } if admitted_at == n),
                "count {n} should be admitted, got {d:?}"
            );
        }
    }

    #[test]
    fn the_nth_plus_one_use_is_cap_exceeded() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = UsageLedger::new(dir.path());
        let s = said("ECredTwo");
        for n in 0..3 {
            ledger
                .enforce(&s, cap3(), UsageObservation { calls_used: n })
                .unwrap();
        }
        let d = ledger
            .enforce(&s, cap3(), UsageObservation { calls_used: 3 })
            .unwrap();
        assert!(
            matches!(d, UsageDecision::CapExceeded { observed: 3, .. }),
            "4th use must be cap-exceeded, got {d:?}"
        );
    }

    #[test]
    fn replayed_opening_counter_is_rejected_after_cap_spent() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = UsageLedger::new(dir.path());
        let s = said("ECredThree");
        // Spend three calls: high-water advances to 2.
        for n in 0..3 {
            ledger
                .enforce(&s, cap3(), UsageObservation { calls_used: n })
                .unwrap();
        }
        // Replay the pre-spend counter (calls_used=0) — must be a rollback, not admitted.
        let d = ledger
            .enforce(&s, cap3(), UsageObservation { calls_used: 0 })
            .unwrap();
        assert!(
            matches!(
                d,
                UsageDecision::RolledBack {
                    observed: 0,
                    high_water: 2
                }
            ),
            "replay of count=0 after spend must be rolled-back, got {d:?}"
        );
    }

    #[test]
    fn cap_exceeded_does_not_raise_high_water() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = UsageLedger::new(dir.path());
        let s = said("ECredFour");
        // Admit count 0, then over-cap at 5 — the over-cap value must not be recorded.
        ledger
            .enforce(&s, cap3(), UsageObservation { calls_used: 0 })
            .unwrap();
        ledger
            .enforce(&s, cap3(), UsageObservation { calls_used: 5 })
            .unwrap();
        // A within-cap count of 1 still advances normally (high-water is 0, not 5).
        let d = ledger
            .enforce(&s, cap3(), UsageObservation { calls_used: 1 })
            .unwrap();
        assert!(matches!(d, UsageDecision::Admitted { admitted_at: 1, .. }));
    }

    #[test]
    fn re_presenting_the_high_water_count_is_admitted_not_rolled_back() {
        // Equal-to-mark is not a rollback (it is the same authorized snapshot), only
        // strictly-below is. This keeps a legitimate re-verify of the latest count valid.
        let dir = tempfile::tempdir().unwrap();
        let ledger = UsageLedger::new(dir.path());
        let s = said("ECredFive");
        ledger
            .enforce(&s, cap3(), UsageObservation { calls_used: 0 })
            .unwrap();
        ledger
            .enforce(&s, cap3(), UsageObservation { calls_used: 1 })
            .unwrap();
        let d = ledger
            .enforce(&s, cap3(), UsageObservation { calls_used: 1 })
            .unwrap();
        assert!(matches!(d, UsageDecision::Admitted { admitted_at: 1, .. }));
    }

    #[test]
    fn unsafe_said_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = UsageLedger::new(dir.path());
        let bad = said("../escape");
        let r = ledger.enforce(&bad, cap3(), UsageObservation { calls_used: 0 });
        assert!(r.is_err(), "path-traversal SAID must be refused");
    }
}
