//! First-party revocation freshness: a delegator KEL/TEL refresh port + staleness policy.
//!
//! `auths_verifier::verify_presentation` reports a credential as revoked the instant the TEL
//! `rev` is visible in the **local** registry; "freshness" is purely how fast the relying
//! party's local copy learns of that `rev`. The first-party answer (no online issuer in the
//! trust path) is OCSP-stapling-style: a background poll pulls the delegator's KEL/TEL into
//! the local registry on an interval, so the verify path does **zero** per-request network I/O.
//!
//! This module owns that orchestration; per the Golden Rule the verifier stays pure. It defines:
//! - [`DelegatorLogSource`] — the injected refresh port. The production impl pulls a git
//!   registry remote (`git fetch` into the local copy the middleware reads); tests inject a fake.
//! - [`RootRefresh`] — drives the port on an interval and tracks a per-delegator freshness
//!   watermark. The caller's scheduler ticks [`RootRefresh::refresh_if_due`]; the SDK spawns no
//!   thread of its own (no hidden runtime, clock injected at every call).
//! - [`RevocationFreshnessPolicy`] / [`enforce_freshness`] — the fail-closed (default) vs fail-open
//!   decision over how stale the local copy is, surfacing the age so the HTTP boundary can log it.
//!
//! ## Staleness bound
//!
//! The effective bound is **`interval + propagation`**: at most one poll `interval` between the
//! `rev` becoming fetchable on the remote and the local pull, plus the deployment's
//! publish→fetchable propagation delay. Short-lived credentials bound staleness structurally and
//! are the **primary** lever (a 5-minute credential cannot be honored 5 minutes after revocation
//! regardless of poll cadence); the poll interval is the secondary lever. [`RootRefresh::staleness_bound`]
//! surfaces the interval component so each deployment can document its own bound.

use std::collections::HashMap;

use auths_id::keri::types::Prefix;
use chrono::{DateTime, Duration, Utc};
use parking_lot::Mutex;

/// Failure to refresh a delegator's logs from the injected source.
#[derive(Debug, thiserror::Error)]
pub enum RefreshError {
    /// The delegator's remote log could not be reached or pulled.
    #[error("delegator log unreachable: {0}")]
    Unreachable(String),
}

/// The injected refresh port: pull a delegator's latest KEL/TEL into the local registry.
///
/// The production implementation fetches the delegator's git registry remote into the local
/// copy the relying-party middleware verifies against (an explicit, cacheable pull — never a
/// per-verification live lookup, which would add latency, leak which credentials are checked,
/// and soft-fail on a network blip). Tests inject a fake that flips a "published" flag.
pub trait DelegatorLogSource: Send + Sync {
    /// Pull `delegator`'s latest KEL/TEL into the local registry as of `now`.
    ///
    /// Args:
    /// * `delegator`: The delegator (root) AID whose logs gate the delegated subject.
    /// * `now`: The current time, injected at the boundary.
    ///
    /// Usage:
    /// ```ignore
    /// source.refresh(&delegator_prefix, clock.now())?;
    /// ```
    fn refresh(&self, delegator: &Prefix, now: DateTime<Utc>) -> Result<(), RefreshError>;
}

/// Whether a poll ran this tick or the local copy was still within the interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshOutcome {
    /// The source was pulled and the freshness watermark advanced.
    Refreshed,
    /// The local copy is still within the poll interval; no pull was performed.
    Skipped,
}

/// How to treat a presentation whose delegator copy is staler than the poll interval.
///
/// The default is [`RevocationFreshnessPolicy::FailClosed`] (high-assurance: a stale or never-pulled copy
/// cannot honor a presentation, since a `rev` may have landed unseen). [`RevocationFreshnessPolicy::FailOpen`]
/// trades that for availability within an explicit, bounded staleness budget — the boundary MUST
/// log the surfaced age so the residual risk is observable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RevocationFreshnessPolicy {
    /// Reject any presentation whose delegator copy is staler than the interval (default).
    #[default]
    FailClosed,
    /// Honor a stale copy up to `max_staleness`, then reject; log the age.
    FailOpen {
        /// The maximum age beyond which even fail-open rejects.
        max_staleness: Duration,
    },
}

/// The freshness verdict for a delegator copy, carrying the age so the boundary can log it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreshnessDecision {
    /// The local copy is within the staleness bound.
    Fresh {
        /// How long ago the copy was last refreshed.
        age: Duration,
    },
    /// The copy is stale but honored under fail-open within budget — log the age.
    StaleHonored {
        /// How long ago the copy was last refreshed.
        age: Duration,
        /// The fail-open budget the age is still within.
        budget: Duration,
    },
    /// The copy is too stale to honor (fail-closed, or past the fail-open budget).
    StaleRejected {
        /// How long ago the copy was last refreshed.
        age: Duration,
    },
    /// The delegator has never been refreshed locally — no copy to bound staleness against.
    NeverRefreshed,
}

impl FreshnessDecision {
    /// Whether a presentation may be honored under this freshness decision.
    pub fn is_honored(&self) -> bool {
        matches!(self, Self::Fresh { .. } | Self::StaleHonored { .. })
    }
}

/// Decide whether a delegator copy is fresh enough to honor, given the policy.
///
/// A copy within `staleness_bound` is [`FreshnessDecision::Fresh`]. A staler copy is rejected
/// under [`RevocationFreshnessPolicy::FailClosed`]; under [`RevocationFreshnessPolicy::FailOpen`] it is honored up to
/// `max_staleness` (returning the age to log) and rejected beyond it. A delegator never refreshed
/// locally is [`FreshnessDecision::NeverRefreshed`] (rejected by both policies — there is no copy
/// whose staleness could be bounded).
///
/// Args:
/// * `policy`: The fail-closed / fail-open knob.
/// * `last_refreshed`: When the delegator copy was last pulled, or `None` if never.
/// * `now`: The current time, injected at the boundary.
/// * `staleness_bound`: The fresh window (the poll interval).
///
/// Usage:
/// ```ignore
/// let decision = enforce_freshness(&policy, refresh.last_refreshed(&d), now, refresh.staleness_bound());
/// if !decision.is_honored() { return deny(); }
/// ```
pub fn enforce_freshness(
    policy: &RevocationFreshnessPolicy,
    last_refreshed: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    staleness_bound: Duration,
) -> FreshnessDecision {
    let Some(last) = last_refreshed else {
        return FreshnessDecision::NeverRefreshed;
    };
    let age = now.signed_duration_since(last);
    if age <= staleness_bound {
        return FreshnessDecision::Fresh { age };
    }
    match policy {
        RevocationFreshnessPolicy::FailClosed => FreshnessDecision::StaleRejected { age },
        RevocationFreshnessPolicy::FailOpen { max_staleness } => {
            if age <= *max_staleness {
                FreshnessDecision::StaleHonored {
                    age,
                    budget: *max_staleness,
                }
            } else {
                FreshnessDecision::StaleRejected { age }
            }
        }
    }
}

/// Drives a [`DelegatorLogSource`] on a fixed interval and tracks each delegator's freshness.
///
/// The caller's scheduler (a tokio interval, a cron tick) calls [`RootRefresh::refresh_if_due`]
/// per delegator; the store does the pull only when the interval has elapsed since the last one,
/// so the verify path never blocks on the network. The freshness watermark backs
/// [`RootRefresh::freshness`], the per-request fail-closed/fail-open decision.
pub struct RootRefresh<S: DelegatorLogSource> {
    interval: Duration,
    source: S,
    watermarks: Mutex<HashMap<String, DateTime<Utc>>>,
}

impl<S: DelegatorLogSource> RootRefresh<S> {
    /// Build a refresh driver polling `source` no more often than every `interval`.
    ///
    /// Args:
    /// * `interval`: The poll interval (the interval component of the staleness bound).
    /// * `source`: The injected refresh port.
    ///
    /// Usage:
    /// ```ignore
    /// let refresh = RootRefresh::new(Duration::minutes(1), git_source);
    /// ```
    pub fn new(interval: Duration, source: S) -> Self {
        Self {
            interval,
            source,
            watermarks: Mutex::new(HashMap::new()),
        }
    }

    /// The interval component of the staleness bound; the full bound is `this + propagation`.
    pub fn staleness_bound(&self) -> Duration {
        self.interval
    }

    /// When `delegator`'s local copy was last refreshed, or `None` if never.
    pub fn last_refreshed(&self, delegator: &Prefix) -> Option<DateTime<Utc>> {
        self.watermarks.lock().get(delegator.as_str()).copied()
    }

    /// Pull `delegator`'s logs iff the interval has elapsed since the last pull.
    ///
    /// Returns [`RefreshOutcome::Refreshed`] (and advances the watermark to `now`) when a pull
    /// ran, or [`RefreshOutcome::Skipped`] when the copy is still within the interval. A source
    /// error propagates so the caller can apply the [`RevocationFreshnessPolicy`] (fail-closed by default).
    ///
    /// Args:
    /// * `delegator`: The delegator AID to refresh.
    /// * `now`: The current time, injected at the boundary.
    pub fn refresh_if_due(
        &self,
        delegator: &Prefix,
        now: DateTime<Utc>,
    ) -> Result<RefreshOutcome, RefreshError> {
        let due = match self.last_refreshed(delegator) {
            Some(last) => now.signed_duration_since(last) >= self.interval,
            None => true,
        };
        if !due {
            return Ok(RefreshOutcome::Skipped);
        }
        self.source.refresh(delegator, now)?;
        self.watermarks
            .lock()
            .insert(delegator.as_str().to_string(), now);
        Ok(RefreshOutcome::Refreshed)
    }

    /// The freshness decision for `delegator` under `policy` as of `now`.
    pub fn freshness(
        &self,
        delegator: &Prefix,
        policy: &RevocationFreshnessPolicy,
        now: DateTime<Utc>,
    ) -> FreshnessDecision {
        enforce_freshness(policy, self.last_refreshed(delegator), now, self.interval)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn t0() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2030-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn delegator() -> Prefix {
        Prefix::new_unchecked("Edelegator".to_string())
    }

    /// A fake delegator log: a "remote" revocation only becomes visible in the "local" copy
    /// after a `refresh()` pull — modeling publish → poll → locally-visible.
    struct FakeDelegatorLog {
        remote_revoked: Mutex<bool>,
        local_revoked: Mutex<bool>,
        reachable: Mutex<bool>,
        pulls: AtomicUsize,
    }

    impl FakeDelegatorLog {
        fn new() -> Self {
            Self {
                remote_revoked: Mutex::new(false),
                local_revoked: Mutex::new(false),
                reachable: Mutex::new(true),
                pulls: AtomicUsize::new(0),
            }
        }
        fn publish_revocation(&self) {
            *self.remote_revoked.lock() = true;
        }
        fn local_sees_revoked(&self) -> bool {
            *self.local_revoked.lock()
        }
        fn set_reachable(&self, reachable: bool) {
            *self.reachable.lock() = reachable;
        }
        fn pulls(&self) -> usize {
            self.pulls.load(Ordering::SeqCst)
        }
    }

    impl DelegatorLogSource for Arc<FakeDelegatorLog> {
        fn refresh(&self, _delegator: &Prefix, _now: DateTime<Utc>) -> Result<(), RefreshError> {
            if !*self.reachable.lock() {
                return Err(RefreshError::Unreachable("offline".to_string()));
            }
            self.pulls.fetch_add(1, Ordering::SeqCst);
            *self.local_revoked.lock() = *self.remote_revoked.lock();
            Ok(())
        }
    }

    #[test]
    fn revocation_becomes_visible_within_one_interval() {
        let log = Arc::new(FakeDelegatorLog::new());
        let refresh = RootRefresh::new(Duration::seconds(30), Arc::clone(&log));
        let d = delegator();

        // Initial poll: nothing revoked yet.
        assert_eq!(
            refresh.refresh_if_due(&d, t0()).unwrap(),
            RefreshOutcome::Refreshed
        );
        assert!(!log.local_sees_revoked());

        // The delegator publishes a revocation to its remote log.
        log.publish_revocation();

        // Before the interval elapses, no pull happens → the local copy is still unaware.
        let soon = t0() + Duration::seconds(10);
        assert_eq!(
            refresh.refresh_if_due(&d, soon).unwrap(),
            RefreshOutcome::Skipped
        );
        assert!(!log.local_sees_revoked());
        assert_eq!(log.pulls(), 1);

        // After the interval, the next poll pulls the rev → revoked is visible within ≤ interval.
        let after = t0() + Duration::seconds(31);
        assert_eq!(
            refresh.refresh_if_due(&d, after).unwrap(),
            RefreshOutcome::Refreshed
        );
        assert!(
            log.local_sees_revoked(),
            "revocation visible within one poll interval"
        );
        assert_eq!(log.pulls(), 2);
    }

    #[test]
    fn fail_closed_is_the_default_and_rejects_stale_and_absent() {
        let policy = RevocationFreshnessPolicy::default();
        assert_eq!(policy, RevocationFreshnessPolicy::FailClosed);
        let bound = Duration::seconds(30);

        let fresh = enforce_freshness(&policy, Some(t0()), t0() + Duration::seconds(5), bound);
        assert!(matches!(fresh, FreshnessDecision::Fresh { .. }));
        assert!(fresh.is_honored());

        let stale = enforce_freshness(&policy, Some(t0()), t0() + Duration::seconds(120), bound);
        assert!(matches!(stale, FreshnessDecision::StaleRejected { .. }));
        assert!(!stale.is_honored());

        let absent = enforce_freshness(&policy, None, t0(), bound);
        assert_eq!(absent, FreshnessDecision::NeverRefreshed);
        assert!(!absent.is_honored());
    }

    #[test]
    fn fail_open_honors_within_budget_and_rejects_beyond() {
        let policy = RevocationFreshnessPolicy::FailOpen {
            max_staleness: Duration::seconds(300),
        };
        let bound = Duration::seconds(30);

        let within = enforce_freshness(&policy, Some(t0()), t0() + Duration::seconds(120), bound);
        assert!(matches!(within, FreshnessDecision::StaleHonored { .. }));
        assert!(within.is_honored());

        let beyond = enforce_freshness(&policy, Some(t0()), t0() + Duration::seconds(600), bound);
        assert!(matches!(beyond, FreshnessDecision::StaleRejected { .. }));
        assert!(!beyond.is_honored());
    }

    #[test]
    fn unreachable_source_surfaces_an_error_for_the_policy() {
        let log = Arc::new(FakeDelegatorLog::new());
        log.set_reachable(false);
        let refresh = RootRefresh::new(Duration::seconds(30), Arc::clone(&log));
        let err = refresh.refresh_if_due(&delegator(), t0()).unwrap_err();
        assert!(matches!(err, RefreshError::Unreachable(_)));
        // A failed pull does not advance the watermark, so freshness stays fail-closed.
        let decision =
            refresh.freshness(&delegator(), &RevocationFreshnessPolicy::FailClosed, t0());
        assert_eq!(decision, FreshnessDecision::NeverRefreshed);
    }
}
