//! Per-IP + per-route rate limiter.
//!
//! # Tiered quotas and lockout
//!
//! A single global quota would give every session-lookup the same
//! budget as a session-create spam. This limiter splits the budget
//! per endpoint class and adds two cross-cutting defenses:
//!
//! 1. **Tier quotas** — different limits per endpoint class. The
//!    mapping (route → tier) is wrapped by [`classify_path`]; tier
//!    numbers are [`TieredRateConfig`]. Defaults (plan text):
//!    - `SessionCreate`: 5/min/IP
//!    - `SessionLookup`: 20/min/IP
//!    - `SasSubmission`: 3/session/lifetime (one-shot protocol; D.I.D.)
//!    - `Other`: 60/min/IP
//!
//! 2. **Lookup miss-hit lockout** — consecutive not-found responses
//!    from the same IP increment a per-IP counter; at the threshold
//!    (default 3) subsequent lookups are 429 with exponential
//!    `Retry-After: 2^n` seconds, capped at the configured ceiling
//!    (default 300s). The counter decays on the first hit.
//!
//! 3. **Uniform-time miss responses** — the lookup handler calls
//!    [`uniform_time_floor`] to enforce a minimum elapsed time before
//!    returning; both hit and miss paths sleep to the floor. Removes
//!    the nanosecond-scale timing difference an attacker could use to
//!    enumerate short codes.
//!
//! # Why in-house
//!
//! `tower_governor` is the obvious off-the-shelf choice, but it does
//! not store per-IP miss-lockout counters alongside the token bucket.
//! Keeping the lockout state first-class in our limiter is simpler
//! than bolting a second state machine onto governor via an
//! `Extensions` extractor.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const DEFAULT_WINDOW: Duration = Duration::from_secs(60);

/// Endpoint class — determines which quota bucket applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tier {
    /// `POST /v1/pairing/sessions` — session creation.
    SessionCreate,
    /// `GET /v1/pairing/sessions/by-code/{code}` — short-code lookup.
    /// Subject to the miss-hit lockout policy.
    SessionLookup,
    /// `POST /v1/pairing/sessions/{id}/confirm` — SAS
    /// confirmation submission.
    SasSubmission,
    /// Health / confirmation-get / anything else — a generous default.
    Other,
}

/// Runtime-tunable quota + lockout + uniform-time config. Defaults
/// match the plan text; production callers typically just use
/// [`TieredRateConfig::default`].
#[derive(Debug, Clone)]
pub struct TieredRateConfig {
    pub session_create_per_min: u32,
    pub session_lookup_per_min: u32,
    pub sas_submissions_per_session: u32,
    pub other_per_min: u32,

    /// Window used for per-IP rolling counters on every tier except
    /// `SasSubmission` (which is a lifetime-of-session counter).
    pub window: Duration,

    /// Number of consecutive not-found responses from an IP before
    /// the exponential lockout starts.
    pub lookup_miss_threshold: u32,

    /// Base for the exponential-backoff `Retry-After`. The
    /// `n`-th miss-over-threshold yields `base * 2^(n-1)`.
    pub lookup_miss_backoff_base: Duration,

    /// Ceiling on the exponential lockout.
    pub lookup_miss_backoff_cap: Duration,

    /// Minimum elapsed wall time for a lookup response. Both hit and
    /// miss paths sleep to this floor so an attacker cannot distinguish
    /// between an unknown session and a known session that happened to
    /// be slow. 100 ms is human-imperceptible and far above handler
    /// variance.
    pub uniform_miss_floor: Duration,
}

impl Default for TieredRateConfig {
    fn default() -> Self {
        Self {
            session_create_per_min: 5,
            session_lookup_per_min: 20,
            sas_submissions_per_session: 3,
            other_per_min: 60,
            window: DEFAULT_WINDOW,
            lookup_miss_threshold: 3,
            lookup_miss_backoff_base: Duration::from_secs(1),
            lookup_miss_backoff_cap: Duration::from_secs(300),
            uniform_miss_floor: Duration::from_millis(100),
        }
    }
}

/// Per-IP-per-tier rolling-window counter state.
#[derive(Debug, Clone, Copy)]
struct WindowState {
    count: u32,
    window_start: Instant,
}

/// Lookup miss-hit tracking per IP.
#[derive(Debug, Clone, Copy, Default)]
struct LookupMissState {
    consecutive_misses: u32,
    /// The Instant that, once passed, a subsequent lookup can run even
    /// while `consecutive_misses >= threshold`.
    locked_until: Option<Instant>,
}

/// Outcome of checking a tier quota. Returned to the middleware so
/// `Retry-After` can be populated on 429.
#[derive(Debug, Clone, Copy)]
pub enum CheckOutcome {
    Allowed,
    RateLimited { retry_after: Option<Duration> },
}

/// Main limiter — fan-outs to per-tier sub-maps and centralizes the
/// lockout logic.
pub struct TieredRateLimiter {
    cfg: TieredRateConfig,
    session_create: Mutex<HashMap<IpAddr, WindowState>>,
    session_lookup: Mutex<HashMap<IpAddr, WindowState>>,
    sas_submission: Mutex<HashMap<String, u32>>,
    other: Mutex<HashMap<IpAddr, WindowState>>,
    lookup_miss: Mutex<HashMap<IpAddr, LookupMissState>>,
}

impl TieredRateLimiter {
    pub fn new(cfg: TieredRateConfig) -> Self {
        Self {
            cfg,
            session_create: Mutex::new(HashMap::new()),
            session_lookup: Mutex::new(HashMap::new()),
            sas_submission: Mutex::new(HashMap::new()),
            other: Mutex::new(HashMap::new()),
            lookup_miss: Mutex::new(HashMap::new()),
        }
    }

    /// Read-only accessor for tests / observability.
    pub fn config(&self) -> &TieredRateConfig {
        &self.cfg
    }

    /// Check an IP against the tier quota. Also applies the
    /// miss-lockout for `SessionLookup` before incrementing the
    /// counter.
    pub fn check(&self, tier: Tier, ip: IpAddr) -> CheckOutcome {
        if tier == Tier::SessionLookup {
            if let Some(retry) = self.check_lookup_lockout(ip) {
                return CheckOutcome::RateLimited {
                    retry_after: Some(retry),
                };
            }
        }

        let (map, max) = match tier {
            Tier::SessionCreate => (&self.session_create, self.cfg.session_create_per_min),
            Tier::SessionLookup => (&self.session_lookup, self.cfg.session_lookup_per_min),
            Tier::Other => (&self.other, self.cfg.other_per_min),
            // SasSubmission goes through a different map (keyed by
            // session_id, not IP) via `check_sas_submission`; this arm
            // is unreachable in the normal `check` path.
            Tier::SasSubmission => return CheckOutcome::Allowed,
        };

        let mut guard = map.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let entry = guard.entry(ip).or_insert(WindowState {
            count: 0,
            window_start: now,
        });
        if entry.window_start.elapsed() >= self.cfg.window {
            *entry = WindowState {
                count: 0,
                window_start: now,
            };
        }
        entry.count += 1;
        if entry.count > max {
            // Retry-After hint = time until the current window expires.
            let remaining = self
                .cfg
                .window
                .saturating_sub(entry.window_start.elapsed());
            CheckOutcome::RateLimited {
                retry_after: Some(remaining),
            }
        } else {
            CheckOutcome::Allowed
        }
    }

    /// `SasSubmission` has a per-session lifetime counter rather than
    /// a per-IP rolling window. Called from the confirm handler.
    pub fn check_sas_submission(&self, session_id: &str) -> CheckOutcome {
        let mut guard = self.sas_submission.lock().unwrap_or_else(|e| e.into_inner());
        let entry = guard.entry(session_id.to_string()).or_insert(0);
        *entry += 1;
        if *entry > self.cfg.sas_submissions_per_session {
            CheckOutcome::RateLimited { retry_after: None }
        } else {
            CheckOutcome::Allowed
        }
    }

    /// Record the outcome of a `SessionLookup`. Hits decay the miss
    /// counter; misses increment it and, at threshold, compute a
    /// lockout deadline.
    pub fn record_lookup_outcome(&self, ip: IpAddr, was_hit: bool) {
        let mut guard = self.lookup_miss.lock().unwrap_or_else(|e| e.into_inner());
        let entry = guard.entry(ip).or_default();
        if was_hit {
            entry.consecutive_misses = 0;
            entry.locked_until = None;
            return;
        }
        entry.consecutive_misses = entry.consecutive_misses.saturating_add(1);
        if entry.consecutive_misses > self.cfg.lookup_miss_threshold {
            let over = entry.consecutive_misses - self.cfg.lookup_miss_threshold;
            // 2^(over-1), saturating.
            let factor = 1u64.checked_shl(over.saturating_sub(1)).unwrap_or(u64::MAX);
            let delay = self
                .cfg
                .lookup_miss_backoff_base
                .saturating_mul(factor.try_into().unwrap_or(u32::MAX))
                .min(self.cfg.lookup_miss_backoff_cap);
            entry.locked_until = Some(Instant::now() + delay);
        }
    }

    fn check_lookup_lockout(&self, ip: IpAddr) -> Option<Duration> {
        let guard = self.lookup_miss.lock().unwrap_or_else(|e| e.into_inner());
        let entry = guard.get(&ip)?;
        let until = entry.locked_until?;
        let now = Instant::now();
        if until > now { Some(until - now) } else { None }
    }
}

/// Classify an HTTP path + method into a tier. Called by the rate-
/// limit middleware.
pub fn classify_path(method: &axum::http::Method, path: &str) -> Tier {
    // Exact-prefix match on the stable route shapes. These strings
    // mirror `build_pairing_router`'s `.route(...)` calls.
    if method == axum::http::Method::POST {
        if path == "/v1/pairing/sessions" {
            return Tier::SessionCreate;
        }
        if path.ends_with("/confirm") {
            return Tier::SasSubmission;
        }
    }
    if method == axum::http::Method::GET && path.starts_with("/v1/pairing/sessions/by-code/") {
        return Tier::SessionLookup;
    }
    Tier::Other
}

/// Async helper: sleep until `start + floor`. Used by the lookup
/// handler to equalize hit/miss timing.
pub async fn uniform_time_floor(start: Instant, floor: Duration) {
    let deadline = start + floor;
    let now = Instant::now();
    if deadline > now {
        tokio::time::sleep(deadline - now).await;
    }
}

// ---------------------------------------------------------------------------
// Legacy single-tier shim
// ---------------------------------------------------------------------------
//
// Preserves the single-tier `RateLimiter::new(n)` API used by the
// existing test harnesses + the `PairingDaemonBuilder::with_rate_limiter`
// call path. New code should use `TieredRateLimiter` directly.
// ---------------------------------------------------------------------------

/// Thin wrapper around [`TieredRateLimiter`] that defaults to the
/// built-in config and applies a shared cap across every tier.
pub struct RateLimiter {
    inner: TieredRateLimiter,
}

impl RateLimiter {
    /// Create a legacy single-tier limiter. Internally constructs a
    /// [`TieredRateConfig`] where every per-min quota is the supplied
    /// `max_requests_per_minute` value.
    pub fn new(max_requests_per_minute: u32) -> Self {
        let cfg = TieredRateConfig {
            session_create_per_min: max_requests_per_minute,
            session_lookup_per_min: max_requests_per_minute,
            sas_submissions_per_session: max_requests_per_minute,
            other_per_min: max_requests_per_minute,
            ..TieredRateConfig::default()
        };
        Self {
            inner: TieredRateLimiter::new(cfg),
        }
    }

    /// Access the underlying tiered limiter.
    pub fn inner(&self) -> &TieredRateLimiter {
        &self.inner
    }

    /// Tier-agnostic check (for the single-tier shim). Counts against
    /// the `Other` bucket. Returns true if allowed.
    pub fn check(&self, ip: IpAddr) -> bool {
        matches!(self.inner.check(Tier::Other, ip), CheckOutcome::Allowed)
    }
}

#[cfg(feature = "server")]
pub(crate) mod middleware {
    use std::sync::Arc;

    use axum::{Extension, extract::ConnectInfo, http::Request, middleware::Next};

    use super::{CheckOutcome, RateLimiter, Tier, TieredRateLimiter, classify_path};
    use crate::error::DaemonError;

    /// Legacy middleware — used by existing test harnesses that wire
    /// up the single-tier shim. Counts every request against `Tier::Other`.
    pub async fn rate_limit_middleware(
        Extension(limiter): Extension<Arc<RateLimiter>>,
        ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
        request: axum::extract::Request,
        next: Next,
    ) -> Result<axum::response::Response, DaemonError> {
        if !limiter.check(addr.ip()) {
            return Err(DaemonError::RateLimited { retry_after: None });
        }
        Ok(next.run(request).await)
    }

    /// Tier-aware middleware. Classifies the request path and checks
    /// the matching tier quota. `Retry-After` is populated from
    /// [`CheckOutcome::RateLimited`] when available.
    #[allow(dead_code)]
    pub async fn tiered_rate_limit_middleware(
        Extension(limiter): Extension<Arc<TieredRateLimiter>>,
        ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
        request: Request<axum::body::Body>,
        next: Next,
    ) -> Result<axum::response::Response, DaemonError> {
        let tier = classify_path(request.method(), request.uri().path());
        match limiter.check(tier, addr.ip()) {
            CheckOutcome::Allowed => Ok(next.run(request).await),
            CheckOutcome::RateLimited { retry_after } => {
                Err(DaemonError::RateLimited { retry_after })
            }
        }
    }

    // Reference `Tier` so clippy doesn't trip if only the middleware
    // uses `classify_path` publicly — silence the unused-import lint
    // when feature combinations change.
    #[allow(dead_code)]
    fn _tier_import_referrer(_: Tier) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cfg() -> TieredRateConfig {
        TieredRateConfig {
            session_create_per_min: 2,
            session_lookup_per_min: 3,
            sas_submissions_per_session: 2,
            other_per_min: 10,
            lookup_miss_threshold: 2,
            lookup_miss_backoff_base: Duration::from_secs(1),
            lookup_miss_backoff_cap: Duration::from_secs(60),
            ..Default::default()
        }
    }

    #[test]
    fn session_create_tier_caps_at_configured_quota() {
        let l = TieredRateLimiter::new(test_cfg());
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(matches!(
            l.check(Tier::SessionCreate, ip),
            CheckOutcome::Allowed
        ));
        assert!(matches!(
            l.check(Tier::SessionCreate, ip),
            CheckOutcome::Allowed
        ));
        assert!(matches!(
            l.check(Tier::SessionCreate, ip),
            CheckOutcome::RateLimited { .. }
        ));
    }

    #[test]
    fn session_lookup_independent_from_session_create() {
        let l = TieredRateLimiter::new(test_cfg());
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        // Burn the create quota.
        let _ = l.check(Tier::SessionCreate, ip);
        let _ = l.check(Tier::SessionCreate, ip);
        // Lookup quota must still be fresh.
        assert!(matches!(
            l.check(Tier::SessionLookup, ip),
            CheckOutcome::Allowed
        ));
    }

    #[test]
    fn sas_submission_counter_is_per_session() {
        let l = TieredRateLimiter::new(test_cfg());
        assert!(matches!(
            l.check_sas_submission("s1"),
            CheckOutcome::Allowed
        ));
        assert!(matches!(
            l.check_sas_submission("s1"),
            CheckOutcome::Allowed
        ));
        assert!(matches!(
            l.check_sas_submission("s1"),
            CheckOutcome::RateLimited { .. }
        ));
        // A different session_id is tracked separately.
        assert!(matches!(
            l.check_sas_submission("s2"),
            CheckOutcome::Allowed
        ));
    }

    #[test]
    fn consecutive_lookup_misses_trigger_lockout() {
        let l = TieredRateLimiter::new(test_cfg());
        let ip: IpAddr = "192.168.1.5".parse().unwrap();

        // Three misses (threshold=2 → locks out on the 3rd).
        l.record_lookup_outcome(ip, false);
        l.record_lookup_outcome(ip, false);
        l.record_lookup_outcome(ip, false);

        // Next lookup check must be rate-limited with a Retry-After hint.
        match l.check(Tier::SessionLookup, ip) {
            CheckOutcome::RateLimited {
                retry_after: Some(d),
            } => {
                assert!(d <= Duration::from_secs(60));
                assert!(d > Duration::ZERO);
            }
            other => panic!("expected RateLimited with retry_after, got {other:?}"),
        }
    }

    #[test]
    fn first_hit_clears_lockout() {
        let l = TieredRateLimiter::new(test_cfg());
        let ip: IpAddr = "192.168.1.6".parse().unwrap();

        // Miss-miss-miss: locked.
        l.record_lookup_outcome(ip, false);
        l.record_lookup_outcome(ip, false);
        l.record_lookup_outcome(ip, false);
        assert!(matches!(
            l.check(Tier::SessionLookup, ip),
            CheckOutcome::RateLimited { .. }
        ));

        // First hit clears the lockout.
        l.record_lookup_outcome(ip, true);
        assert!(matches!(
            l.check(Tier::SessionLookup, ip),
            CheckOutcome::Allowed
        ));
    }

    #[test]
    fn classify_path_routes_to_correct_tier() {
        let get = axum::http::Method::GET;
        let post = axum::http::Method::POST;

        assert_eq!(
            classify_path(&post, "/v1/pairing/sessions"),
            Tier::SessionCreate
        );
        assert_eq!(
            classify_path(&get, "/v1/pairing/sessions/by-code/ABC123"),
            Tier::SessionLookup
        );
        assert_eq!(
            classify_path(&post, "/v1/pairing/sessions/abc/confirm"),
            Tier::SasSubmission
        );
        assert_eq!(classify_path(&get, "/health"), Tier::Other);
        assert_eq!(
            classify_path(&get, "/v1/pairing/sessions/abc/confirmation"),
            Tier::Other
        );
    }

    #[test]
    fn legacy_rate_limiter_shim_still_rejects_over_quota() {
        let l = RateLimiter::new(2);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(l.check(ip));
        assert!(l.check(ip));
        assert!(!l.check(ip));
    }

    #[test]
    fn different_ips_track_independently() {
        let l = TieredRateLimiter::new(test_cfg());
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        let b: IpAddr = "10.0.0.2".parse().unwrap();
        // Burn A's create quota.
        let _ = l.check(Tier::SessionCreate, a);
        let _ = l.check(Tier::SessionCreate, a);
        assert!(matches!(
            l.check(Tier::SessionCreate, a),
            CheckOutcome::RateLimited { .. }
        ));
        // B is fresh.
        assert!(matches!(
            l.check(Tier::SessionCreate, b),
            CheckOutcome::Allowed
        ));
    }
}
