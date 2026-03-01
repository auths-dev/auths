//! Clock provider abstraction for injectable time.

use chrono::{DateTime, Utc};

/// Provides the current wall-clock time, injectable for testing.
///
/// Implement this trait to decouple domain logic from `Utc::now()`.
/// Use [`SystemClock`] in production and `MockClock` (from `auths-test-utils`)
/// in tests.
///
/// Usage:
/// ```ignore
/// fn check_expiry(clock: &dyn ClockProvider, expires_at: DateTime<Utc>) -> bool {
///     clock.now() < expires_at
/// }
/// ```
pub trait ClockProvider: Send + Sync {
    /// Returns the current time.
    ///
    /// Usage:
    /// ```ignore
    /// let now = clock.now();
    /// ```
    fn now(&self) -> DateTime<Utc>;
}

/// Production clock that delegates to [`Utc::now`].
///
/// Usage:
/// ```ignore
/// let clock = SystemClock;
/// let timestamp = clock.now();
/// ```
pub struct SystemClock;

impl ClockProvider for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}
