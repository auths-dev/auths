use auths_core::ports::clock::ClockProvider;
use chrono::{DateTime, Utc};

/// Fixed-time clock for deterministic tests.
///
/// Returns the same timestamp on every call to [`ClockProvider::now`],
/// making time-dependent logic reproducible in tests.
///
/// Usage:
/// ```ignore
/// use auths_test_utils::fakes::clock::MockClock;
/// use chrono::Utc;
///
/// let fixed = Utc::now();
/// let clock = MockClock(fixed);
/// assert_eq!(clock.now(), fixed);
/// ```
pub struct MockClock(pub DateTime<Utc>);

impl ClockProvider for MockClock {
    fn now(&self) -> DateTime<Utc> {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn mock_clock_returns_fixed_time() {
        let fixed = Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap();
        let clock = MockClock(fixed);
        assert_eq!(clock.now(), fixed);
        assert_eq!(clock.now(), fixed);
    }
}
