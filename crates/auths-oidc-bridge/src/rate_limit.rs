//! Per-prefix rate limiting for the /token endpoint.

use std::num::NonZeroU32;

use governor::Quota;
use governor::RateLimiter as GovernorLimiter;
use governor::clock::{Clock, DefaultClock};
use governor::state::keyed::DashMapStateStore;

use crate::error::BridgeError;

#[allow(clippy::expect_used)] // Compile-time constant
const DEFAULT_RPM: NonZeroU32 = NonZeroU32::new(30).expect("30 is non-zero");
#[allow(clippy::expect_used)] // Compile-time constant
const DEFAULT_BURST: NonZeroU32 = NonZeroU32::new(5).expect("5 is non-zero");

/// Rate limiter keyed by KERI prefix.
pub struct PrefixRateLimiter {
    limiter: GovernorLimiter<String, DashMapStateStore<String>, DefaultClock>,
}

impl PrefixRateLimiter {
    /// Create a new rate limiter with the given requests per minute and burst size.
    pub fn new(requests_per_minute: u32, burst_size: u32) -> Self {
        let rpm = NonZeroU32::new(requests_per_minute).unwrap_or(DEFAULT_RPM);
        let burst = NonZeroU32::new(burst_size).unwrap_or(DEFAULT_BURST);
        let quota = Quota::per_minute(rpm).allow_burst(burst);

        Self {
            limiter: GovernorLimiter::dashmap(quota),
        }
    }

    /// Check if a request from the given KERI prefix is allowed.
    ///
    /// Returns `Ok(())` if the request is within the rate limit,
    /// or `Err(BridgeError::RateLimited)` if the prefix has exceeded its quota.
    pub fn check(&self, prefix: &str) -> Result<(), BridgeError> {
        self.limiter
            .check_key(&prefix.to_string())
            .map_err(|not_until| {
                let wait = not_until.wait_time_from(DefaultClock::default().now());
                BridgeError::RateLimited {
                    prefix: prefix.to_string(),
                    retry_after_secs: wait.as_secs() + 1,
                }
            })
    }
}
