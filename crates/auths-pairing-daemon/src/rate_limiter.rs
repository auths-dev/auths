use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const WINDOW: Duration = Duration::from_secs(60);

/// Per-IP rate limiter with a sliding window.
///
/// Tracks request counts per source IP within a 60-second window.
/// When a window expires for an IP, the counter resets.
///
/// Args:
/// * `max_requests_per_minute`: Maximum requests allowed per IP within one window.
///
/// Usage:
/// ```ignore
/// let limiter = RateLimiter::new(5);
/// if limiter.check("192.168.1.10".parse().unwrap()) {
///     // request allowed
/// } else {
///     // rate limited — return 429
/// }
/// ```
pub struct RateLimiter {
    requests: Mutex<HashMap<IpAddr, (u32, Instant)>>,
    max_requests_per_minute: u32,
}

impl RateLimiter {
    /// Create a rate limiter with the given per-IP request limit.
    ///
    /// Args:
    /// * `max_requests_per_minute`: Maximum requests allowed per IP per minute.
    ///
    /// Usage:
    /// ```ignore
    /// let limiter = RateLimiter::new(5);
    /// ```
    pub fn new(max_requests_per_minute: u32) -> Self {
        Self {
            requests: Mutex::new(HashMap::new()),
            max_requests_per_minute,
        }
    }

    /// Check whether a request from the given IP is allowed.
    ///
    /// Returns `true` if the request is within the rate limit, `false` if it
    /// should be rejected. Thread-safe via `std::sync::Mutex`.
    ///
    /// Args:
    /// * `ip`: Source IP address of the incoming request.
    ///
    /// Usage:
    /// ```ignore
    /// let allowed = limiter.check(addr.ip());
    /// if !allowed {
    ///     return Err(StatusCode::TOO_MANY_REQUESTS);
    /// }
    /// ```
    pub fn check(&self, ip: IpAddr) -> bool {
        let mut requests = self.requests.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();

        let entry = requests.entry(ip).or_insert((0, now));
        reset_if_window_expired(entry, WINDOW);
        entry.0 += 1;

        is_within_limit(entry.0, self.max_requests_per_minute)
    }
}

fn reset_if_window_expired(entry: &mut (u32, Instant), window: Duration) {
    if entry.1.elapsed() >= window {
        *entry = (0, Instant::now());
    }
}

fn is_within_limit(count: u32, max: u32) -> bool {
    count <= max
}

#[cfg(feature = "server")]
pub(crate) mod middleware {
    use std::sync::Arc;

    use axum::{Extension, extract::ConnectInfo, middleware::Next};

    use super::RateLimiter;
    use crate::error::DaemonError;

    pub async fn rate_limit_middleware(
        Extension(limiter): Extension<Arc<RateLimiter>>,
        ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
        request: axum::extract::Request,
        next: Next,
    ) -> Result<axum::response::Response, DaemonError> {
        if !limiter.check(addr.ip()) {
            // fn-130.T1: flow through DaemonError so the central
            // IntoResponse impl emits the JSON body + (later) the
            // Retry-After header. T5 plugs the tiered limiter and
            // populates `retry_after`; until then the plain None
            // response matches the prior 429-no-header behavior.
            return Err(DaemonError::RateLimited { retry_after: None });
        }
        Ok(next.run(request).await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_requests_within_limit() {
        let limiter = RateLimiter::new(3);
        let ip: IpAddr = "192.168.1.1".parse().unwrap_or_else(|_| unreachable!());

        assert!(limiter.check(ip));
        assert!(limiter.check(ip));
        assert!(limiter.check(ip));
    }

    #[test]
    fn rejects_requests_over_limit() {
        let limiter = RateLimiter::new(2);
        let ip: IpAddr = "192.168.1.1".parse().unwrap_or_else(|_| unreachable!());

        assert!(limiter.check(ip));
        assert!(limiter.check(ip));
        assert!(!limiter.check(ip));
    }

    #[test]
    fn tracks_ips_independently() {
        let limiter = RateLimiter::new(1);
        let ip_a: IpAddr = "10.0.0.1".parse().unwrap_or_else(|_| unreachable!());
        let ip_b: IpAddr = "10.0.0.2".parse().unwrap_or_else(|_| unreachable!());

        assert!(limiter.check(ip_a));
        assert!(!limiter.check(ip_a));
        assert!(limiter.check(ip_b));
    }
}
