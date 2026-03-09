use std::net::IpAddr;

use auths_pairing_daemon::RateLimiter;

#[test]
fn allows_requests_within_limit() {
    let limiter = RateLimiter::new(5);
    let ip: IpAddr = "10.0.0.1".parse().unwrap();

    for i in 0..5 {
        assert!(limiter.check(ip), "request {i} should be allowed");
    }
}

#[test]
fn blocks_after_burst_exceeded() {
    let limiter = RateLimiter::new(3);
    let ip: IpAddr = "10.0.0.1".parse().unwrap();

    for _ in 0..3 {
        assert!(limiter.check(ip));
    }

    assert!(!limiter.check(ip), "4th request should be blocked");
}

#[test]
fn tracks_ips_independently() {
    let limiter = RateLimiter::new(2);
    let ip_a: IpAddr = "10.0.0.1".parse().unwrap();
    let ip_b: IpAddr = "10.0.0.2".parse().unwrap();

    assert!(limiter.check(ip_a));
    assert!(limiter.check(ip_a));
    assert!(!limiter.check(ip_a));

    assert!(
        limiter.check(ip_b),
        "different IP should have its own counter"
    );
}
