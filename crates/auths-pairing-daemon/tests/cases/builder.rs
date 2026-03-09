use std::net::{IpAddr, Ipv4Addr};

use auths_pairing_daemon::{
    MockNetworkDiscovery, MockNetworkInterfaces, PairingDaemonBuilder, RateLimiter,
};

use super::test_session;

#[test]
fn builds_with_mock_implementations() {
    let mock_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
    let mock_addr = std::net::SocketAddr::new(mock_ip, 8080);

    let daemon = PairingDaemonBuilder::new()
        .with_network(MockNetworkInterfaces(mock_ip))
        .with_discovery(MockNetworkDiscovery(mock_addr))
        .with_rate_limiter(RateLimiter::new(10))
        .build(test_session())
        .unwrap();

    assert_eq!(daemon.bind_ip(), mock_ip);
    assert!(!daemon.token().is_empty());
}

#[test]
fn into_parts_splits_router_and_handle() {
    let mock_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let mock_addr = std::net::SocketAddr::new(mock_ip, 9090);

    let daemon = PairingDaemonBuilder::new()
        .with_network(MockNetworkInterfaces(mock_ip))
        .with_discovery(MockNetworkDiscovery(mock_addr))
        .build(test_session())
        .unwrap();

    let token = daemon.token().to_string();
    let (_router, handle) = daemon.into_parts();

    assert_eq!(handle.bind_ip(), mock_ip);
    assert_eq!(handle.token(), token);
}
