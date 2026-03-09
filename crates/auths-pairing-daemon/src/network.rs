use std::net::IpAddr;

use crate::DaemonError;

/// Detects the best LAN IP address for binding a pairing server.
///
/// Implementations enumerate network interfaces and select a non-loopback,
/// non-link-local address, preferring physical interfaces and IPv4.
///
/// Usage:
/// ```ignore
/// let detector = IfAddrsNetworkInterfaces;
/// let lan_ip = detector.detect_lan_ip()?;
/// ```
pub trait NetworkInterfaces: Send + Sync {
    /// Detect the best LAN IP address on this machine.
    ///
    /// Args: (none — uses system network interfaces)
    ///
    /// Usage:
    /// ```ignore
    /// let ip = network.detect_lan_ip()?;
    /// let listener = TcpListener::bind((ip, 0)).await?;
    /// ```
    fn detect_lan_ip(&self) -> Result<IpAddr, DaemonError>;
}

fn is_viable_address(ip: &IpAddr) -> bool {
    if ip.is_loopback() {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => !v4.is_link_local(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) != 0xfe80,
    }
}

fn is_virtual_interface(name: &str) -> bool {
    name.starts_with("tun")
        || name.starts_with("tap")
        || name.starts_with("utun")
        || name.starts_with("docker")
        || name.starts_with("veth")
        || name.starts_with("br-")
}

#[cfg(feature = "server")]
pub struct IfAddrsNetworkInterfaces;

#[cfg(feature = "server")]
impl NetworkInterfaces for IfAddrsNetworkInterfaces {
    fn detect_lan_ip(&self) -> Result<IpAddr, DaemonError> {
        let addrs = if_addrs::get_if_addrs().map_err(DaemonError::NetworkDetectionFailed)?;

        let mut candidates: Vec<(IpAddr, bool)> = Vec::new();
        for iface in &addrs {
            let ip = iface.ip();
            if !is_viable_address(&ip) {
                continue;
            }
            candidates.push((ip, is_virtual_interface(&iface.name)));
        }

        candidates.sort_by_key(|(ip, is_virtual)| (*is_virtual, !ip.is_ipv4()));

        candidates.first().map(|(ip, _)| *ip).ok_or_else(|| {
            DaemonError::NetworkDetectionFailed(std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                "no suitable LAN interface found",
            ))
        })
    }
}

/// Mock network interface detector for testing.
///
/// Returns a fixed IP address without querying real interfaces.
///
/// Usage:
/// ```ignore
/// let mock = MockNetworkInterfaces(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
/// assert_eq!(mock.detect_lan_ip().unwrap(), "192.168.1.100".parse().unwrap());
/// ```
pub struct MockNetworkInterfaces(pub IpAddr);

impl NetworkInterfaces for MockNetworkInterfaces {
    fn detect_lan_ip(&self) -> Result<IpAddr, DaemonError> {
        Ok(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn viable_address_excludes_loopback() {
        assert!(!is_viable_address(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn viable_address_excludes_link_local() {
        assert!(!is_viable_address(&IpAddr::V4(Ipv4Addr::new(
            169, 254, 1, 1
        ))));
    }

    #[test]
    fn viable_address_accepts_lan() {
        assert!(is_viable_address(&IpAddr::V4(Ipv4Addr::new(
            192, 168, 1, 100
        ))));
    }

    #[test]
    fn virtual_interface_detection() {
        assert!(is_virtual_interface("docker0"));
        assert!(is_virtual_interface("tun0"));
        assert!(is_virtual_interface("utun3"));
        assert!(is_virtual_interface("veth1234"));
        assert!(is_virtual_interface("br-abc"));
        assert!(!is_virtual_interface("en0"));
        assert!(!is_virtual_interface("eth0"));
    }

    #[test]
    fn mock_returns_fixed_ip() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42));
        let mock = MockNetworkInterfaces(ip);
        assert_eq!(mock.detect_lan_ip().unwrap_or_else(|_| unreachable!()), ip);
    }
}
