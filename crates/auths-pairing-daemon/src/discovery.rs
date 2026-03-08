use std::net::SocketAddr;
use std::time::Duration;

use crate::DaemonError;

/// Advertises and discovers pairing sessions on the local network.
///
/// Implementations handle the transport mechanism (mDNS, BLE, etc.)
/// for advertising a pairing server and discovering peers.
///
/// Usage:
/// ```ignore
/// let discovery = MdnsDiscovery;
/// let handle = discovery.advertise(8080, "ABC123", "did:keri:...")?;
/// // ... later
/// handle.shutdown();
/// ```
pub trait NetworkDiscovery: Send + Sync {
    /// Advertise a pairing session on the local network.
    ///
    /// Args:
    /// * `port`: TCP port the pairing server is listening on.
    /// * `short_code`: 6-character pairing short code.
    /// * `controller_did`: DID of the identity initiating the pairing.
    ///
    /// Usage:
    /// ```ignore
    /// let handle = discovery.advertise(port, &short_code, &controller_did)?;
    /// ```
    fn advertise(
        &self,
        port: u16,
        short_code: &str,
        controller_did: &str,
    ) -> Result<Box<dyn AdvertiseHandle>, DaemonError>;

    /// Discover a pairing session by short code.
    ///
    /// Blocks until a matching peer is found or the timeout elapses.
    /// Callers should use `tokio::task::spawn_blocking` if in an async context.
    ///
    /// Args:
    /// * `short_code`: The 6-character short code to search for.
    /// * `timeout`: Maximum time to wait for discovery.
    ///
    /// Usage:
    /// ```ignore
    /// let addr = discovery.discover("ABC123", Duration::from_secs(30))?;
    /// ```
    fn discover(&self, short_code: &str, timeout: Duration) -> Result<SocketAddr, DaemonError>;
}

/// Handle to a running advertisement that can be shut down.
///
/// `shutdown` consumes the handle. Errors are best-effort and not returned
/// since mDNS cleanup failures are not actionable.
pub trait AdvertiseHandle: Send + Sync {
    /// Stop advertising and release resources.
    fn shutdown(self: Box<Self>);
}

pub const SERVICE_TYPE: &str = "_auths-pair._tcp.local.";

#[cfg(feature = "mdns")]
mod mdns_impl {
    use std::net::{IpAddr, SocketAddr};
    use std::time::Duration;

    use mdns_sd::{ResolvedService, ServiceDaemon, ServiceEvent, ServiceInfo};

    use super::{AdvertiseHandle, DaemonError, NetworkDiscovery, SERVICE_TYPE};

    pub struct MdnsDiscovery;

    impl NetworkDiscovery for MdnsDiscovery {
        fn advertise(
            &self,
            port: u16,
            short_code: &str,
            controller_did: &str,
        ) -> Result<Box<dyn AdvertiseHandle>, DaemonError> {
            let daemon = ServiceDaemon::new().map_err(|e| DaemonError::MdnsError(e.to_string()))?;

            let instance_name = format!("auths-pair-{}", short_code.to_lowercase());
            // mDNS hostname is system-level config, not app config — EnvironmentConfig doesn't apply
            #[allow(clippy::disallowed_methods)]
            let host = std::env::var("HOSTNAME")
                .or_else(|_| std::env::var("HOST"))
                .unwrap_or_else(|_| "auths-device".to_string());
            let host_fqdn = format!("{}.local.", host);

            let properties = [("sc", short_code), ("v", "1"), ("did", controller_did)];

            let service_info: ServiceInfo = ServiceInfo::new(
                SERVICE_TYPE,
                &instance_name,
                &host_fqdn,
                "",
                port,
                &properties[..],
            )
            .map_err(|e: mdns_sd::Error| DaemonError::MdnsError(e.to_string()))?;

            let fullname = service_info.get_fullname().to_string();

            daemon
                .register(service_info)
                .map_err(|e| DaemonError::MdnsError(e.to_string()))?;

            Ok(Box::new(MdnsAdvertiseHandle { daemon, fullname }))
        }

        fn discover(&self, short_code: &str, timeout: Duration) -> Result<SocketAddr, DaemonError> {
            let daemon = ServiceDaemon::new().map_err(|e| DaemonError::MdnsError(e.to_string()))?;

            let receiver = daemon
                .browse(SERVICE_TYPE)
                .map_err(|e| DaemonError::MdnsError(e.to_string()))?;

            let deadline = std::time::Instant::now() + timeout;
            let normalized_code = short_code.to_uppercase();

            loop {
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                if remaining.is_zero() {
                    let _ = daemon.shutdown();
                    return Err(DaemonError::Pairing(
                        auths_core::pairing::PairingError::NoPeerFound,
                    ));
                }

                if let Ok(ServiceEvent::ServiceResolved(resolved)) =
                    receiver.recv_timeout(remaining.min(Duration::from_secs(1)))
                    && let Some(addr) = extract_matching_addr(&resolved, &normalized_code)
                {
                    let _ = daemon.shutdown();
                    return Ok(addr);
                }
            }
        }
    }

    fn extract_matching_addr(resolved: &ResolvedService, target_code: &str) -> Option<SocketAddr> {
        let sc = resolved.get_property_val_str("sc")?;
        if sc.to_uppercase() != target_code {
            return None;
        }
        let port = resolved.get_port();
        let addr = *resolved.get_addresses_v4().iter().next()?;
        Some(SocketAddr::new(IpAddr::V4(addr), port))
    }

    struct MdnsAdvertiseHandle {
        daemon: ServiceDaemon,
        fullname: String,
    }

    impl AdvertiseHandle for MdnsAdvertiseHandle {
        fn shutdown(self: Box<Self>) {
            let _ = self.daemon.unregister(&self.fullname);
            let _ = self.daemon.shutdown();
        }
    }
}

#[cfg(feature = "mdns")]
pub use mdns_impl::MdnsDiscovery;

/// Mock discovery for testing without real mDNS sockets.
///
/// `advertise` returns a no-op handle. `discover` returns a pre-configured address.
///
/// Usage:
/// ```ignore
/// let mock = MockNetworkDiscovery(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080));
/// let addr = mock.discover("ABC123", Duration::from_secs(1))?;
/// ```
pub struct MockNetworkDiscovery(pub SocketAddr);

impl NetworkDiscovery for MockNetworkDiscovery {
    fn advertise(
        &self,
        _port: u16,
        _short_code: &str,
        _controller_did: &str,
    ) -> Result<Box<dyn AdvertiseHandle>, DaemonError> {
        Ok(Box::new(NoOpAdvertiseHandle))
    }

    fn discover(&self, _short_code: &str, _timeout: Duration) -> Result<SocketAddr, DaemonError> {
        Ok(self.0)
    }
}

struct NoOpAdvertiseHandle;

impl AdvertiseHandle for NoOpAdvertiseHandle {
    fn shutdown(self: Box<Self>) {}
}
