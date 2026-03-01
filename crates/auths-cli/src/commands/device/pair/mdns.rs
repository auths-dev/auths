//! mDNS advertisement and discovery for LAN pairing.
//!
//! Uses the `_auths-pair._tcp.local.` service type to advertise and
//! discover pairing sessions on the local network.
//!
//! mDNS is only needed for CLI-to-CLI join without QR.
//! QR-based pairing embeds IP:port directly.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};

const SERVICE_TYPE: &str = "_auths-pair._tcp.local.";

/// Advertises a pairing session via mDNS.
pub struct PairingAdvertiser {
    daemon: ServiceDaemon,
    fullname: String,
}

impl PairingAdvertiser {
    /// Start advertising a pairing session.
    ///
    /// - `port`: the TCP port the LAN server is listening on
    /// - `short_code`: the 6-char pairing short code
    /// - `controller_did`: the controller DID (included in TXT record)
    pub fn advertise(
        port: u16,
        short_code: &str,
        controller_did: &str,
    ) -> Result<Self, auths_core::pairing::PairingError> {
        let daemon = ServiceDaemon::new()
            .map_err(|e| auths_core::pairing::PairingError::MdnsError(e.to_string()))?;

        let instance_name = format!("auths-pair-{}", short_code.to_lowercase());
        let host = std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("HOST"))
            .unwrap_or_else(|_| "auths-device".to_string());
        let host_fqdn = format!("{}.local.", host);

        let properties = [("sc", short_code), ("v", "1"), ("did", controller_did)];

        let service_info = ServiceInfo::new(
            SERVICE_TYPE,
            &instance_name,
            &host_fqdn,
            "",
            port,
            &properties[..],
        )
        .map_err(|e| auths_core::pairing::PairingError::MdnsError(e.to_string()))?;

        let fullname = service_info.get_fullname().to_string();

        daemon
            .register(service_info)
            .map_err(|e| auths_core::pairing::PairingError::MdnsError(e.to_string()))?;

        Ok(Self { daemon, fullname })
    }

    /// Stop advertising and shut down the mDNS daemon.
    pub fn shutdown(self) {
        let _ = self.daemon.unregister(&self.fullname);
        let _ = self.daemon.shutdown();
    }
}

/// Discovers a pairing session via mDNS by matching the short code.
pub struct PairingDiscoverer;

impl PairingDiscoverer {
    /// Browse for a pairing session with the given short code.
    ///
    /// Returns the `SocketAddr` of the LAN server once found, or errors
    /// on timeout.
    pub fn discover(
        short_code: &str,
        timeout: Duration,
    ) -> Result<SocketAddr, auths_core::pairing::PairingError> {
        let daemon = ServiceDaemon::new()
            .map_err(|e| auths_core::pairing::PairingError::MdnsError(e.to_string()))?;

        let receiver = daemon
            .browse(SERVICE_TYPE)
            .map_err(|e| auths_core::pairing::PairingError::MdnsError(e.to_string()))?;

        let deadline = std::time::Instant::now() + timeout;
        let normalized_code = short_code.to_uppercase();

        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                let _ = daemon.shutdown();
                return Err(auths_core::pairing::PairingError::NoPeerFound);
            }

            match receiver.recv_timeout(remaining.min(Duration::from_secs(1))) {
                Ok(ServiceEvent::ServiceResolved(info)) => {
                    // Check if the TXT record has a matching short code
                    if let Some(sc) = info.get_property_val_str("sc")
                        && sc.to_uppercase() == normalized_code
                    {
                        let port = info.get_port();
                        // Prefer IPv4 addresses for LAN pairing
                        if let Some(addr) = info.get_addresses_v4().into_iter().next() {
                            let _ = daemon.shutdown();
                            return Ok(SocketAddr::new(IpAddr::V4(addr), port));
                        }
                    }
                }
                Ok(_) => {
                    // Other events — keep waiting
                }
                Err(_) => {
                    // Timeout or channel closed — deadline check at top of
                    // loop handles both cases.
                }
            }
        }
    }
}
