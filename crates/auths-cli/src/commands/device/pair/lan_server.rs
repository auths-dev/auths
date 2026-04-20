//! Thin CLI wrapper around `auths-pairing-daemon` for LAN pairing.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use auths_pairing_daemon::{HostAllowlist, PairingDaemonBuilder, PairingDaemonHandle};
use auths_sdk::pairing::{CreateSessionRequest, SubmitResponseRequest};

/// Detect the LAN IP address of this machine.
pub fn detect_lan_ip() -> std::io::Result<IpAddr> {
    let network = auths_pairing_daemon::IfAddrsNetworkInterfaces;
    auths_pairing_daemon::NetworkInterfaces::detect_lan_ip(&network)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, e.to_string()))
}

/// An ephemeral HTTP server that serves exactly one pairing session.
pub struct LanPairingServer {
    addr: SocketAddr,
    cancel: CancellationToken,
    handle: PairingDaemonHandle,
    _task: tokio::task::JoinHandle<()>,
    pairing_token_b64: String,
}

impl LanPairingServer {
    /// Start the LAN pairing server bound to a specific LAN IP.
    ///
    /// Args:
    /// * `session`: The pairing session request data.
    /// * `bind_ip`: The LAN IP to bind to (from `detect_lan_ip()`).
    pub async fn start(session: CreateSessionRequest, bind_ip: IpAddr) -> anyhow::Result<Self> {
        let daemon = PairingDaemonBuilder::new().build(session)?;
        let pairing_token_b64 = daemon.token().to_string();

        // Bind FIRST so we know the port, then build the router with
        // a Host/Origin/Referer allowlist scoped to the bound
        // `SocketAddr`. Reversing this order would either leave the
        // port unknown (fail-closed allowlist → 421 for every request)
        // or require mutable state in the middleware.
        let cancel = CancellationToken::new();
        let listener = tokio::net::TcpListener::bind(SocketAddr::new(bind_ip, 0))
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "Could not bind to {} — check that your device is on the correct \
                     network, or use relay-based pairing. ({})",
                    bind_ip,
                    e
                )
            })?;
        let addr = listener.local_addr()?;
        let allowlist = HostAllowlist::for_bound_addr(addr, None);
        let (router, handle) = daemon.into_parts(allowlist);

        let cancel_clone = cancel.clone();
        let task = tokio::spawn(async move {
            let server = axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            );
            tokio::select! {
                _ = server => {}
                _ = cancel_clone.cancelled() => {}
            }
        });

        Ok(Self {
            addr,
            cancel,
            handle,
            _task: task,
            pairing_token_b64,
        })
    }

    /// The address the server is listening on.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The base64url-encoded pairing token for QR code inclusion.
    pub fn pairing_token(&self) -> &str {
        &self.pairing_token_b64
    }

    /// Advertise via mDNS if discovery is available.
    pub fn advertise(
        &self,
        port: u16,
        short_code: &str,
        controller_did: &str,
    ) -> Option<
        Result<Box<dyn auths_pairing_daemon::AdvertiseHandle>, auths_pairing_daemon::DaemonError>,
    > {
        self.handle.advertise(port, short_code, controller_did)
    }

    /// Wait for a pairing response, with a timeout.
    ///
    /// Consumes `self` — the server shuts down after this returns.
    pub async fn wait_for_response(
        self,
        timeout: Duration,
    ) -> Result<SubmitResponseRequest, auths_sdk::error::PairingError> {
        self.cancel.cancel();

        self.handle
            .wait_for_response(timeout)
            .await
            .map_err(|e| match e {
                auths_pairing_daemon::DaemonError::Pairing(pe) => pe,
                other => auths_sdk::error::PairingError::LocalServerError(other.to_string()),
            })
    }
}
