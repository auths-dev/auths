//! Builder API and runtime handle for the pairing daemon.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::oneshot;

use auths_core::pairing::types::{CreateSessionRequest, SubmitResponseRequest};

use crate::discovery::{AdvertiseHandle, NetworkDiscovery};
use crate::error::DaemonError;
use crate::network::NetworkInterfaces;
use crate::rate_limiter::RateLimiter;
use crate::router::build_pairing_router;
use crate::state::DaemonState;
use crate::token::generate_transport_token;

/// Builder for constructing a [`PairingDaemon`].
///
/// All dependencies default to production implementations when built with
/// the appropriate features (`server`, `mdns`). Override any dependency
/// for testing by calling the `with_*` methods before `build()`.
///
/// Usage:
/// ```ignore
/// let daemon = PairingDaemonBuilder::new()
///     .build(session_request)?;
///
/// let (router, handle) = daemon.into_parts();
/// let listener = TcpListener::bind((handle.bind_ip(), 0)).await?;
/// tokio::spawn(axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()));
///
/// let response = handle.wait_for_response(Duration::from_secs(300)).await?;
/// ```
pub struct PairingDaemonBuilder {
    rate_limiter: Option<RateLimiter>,
    network: Option<Box<dyn NetworkInterfaces>>,
    discovery: Option<Box<dyn NetworkDiscovery>>,
}

impl PairingDaemonBuilder {
    /// Create a new builder with all fields set to `None` (defaults applied in `build()`).
    ///
    /// Usage:
    /// ```ignore
    /// let builder = PairingDaemonBuilder::new();
    /// ```
    pub fn new() -> Self {
        Self {
            rate_limiter: None,
            network: None,
            discovery: None,
        }
    }

    /// Override the rate limiter.
    ///
    /// Args:
    /// * `limiter`: Custom rate limiter instance.
    ///
    /// Usage:
    /// ```ignore
    /// let builder = PairingDaemonBuilder::new()
    ///     .with_rate_limiter(RateLimiter::new(10));
    /// ```
    pub fn with_rate_limiter(mut self, limiter: RateLimiter) -> Self {
        self.rate_limiter = Some(limiter);
        self
    }

    /// Override the network interface detector.
    ///
    /// Args:
    /// * `network`: Implementation of [`NetworkInterfaces`].
    ///
    /// Usage:
    /// ```ignore
    /// let builder = PairingDaemonBuilder::new()
    ///     .with_network(MockNetworkInterfaces("10.0.0.1".parse().unwrap()));
    /// ```
    pub fn with_network(mut self, network: impl NetworkInterfaces + 'static) -> Self {
        self.network = Some(Box::new(network));
        self
    }

    /// Override the mDNS discovery implementation.
    ///
    /// Args:
    /// * `discovery`: Implementation of [`NetworkDiscovery`].
    ///
    /// Usage:
    /// ```ignore
    /// let builder = PairingDaemonBuilder::new()
    ///     .with_discovery(MockNetworkDiscovery(addr));
    /// ```
    pub fn with_discovery(mut self, discovery: impl NetworkDiscovery + 'static) -> Self {
        self.discovery = Some(Box::new(discovery));
        self
    }

    /// Build the pairing daemon from the session request.
    ///
    /// Detects the LAN IP, generates a transport token, constructs the router,
    /// and returns a [`PairingDaemon`] ready for serving.
    ///
    /// Args:
    /// * `session`: The pairing session request data.
    ///
    /// Usage:
    /// ```ignore
    /// let daemon = PairingDaemonBuilder::new().build(session)?;
    /// ```
    pub fn build(self, session: CreateSessionRequest) -> Result<PairingDaemon, DaemonError> {
        // fn-128.T7: health-check the OS CSPRNG before we spend any of its
        // output. On Linux, `OsRng` reads `getrandom(2)` which blocks until
        // the kernel pool is seeded; we additionally run NIST SP 800-90B
        // RCT + APT over a 4 KiB sample to catch a wedged or insufficiently-
        // seeded RNG. Refusal to start is the only safe posture — silent
        // low-entropy keys are a documented class-breaking failure mode.
        {
            use crate::entropy_probe::{HealthRng, run_health_check};
            let mut rng = HealthRng::os_rng();
            run_health_check(&mut rng)?;
        }

        let rate_limiter = self.rate_limiter.unwrap_or_else(|| RateLimiter::new(5));
        let network: Box<dyn NetworkInterfaces> = self.network.unwrap_or_else(default_network);
        let discovery: Option<Box<dyn NetworkDiscovery>> =
            self.discovery.or_else(default_discovery);

        let bind_ip = network.detect_lan_ip()?;
        let (token_bytes, token_b64) = generate_transport_token()?;

        let (tx, rx) = oneshot::channel();
        let state = Arc::new(DaemonState::new(session, token_bytes, tx));
        let rate_limiter = Arc::new(rate_limiter);

        let router = build_pairing_router(state.clone(), rate_limiter);

        Ok(PairingDaemon {
            router,
            state,
            response_rx: rx,
            token: token_b64,
            bind_ip,
            discovery,
        })
    }
}

impl Default for PairingDaemonBuilder {
    fn default() -> Self {
        Self::new()
    }
}

fn default_network() -> Box<dyn NetworkInterfaces> {
    #[cfg(feature = "server")]
    {
        Box::new(crate::network::IfAddrsNetworkInterfaces)
    }
    #[cfg(not(feature = "server"))]
    {
        compile_error!("PairingDaemonBuilder requires the `server` feature")
    }
}

fn default_discovery() -> Option<Box<dyn NetworkDiscovery>> {
    #[cfg(feature = "mdns")]
    {
        Some(Box::new(crate::discovery::MdnsDiscovery))
    }
    #[cfg(not(feature = "mdns"))]
    {
        None
    }
}

/// A fully configured pairing daemon ready to serve.
///
/// Call [`into_parts()`](PairingDaemon::into_parts) to split into the Axum
/// router (for serving) and a [`PairingDaemonHandle`] (for awaiting responses).
pub struct PairingDaemon {
    router: axum::Router,
    state: Arc<DaemonState>,
    response_rx: oneshot::Receiver<SubmitResponseRequest>,
    token: String,
    bind_ip: IpAddr,
    discovery: Option<Box<dyn NetworkDiscovery>>,
}

impl PairingDaemon {
    /// The base64url-encoded transport token for QR code inclusion.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// The detected LAN IP address to bind to.
    pub fn bind_ip(&self) -> IpAddr {
        self.bind_ip
    }

    /// Split the daemon into router and handle.
    ///
    /// The router should be passed to `axum::serve`. The handle provides
    /// `wait_for_response` and `advertise` methods.
    ///
    /// Usage:
    /// ```ignore
    /// let (router, handle) = daemon.into_parts();
    /// ```
    pub fn into_parts(self) -> (axum::Router, PairingDaemonHandle) {
        let handle = PairingDaemonHandle {
            state: self.state,
            response_rx: self.response_rx,
            discovery: self.discovery,
            bind_ip: self.bind_ip,
            token: self.token,
        };
        (self.router, handle)
    }
}

/// Handle for interacting with a running pairing daemon.
///
/// Owns the response channel, discovery, and state. Provides methods
/// to await pairing responses and advertise via mDNS.
pub struct PairingDaemonHandle {
    state: Arc<DaemonState>,
    response_rx: oneshot::Receiver<SubmitResponseRequest>,
    discovery: Option<Box<dyn NetworkDiscovery>>,
    bind_ip: IpAddr,
    token: String,
}

impl PairingDaemonHandle {
    /// Wait for a device to submit a pairing response.
    ///
    /// Consumes the handle. Returns the response or a timeout error.
    ///
    /// Args:
    /// * `timeout`: Maximum time to wait for a response.
    ///
    /// Usage:
    /// ```ignore
    /// let response = handle.wait_for_response(Duration::from_secs(300)).await?;
    /// ```
    pub async fn wait_for_response(
        self,
        timeout: Duration,
    ) -> Result<SubmitResponseRequest, DaemonError> {
        let result = tokio::time::timeout(timeout, self.response_rx).await;
        match result {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => Err(DaemonError::Pairing(
                auths_core::pairing::PairingError::LocalServerError(
                    "Response channel closed".to_string(),
                ),
            )),
            Err(_) => Err(DaemonError::Pairing(
                auths_core::pairing::PairingError::LanTimeout,
            )),
        }
    }

    /// Start mDNS advertisement for this pairing session.
    ///
    /// Returns `None` if no discovery implementation is configured.
    ///
    /// Args:
    /// * `port`: TCP port the server is listening on.
    /// * `short_code`: The 6-character pairing code.
    /// * `controller_did`: DID of the initiating identity.
    ///
    /// Usage:
    /// ```ignore
    /// let advertiser = handle.advertise(port, &short_code, &did)?;
    /// ```
    pub fn advertise(
        &self,
        port: u16,
        short_code: &str,
        controller_did: &str,
    ) -> Option<Result<Box<dyn AdvertiseHandle>, DaemonError>> {
        self.discovery
            .as_ref()
            .map(|d| d.advertise(port, short_code, controller_did))
    }

    /// The shared daemon state.
    pub fn state(&self) -> &Arc<DaemonState> {
        &self.state
    }

    /// The detected LAN IP address.
    pub fn bind_ip(&self) -> IpAddr {
        self.bind_ip
    }

    /// The base64url-encoded transport token.
    pub fn token(&self) -> &str {
        &self.token
    }
}
