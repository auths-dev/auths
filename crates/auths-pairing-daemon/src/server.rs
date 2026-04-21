//! Builder API and runtime handle for the pairing daemon.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Semaphore, oneshot};

use auths_core::pairing::types::{CreateSessionRequest, SubmitResponseRequest};

use crate::discovery::{AdvertiseHandle, NetworkDiscovery};
use crate::error::DaemonError;
use crate::host_allowlist::HostAllowlist;
use crate::network::NetworkInterfaces;
use crate::rate_limiter::{RateLimiter, TieredRateConfig, TieredRateLimiter};
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
    rate_tiers: Option<TieredRateConfig>,
    network: Option<Box<dyn NetworkInterfaces>>,
    discovery: Option<Box<dyn NetworkDiscovery>>,
    cpu_budget: Option<Arc<Semaphore>>,
    cpu_budget_permits: Option<usize>,
    connection_cap: Option<Arc<Semaphore>>,
    connection_cap_permits: Option<usize>,
    session_ttl: Option<Duration>,
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
            rate_tiers: None,
            network: None,
            discovery: None,
            cpu_budget: None,
            cpu_budget_permits: None,
            connection_cap: None,
            connection_cap_permits: None,
            session_ttl: None,
        }
    }

    /// Cap the number of concurrent in-flight new-session creations.
    /// Override for tests; production uses `min(num_cpus, 4)`.
    pub fn with_cpu_budget(mut self, permits: usize) -> Self {
        self.cpu_budget_permits = Some(permits.max(1));
        self
    }

    /// Cap the number of concurrent TCP connections admitted to the
    /// daemon. Overflow connections are dropped at `accept()` before
    /// any bytes are read.
    pub fn with_connection_cap(mut self, permits: usize) -> Self {
        self.connection_cap_permits = Some(permits.max(1));
        self
    }

    /// Override the default 5-minute session lifetime. The expiry
    /// clock is monotonic (`tokio::time::Instant`), not wall-clock,
    /// so NTP adjustments or clock-skew attacks cannot extend a
    /// session.
    pub fn with_session_ttl(mut self, ttl: Duration) -> Self {
        self.session_ttl = Some(ttl);
        self
    }

    /// Override the tiered rate-limit configuration. When set, this
    /// takes precedence over the legacy `with_rate_limiter` path.
    ///
    /// Args:
    /// * `tiers`: A [`TieredRateConfig`] instance.
    pub fn with_rate_tiers(mut self, tiers: TieredRateConfig) -> Self {
        self.rate_tiers = Some(tiers);
        self
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
        // Health-check the OS CSPRNG before we spend any of its
        // output. On Linux, `OsRng` reads `getrandom(2)` which blocks
        // until the kernel pool is seeded; we additionally run NIST
        // SP 800-90B RCT + APT over a 4 KiB sample to catch a wedged
        // or insufficiently-seeded RNG. Refusal to start is the only
        // safe posture — silent low-entropy keys are a documented
        // class-breaking failure mode.
        {
            use crate::entropy_probe::{HealthRng, run_health_check};
            let mut rng = HealthRng::os_rng();
            run_health_check(&mut rng)?;
        }

        // Tier config takes precedence over legacy; if neither is set,
        // use TieredRateConfig::default() which matches plan tier
        // quotas (5/20/3/60 per minute).
        let tier_config = self.rate_tiers.unwrap_or_default();
        let tiered = Arc::new(TieredRateLimiter::new(tier_config));
        // `self.rate_limiter` is kept in the builder for
        // backward-compat but is no longer threaded through — the
        // tiered limiter is the single source of truth.
        let _legacy = self.rate_limiter;
        let network: Box<dyn NetworkInterfaces> = self.network.unwrap_or_else(default_network);
        let discovery: Option<Box<dyn NetworkDiscovery>> =
            self.discovery.or_else(default_discovery);

        let bind_ip = network.detect_lan_ip()?;
        let (token_bytes, token_b64) = generate_transport_token()?;

        // CPU-budget semaphore: bounded concurrency for admitting
        // new sessions. Rejection is 503 CapacityExhausted with a
        // Retry-After hint — the caller/handle owns the permit.
        let cpu_budget = self.cpu_budget.unwrap_or_else(|| {
            let permits = self.cpu_budget_permits.unwrap_or_else(|| {
                std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(4)
                    .min(4)
            });
            Arc::new(Semaphore::new(permits))
        });
        let permit =
            cpu_budget
                .clone()
                .try_acquire_owned()
                .map_err(|_| DaemonError::CapacityExhausted {
                    retry_after: Duration::from_secs(5),
                })?;

        // Connection-level cap is created here but acquired in the
        // accept loop (in the CLI layer). We just own the Arc so it
        // lives as long as the daemon.
        let connection_cap = self.connection_cap.unwrap_or_else(|| {
            let permits = self.connection_cap_permits.unwrap_or(128);
            Arc::new(Semaphore::new(permits))
        });

        let session_ttl = self.session_ttl.unwrap_or(Duration::from_secs(300));
        let (tx, rx) = oneshot::channel();
        let state = Arc::new(DaemonState::new_with_ttl(
            session,
            token_bytes,
            tx,
            session_ttl,
        ));

        // Router is built lazily in `into_parts`, once the caller
        // knows the bound port. We need the port to scope the Host
        // allowlist, so router construction has to wait until after
        // `TcpListener::bind`.
        Ok(PairingDaemon {
            state,
            tiered_limiter: tiered,
            response_rx: rx,
            token: token_b64,
            bind_ip,
            discovery,
            _cpu_permit: permit,
            connection_cap,
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
/// Call [`into_parts()`](PairingDaemon::into_parts) to split into the
/// Axum router (for serving) and a [`PairingDaemonHandle`] (for awaiting
/// responses). Router construction happens here so the caller can
/// first bind a `TcpListener`, read the chosen port, and pass a
/// [`HostAllowlist`] that scopes the Host/Origin/Referer middleware
/// to `<host>:<port>` matches.
pub struct PairingDaemon {
    state: Arc<DaemonState>,
    tiered_limiter: Arc<TieredRateLimiter>,
    response_rx: oneshot::Receiver<SubmitResponseRequest>,
    token: String,
    bind_ip: IpAddr,
    discovery: Option<Box<dyn NetworkDiscovery>>,
    /// Holds the CPU-budget permit for the lifetime of the daemon.
    /// Drop releases it so subsequent session creations can proceed.
    _cpu_permit: tokio::sync::OwnedSemaphorePermit,
    /// Shared semaphore for the TCP accept loop. `into_parts`
    /// surfaces this so the caller can acquire a permit per inbound
    /// connection.
    connection_cap: Arc<Semaphore>,
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
    /// Args:
    /// * `allowlist`: The production [`HostAllowlist`] — typically built
    ///   via [`HostAllowlist::for_bound_addr`] once the bound `SocketAddr`
    ///   is known.
    ///
    /// Usage:
    /// ```ignore
    /// let listener = TcpListener::bind((daemon.bind_ip(), 0)).await?;
    /// let addr = listener.local_addr()?;
    /// let allowlist = HostAllowlist::for_bound_addr(addr, None);
    /// let (router, handle) = daemon.into_parts(allowlist);
    /// ```
    pub fn into_parts(self, allowlist: HostAllowlist) -> (axum::Router, PairingDaemonHandle) {
        let router =
            build_pairing_router(self.state.clone(), self.tiered_limiter, Arc::new(allowlist));
        let handle = PairingDaemonHandle {
            state: self.state,
            response_rx: Some(self.response_rx),
            discovery: self.discovery,
            bind_ip: self.bind_ip,
            token: self.token,
            _cpu_permit: self._cpu_permit,
            connection_cap: self.connection_cap,
        };
        (router, handle)
    }
}

/// Handle for interacting with a running pairing daemon.
///
/// Owns the response channel, discovery, and state. Provides methods
/// to await pairing responses and advertise via mDNS.
pub struct PairingDaemonHandle {
    state: Arc<DaemonState>,
    response_rx: Option<oneshot::Receiver<SubmitResponseRequest>>,
    discovery: Option<Box<dyn NetworkDiscovery>>,
    bind_ip: IpAddr,
    token: String,
    _cpu_permit: tokio::sync::OwnedSemaphorePermit,
    /// Accept-loop connection cap. Caller acquires a permit
    /// per inbound `TcpStream`; dropping the permit (on connection
    /// close) lets a new connection through.
    connection_cap: Arc<Semaphore>,
}

impl PairingDaemonHandle {
    /// The accept-loop connection cap. Caller should
    /// `try_acquire_owned()` on each incoming `TcpStream` and drop
    /// the permit when the connection closes; if acquisition fails
    /// the connection should be closed without reading any bytes.
    pub fn connection_cap(&self) -> &Arc<Semaphore> {
        &self.connection_cap
    }

    /// The session mode this daemon was started for. Callers (e.g. the
    /// CLI pair wrapper) branch on this after `wait_for_response`
    /// returns to decide whether to create a fresh attestation or a
    /// superseding one. The daemon itself does not use this — its
    /// handshake verification is identical for both modes.
    pub fn session_mode(&self) -> auths_core::pairing::types::SessionMode {
        self.state.session().mode
    }
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
        &mut self,
        timeout: Duration,
    ) -> Result<SubmitResponseRequest, DaemonError> {
        let rx = self.response_rx.take().ok_or_else(|| {
            DaemonError::Pairing(auths_core::pairing::PairingError::LocalServerError(
                "Response channel already consumed".to_string(),
            ))
        })?;
        let result = tokio::time::timeout(timeout, rx).await;
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

    /// Wait for the paired device to POST `/confirm`.
    ///
    /// Must be called *after* a successful `wait_for_response` — the
    /// confirmation is only meaningful once the session has been bound
    /// to a device pubkey.
    ///
    /// Returns:
    /// * `Ok(Some(req))` if the device confirmed (match or abort).
    /// * `Ok(None)` if the timeout elapsed without a confirmation.
    ///
    /// The daemon-side listener stays up while this awaits; callers
    /// should keep the surrounding HTTP serve task alive. Common
    /// timeout is 3-5 seconds — the paired device auto-fires /confirm
    /// as soon as it processes /response.
    pub async fn wait_for_confirmation(
        &self,
        timeout: Duration,
    ) -> Option<auths_core::pairing::SubmitConfirmationRequest> {
        // Fast path: confirmation already arrived.
        {
            let guard = self.state.confirmation.lock().await;
            if let Some(c) = guard.as_ref() {
                return Some(c.clone());
            }
        }
        // Slow path: wait on notify with timeout.
        let notify = self.state.confirmation_notify.clone();
        let notified = notify.notified();
        tokio::pin!(notified);
        match tokio::time::timeout(timeout, notified).await {
            Ok(_) => self.state.confirmation.lock().await.clone(),
            Err(_) => None,
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
