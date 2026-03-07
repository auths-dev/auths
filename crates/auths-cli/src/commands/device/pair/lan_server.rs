//! Ephemeral LAN HTTP server for single-session pairing.
//!
//! Implements the same REST endpoints the mobile app expects, but serves
//! exactly one session from memory. No persistence, no rate limiting.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, post},
};
use tokio::sync::{Mutex, oneshot};
use tokio_util::sync::CancellationToken;
use tower_http::cors::{Any, CorsLayer};

use auths_core::pairing::types::{
    CreateSessionRequest, GetSessionResponse, SessionStatus, SubmitResponseRequest, SuccessResponse,
};

/// Detect the LAN IP address of this machine via interface enumeration.
///
/// Enumerates network interfaces and selects the best candidate:
/// loopback and link-local addresses are excluded, IPv4 is preferred,
/// and point-to-point interfaces (VPN/Docker tun) are deprioritized.
pub fn detect_lan_ip() -> std::io::Result<IpAddr> {
    let addrs = if_addrs::get_if_addrs().map_err(std::io::Error::other)?;

    let mut candidates: Vec<(IpAddr, bool)> = Vec::new();
    for iface in &addrs {
        if iface.is_loopback() {
            continue;
        }
        let ip = iface.ip();
        if ip.is_loopback() {
            continue;
        }
        match ip {
            IpAddr::V4(v4) if v4.is_link_local() => continue,
            IpAddr::V6(v6) if (v6.segments()[0] & 0xffc0) == 0xfe80 => continue,
            _ => {}
        }

        // Prefer non-point-to-point interfaces (heuristic: tun/tap names)
        let is_ptp = iface.name.starts_with("tun")
            || iface.name.starts_with("tap")
            || iface.name.starts_with("utun")
            || iface.name.starts_with("docker")
            || iface.name.starts_with("veth")
            || iface.name.starts_with("br-");
        candidates.push((ip, is_ptp));
    }

    // Sort: non-ptp before ptp, IPv4 before IPv6 within each group
    candidates.sort_by_key(|(ip, is_ptp)| (*is_ptp, !ip.is_ipv4()));

    candidates.first().map(|(ip, _)| *ip).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            "no suitable LAN interface found",
        )
    })
}

/// Internal state shared between the server and the caller.
struct LanServerState {
    session: CreateSessionRequest,
    status: Mutex<SessionStatus>,
    response_tx: Mutex<Option<oneshot::Sender<SubmitResponseRequest>>>,
}

/// An ephemeral HTTP server that serves exactly one pairing session.
pub struct LanPairingServer {
    addr: SocketAddr,
    cancel: CancellationToken,
    response_rx: oneshot::Receiver<SubmitResponseRequest>,
    _handle: tokio::task::JoinHandle<()>,
}

impl LanPairingServer {
    /// Start the LAN pairing server on an ephemeral port.
    ///
    /// Returns immediately with the server running in the background.
    pub async fn start(session: CreateSessionRequest) -> anyhow::Result<Self> {
        let (tx, rx) = oneshot::channel();
        let cancel = CancellationToken::new();

        let state = Arc::new(LanServerState {
            session,
            status: Mutex::new(SessionStatus::Pending),
            response_tx: Mutex::new(Some(tx)),
        });

        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any);

        let app = Router::new()
            .route("/health", get(handle_health))
            .route(
                "/v1/pairing/sessions/by-code/{code}",
                get(handle_lookup_by_code),
            )
            .route("/v1/pairing/sessions/{id}", get(handle_get_session))
            .route(
                "/v1/pairing/sessions/{id}/response",
                post(handle_submit_response),
            )
            .layer(cors)
            .with_state(state);

        // Bind to 0.0.0.0:0 to get an ephemeral port
        let listener =
            tokio::net::TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
                .await?;
        let addr = listener.local_addr()?;

        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            let server = axum::serve(listener, app);
            tokio::select! {
                _ = server => {}
                _ = cancel_clone.cancelled() => {}
            }
        });

        Ok(Self {
            addr,
            cancel,
            response_rx: rx,
            _handle: handle,
        })
    }

    /// The address the server is listening on.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Wait for a pairing response, with a timeout.
    ///
    /// Consumes `self` — the server shuts down after this returns.
    pub async fn wait_for_response(
        self,
        timeout: std::time::Duration,
    ) -> Result<SubmitResponseRequest, auths_core::pairing::PairingError> {
        let result = tokio::time::timeout(timeout, self.response_rx).await;
        self.cancel.cancel();

        match result {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => Err(auths_core::pairing::PairingError::LocalServerError(
                "Response channel closed".to_string(),
            )),
            Err(_) => Err(auths_core::pairing::PairingError::LanTimeout),
        }
    }

    /// Shut down the server without waiting for a response.
    #[allow(dead_code)] // public API for callers that need graceful shutdown without waiting
    pub fn shutdown(self) {
        self.cancel.cancel();
    }
}

// --- Axum handlers ---

/// GET /health — simple connectivity check
async fn handle_health() -> &'static str {
    "ok"
}

/// GET /v1/pairing/sessions/by-code/{code}
async fn handle_lookup_by_code(
    Path(code): Path<String>,
    State(state): State<Arc<LanServerState>>,
) -> Result<Json<GetSessionResponse>, axum::http::StatusCode> {
    let normalized: String = code
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .flat_map(|c| c.to_uppercase())
        .collect();

    if normalized != state.session.short_code {
        return Err(axum::http::StatusCode::NOT_FOUND);
    }

    let status = *state.status.lock().await;

    Ok(Json(GetSessionResponse {
        session_id: state.session.session_id.clone(),
        status,
        ttl_seconds: 300, // Approximation — the real expiry is in the token
        token: Some(state.session.clone()),
        response: None,
    }))
}

/// GET /v1/pairing/sessions/{id}
async fn handle_get_session(
    Path(id): Path<String>,
    State(state): State<Arc<LanServerState>>,
) -> Result<Json<GetSessionResponse>, axum::http::StatusCode> {
    if id != state.session.session_id {
        return Err(axum::http::StatusCode::NOT_FOUND);
    }

    let status = *state.status.lock().await;

    Ok(Json(GetSessionResponse {
        session_id: state.session.session_id.clone(),
        status,
        ttl_seconds: 300,
        token: Some(state.session.clone()),
        response: None,
    }))
}

/// POST /v1/pairing/sessions/{id}/response
async fn handle_submit_response(
    Path(id): Path<String>,
    State(state): State<Arc<LanServerState>>,
    Json(request): Json<SubmitResponseRequest>,
) -> Result<Json<SuccessResponse>, axum::http::StatusCode> {
    if id != state.session.session_id {
        return Err(axum::http::StatusCode::NOT_FOUND);
    }

    {
        let status = *state.status.lock().await;
        if status != SessionStatus::Pending {
            return Err(axum::http::StatusCode::CONFLICT);
        }
    }

    // Update status
    *state.status.lock().await = SessionStatus::Responded;

    // Signal the waiting caller
    let mut tx_guard = state.response_tx.lock().await;
    if let Some(tx) = tx_guard.take() {
        let _ = tx.send(request);
    }

    Ok(Json(SuccessResponse {
        success: true,
        message: "Response submitted".to_string(),
    }))
}
