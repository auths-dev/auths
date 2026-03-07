//! Ephemeral LAN HTTP server for single-session pairing.
//!
//! Binds to the detected LAN IP (not 0.0.0.0), validates a one-time
//! pairing token on mutating endpoints, and rate-limits per source IP.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use axum::{
    Json, Router,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    routing::{get, post},
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use subtle::ConstantTimeEq;
use tokio::sync::{Mutex, oneshot};
use tokio_util::sync::CancellationToken;

use auths_core::pairing::types::{
    CreateSessionRequest, GetSessionResponse, SessionStatus, SubmitResponseRequest, SuccessResponse,
};

const MAX_REQUESTS_PER_MINUTE: u32 = 5;

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

        let is_ptp = iface.name.starts_with("tun")
            || iface.name.starts_with("tap")
            || iface.name.starts_with("utun")
            || iface.name.starts_with("docker")
            || iface.name.starts_with("veth")
            || iface.name.starts_with("br-");
        candidates.push((ip, is_ptp));
    }

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
    pairing_token: Vec<u8>,
    rate_limits: Mutex<HashMap<IpAddr, (u32, Instant)>>,
}

/// An ephemeral HTTP server that serves exactly one pairing session.
pub struct LanPairingServer {
    addr: SocketAddr,
    cancel: CancellationToken,
    response_rx: oneshot::Receiver<SubmitResponseRequest>,
    _handle: tokio::task::JoinHandle<()>,
    pairing_token_b64: String,
}

impl LanPairingServer {
    /// Start the LAN pairing server bound to a specific LAN IP.
    ///
    /// Args:
    /// * `session`: The pairing session request data.
    /// * `bind_ip`: The LAN IP to bind to (from `detect_lan_ip()`).
    ///
    /// Returns the server and a base64url-encoded pairing token that must
    /// be included in the QR code for the mobile app to authenticate.
    pub async fn start(session: CreateSessionRequest, bind_ip: IpAddr) -> anyhow::Result<Self> {
        let (tx, rx) = oneshot::channel();
        let cancel = CancellationToken::new();

        let mut token_bytes = [0u8; 16];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut token_bytes)
            .map_err(|_| anyhow::anyhow!("failed to generate pairing token"))?;
        let pairing_token_b64 = URL_SAFE_NO_PAD.encode(token_bytes);

        let state = Arc::new(LanServerState {
            session,
            status: Mutex::new(SessionStatus::Pending),
            response_tx: Mutex::new(Some(tx)),
            pairing_token: token_bytes.to_vec(),
            rate_limits: Mutex::new(HashMap::new()),
        });

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
            .layer(middleware::from_fn_with_state(
                state.clone(),
                rate_limit_middleware,
            ))
            .with_state(state);

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

        let cancel_clone = cancel.clone();
        let handle = tokio::spawn(async move {
            let server = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            );
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
    #[allow(dead_code)]
    pub fn shutdown(self) {
        self.cancel.cancel();
    }
}

// --- Middleware ---

async fn rate_limit_middleware(
    State(state): State<Arc<LanServerState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: axum::extract::Request,
    next: Next,
) -> Result<axum::response::Response, StatusCode> {
    let ip = addr.ip();
    let now = Instant::now();
    let mut limits = state.rate_limits.lock().await;

    let entry = limits.entry(ip).or_insert((0, now));
    if now.duration_since(entry.1).as_secs() >= 60 {
        *entry = (0, now);
    }
    entry.0 += 1;
    if entry.0 > MAX_REQUESTS_PER_MINUTE {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    drop(limits);

    Ok(next.run(request).await)
}

fn validate_pairing_token(headers: &HeaderMap, expected: &[u8]) -> bool {
    let Some(value) = headers.get("X-Pairing-Token") else {
        return false;
    };
    let Ok(provided) = URL_SAFE_NO_PAD.decode(value.as_bytes()) else {
        return false;
    };
    provided.ct_eq(expected).into()
}

// --- Axum handlers ---

async fn handle_health() -> &'static str {
    "ok"
}

async fn handle_lookup_by_code(
    Path(code): Path<String>,
    State(state): State<Arc<LanServerState>>,
) -> Result<Json<GetSessionResponse>, StatusCode> {
    let normalized: String = code
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .flat_map(|c| c.to_uppercase())
        .collect();

    if normalized != state.session.short_code {
        return Err(StatusCode::NOT_FOUND);
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

async fn handle_get_session(
    Path(id): Path<String>,
    State(state): State<Arc<LanServerState>>,
) -> Result<Json<GetSessionResponse>, StatusCode> {
    if id != state.session.session_id {
        return Err(StatusCode::NOT_FOUND);
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

async fn handle_submit_response(
    Path(id): Path<String>,
    State(state): State<Arc<LanServerState>>,
    headers: HeaderMap,
    Json(request): Json<SubmitResponseRequest>,
) -> Result<Json<SuccessResponse>, StatusCode> {
    if !validate_pairing_token(&headers, &state.pairing_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    if id != state.session.session_id {
        return Err(StatusCode::NOT_FOUND);
    }

    {
        let status = *state.status.lock().await;
        if status != SessionStatus::Pending {
            return Err(StatusCode::CONFLICT);
        }
    }

    *state.status.lock().await = SessionStatus::Responded;

    let mut tx_guard = state.response_tx.lock().await;
    if let Some(tx) = tx_guard.take() {
        let _ = tx.send(request);
    }

    Ok(Json(SuccessResponse {
        success: true,
        message: "Response submitted".to_string(),
    }))
}
