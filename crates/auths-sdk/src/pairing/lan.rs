//! LAN pairing daemon facade.
//!
//! Feature-gated behind `lan-pairing`. Provides a convenience function
//! for constructing an embeddable pairing daemon from a session request.

pub use auths_pairing_daemon::{PairingDaemon, PairingDaemonBuilder, PairingDaemonHandle};

use auths_core::pairing::types::CreateSessionRequest;

use super::PairingError;

/// Create a LAN pairing daemon from a session request using default configuration.
///
/// Constructs a [`PairingDaemonBuilder`] with production defaults (real network
/// detection, mDNS discovery if available, rate limiter) and builds the daemon.
/// The caller owns binding, serving, and shutdown.
///
/// Note: `now` is not needed here — clock injection applies to session *creation*
/// (via [`super::build_pairing_session_request`]), not daemon construction.
///
/// Args:
/// * `session`: The pairing session request data (from [`super::build_pairing_session_request`]).
///
/// Usage:
/// ```ignore
/// use auths_sdk::pairing::lan::create_lan_pairing_daemon;
/// use std::net::SocketAddr;
///
/// let session_req = build_pairing_session_request(now, params)?;
/// let daemon = create_lan_pairing_daemon(session_req.create_request)?;
/// let (router, handle) = daemon.into_parts();
///
/// let listener = tokio::net::TcpListener::bind(
///     SocketAddr::new(handle.bind_ip(), 0)
/// ).await?;
/// tokio::spawn(axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()));
///
/// let response = handle.wait_for_response(Duration::from_secs(300)).await?;
/// ```
pub fn create_lan_pairing_daemon(
    session: CreateSessionRequest,
) -> Result<PairingDaemon, PairingError> {
    PairingDaemonBuilder::new()
        .build(session)
        .map_err(|e| PairingError::DaemonError(e.to_string()))
}
