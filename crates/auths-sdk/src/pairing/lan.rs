//! LAN pairing daemon facade.
//!
//! Feature-gated behind `lan-pairing`. Provides a convenience function
//! for constructing an embeddable pairing daemon from a session request.

pub use auths_pairing_daemon::{PairingDaemon, PairingDaemonBuilder, PairingDaemonHandle};

use std::time::Duration;

use auths_core::pairing::types::{CreateSessionRequest, SubmitSharedKelRotRequest};

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

/// Wait for (and take) a co-authored shared-KEL rotation received by the
/// daemon during this session.
///
/// The daemon verifies the envelope's indexed signatures at its HTTP
/// boundary and holds at most one rotation per session; this awaits
/// `shared_kel_rot_notify` and takes it for the host to replay against the
/// registry's prior key state
/// (`crate::domains::identity::shared_rot::apply_shared_kel_rot`).
///
/// Interest in the notifier is registered BEFORE the fast-path take, so a
/// rotation landing between the two cannot be missed. Returns `None` on
/// timeout.
///
/// Args:
/// * `handle`: The daemon handle for the live session.
/// * `timeout`: Maximum time to wait for the device to submit a rotation.
///
/// Usage:
/// ```ignore
/// if let Some(held) = wait_for_shared_kel_rot(&handle, Duration::from_secs(120)).await {
///     let applied = apply_shared_kel_rot(&held.rot_envelope, &prefix, registry.as_ref())?;
/// }
/// ```
pub async fn wait_for_shared_kel_rot(
    handle: &PairingDaemonHandle,
    timeout: Duration,
) -> Option<SubmitSharedKelRotRequest> {
    let state = handle.state();
    let notify = state.shared_kel_rot_notify();
    let notified = notify.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();

    if let Some(rot) = state.take_shared_kel_rot().await {
        return Some(rot);
    }
    match tokio::time::timeout(timeout, notified).await {
        Ok(()) => state.take_shared_kel_rot().await,
        Err(_) => None,
    }
}
