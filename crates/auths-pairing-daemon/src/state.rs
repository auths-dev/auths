use std::sync::Arc;

use tokio::sync::{Mutex, Notify, oneshot};

use auths_core::pairing::types::{
    CreateSessionRequest, SessionStatus, SubmitConfirmationRequest, SubmitResponseRequest,
};

/// Shared state for a single pairing session.
///
/// Holds the session data, status, response channel, and confirmation
/// state for exactly one pairing interaction. Thread-safe via `Arc`.
///
/// Args:
/// * `session`: The pairing session request that initiated this daemon.
/// * `pairing_token`: Raw token bytes for authenticating mutating requests.
/// * `response_tx`: Oneshot sender for delivering the device response.
///
/// Usage:
/// ```ignore
/// let (tx, rx) = tokio::sync::oneshot::channel();
/// let state = DaemonState::new(session, token_bytes, tx);
/// let shared = Arc::new(state);
/// ```
pub struct DaemonState {
    pub(crate) session: CreateSessionRequest,
    // Used by handlers in fn-52.3
    #[allow(dead_code)]
    pub(crate) status: Mutex<SessionStatus>,
    #[allow(dead_code)]
    pub(crate) response_tx: Mutex<Option<oneshot::Sender<SubmitResponseRequest>>>,
    #[allow(dead_code)]
    pub(crate) confirmation: Mutex<Option<SubmitConfirmationRequest>>,
    #[allow(dead_code)]
    pub(crate) confirmation_notify: Arc<Notify>,
    pub(crate) pairing_token: Vec<u8>,
}

impl DaemonState {
    /// Create a new daemon state for a single pairing session.
    ///
    /// Args:
    /// * `session`: The pairing session request data.
    /// * `pairing_token`: Raw token bytes for request authentication.
    /// * `response_tx`: Oneshot sender; fires when the device submits a response.
    ///
    /// Usage:
    /// ```ignore
    /// let (tx, rx) = tokio::sync::oneshot::channel();
    /// let state = DaemonState::new(session_request, token_bytes, tx);
    /// ```
    pub fn new(
        session: CreateSessionRequest,
        pairing_token: Vec<u8>,
        response_tx: oneshot::Sender<SubmitResponseRequest>,
    ) -> Self {
        Self {
            session,
            status: Mutex::new(SessionStatus::Pending),
            response_tx: Mutex::new(Some(response_tx)),
            confirmation: Mutex::new(None),
            confirmation_notify: Arc::new(Notify::new()),
            pairing_token,
        }
    }

    /// The session request that this daemon is serving.
    ///
    /// Usage:
    /// ```ignore
    /// let session_id = state.session().session_id.clone();
    /// ```
    pub fn session(&self) -> &CreateSessionRequest {
        &self.session
    }

    /// The raw pairing token bytes used to authenticate mutating requests.
    ///
    /// Usage:
    /// ```ignore
    /// let is_valid = validate_pairing_token(headers, state.pairing_token());
    /// ```
    pub fn pairing_token(&self) -> &[u8] {
        &self.pairing_token
    }
}
