use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, Notify, oneshot};
use tokio::time::Instant;

use auths_core::pairing::types::{
    CreateSessionRequest, GetConfirmationResponse, GetSessionResponse, SessionStatus,
    SubmitConfirmationRequest, SubmitResponseRequest, SuccessResponse,
};

/// Errors from session state transitions.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// The session is not in the expected state for this operation.
    #[error("session conflict: {0}")]
    Conflict(&'static str),
}

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
    pub(crate) status: Mutex<SessionStatus>,
    pub(crate) response_tx: Mutex<Option<oneshot::Sender<SubmitResponseRequest>>>,
    pub(crate) confirmation: Mutex<Option<SubmitConfirmationRequest>>,
    pub(crate) confirmation_notify: Arc<Notify>,
    pub(crate) pairing_token: Vec<u8>,
    /// Replay-protection cache shared across HMAC + Sig auth paths.
    /// Each `(kid, nonce)` is remembered for the nonce TTL window.
    #[cfg(feature = "server")]
    pub(crate) nonce_cache: crate::auth::NonceCache,
    /// First-use pubkey binding. Populated on the first successful
    /// `Auths-Sig` verification (typically `POST /response`);
    /// subsequent requests must be signed by the same key.
    #[cfg(feature = "server")]
    pub(crate) pubkey_binding: crate::auth::PubkeyBinding,
    /// Monotonic start-of-session timestamp. Paired with `ttl` to
    /// enforce expiry independent of wall-clock drift. `Instant`
    /// stops during process suspend on some platforms; for our
    /// 5-minute default TTL that's acceptable — on wake the session
    /// is simply considered fresh, which is fail-open in the
    /// direction of availability (the user can still try to pair).
    pub(crate) created_at: Instant,
    pub(crate) ttl: Duration,
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
        Self::new_with_ttl(
            session,
            pairing_token,
            response_tx,
            Duration::from_secs(300),
        )
    }

    /// Like [`new`][Self::new] but with an explicit TTL. Used by
    /// tests + callers that want to shorten the default 5-minute
    /// session lifetime.
    pub fn new_with_ttl(
        session: CreateSessionRequest,
        pairing_token: Vec<u8>,
        response_tx: oneshot::Sender<SubmitResponseRequest>,
        ttl: Duration,
    ) -> Self {
        Self {
            session,
            status: Mutex::new(SessionStatus::Pending),
            response_tx: Mutex::new(Some(response_tx)),
            confirmation: Mutex::new(None),
            confirmation_notify: Arc::new(Notify::new()),
            pairing_token,
            #[cfg(feature = "server")]
            nonce_cache: crate::auth::NonceCache::new(),
            #[cfg(feature = "server")]
            pubkey_binding: crate::auth::PubkeyBinding::new(),
            created_at: Instant::now(),
            ttl,
        }
    }

    /// Monotonic expiry check. Returns `true` when the session has
    /// outlived its configured TTL; the handler surface maps this to
    /// `DaemonError::SessionExpired` (410 Gone).
    pub fn is_expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.created_at) >= self.ttl
    }

    /// Convenience: read the monotonic creation timestamp. Exposed
    /// for callers that want to display "session expires in Xs" to
    /// the user.
    pub fn created_at(&self) -> Instant {
        self.created_at
    }

    /// Configured TTL.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Replay-protection cache for Authorization headers.
    #[cfg(feature = "server")]
    pub fn nonce_cache(&self) -> &crate::auth::NonceCache {
        &self.nonce_cache
    }

    /// First-use pubkey binding for this session.
    #[cfg(feature = "server")]
    pub fn pubkey_binding(&self) -> &crate::auth::PubkeyBinding {
        &self.pubkey_binding
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

    /// The raw transport token bytes — a unique per-session
    /// identifier embedded in e.g. the mDNS TXT record. Historically
    /// doubled as an HTTP bearer token; HTTP auth is now HMAC (for
    /// `/lookup`) or device signatures (for session-scoped
    /// endpoints), but consumers that only want a session nonce
    /// still use this.
    pub fn pairing_token(&self) -> &[u8] {
        &self.pairing_token
    }

    /// Look up the session by short code. Returns `None` if the code doesn't match.
    pub async fn lookup_by_code(&self, code: &str) -> Option<GetSessionResponse> {
        let normalized: String = code
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .flat_map(|c| c.to_uppercase())
            .collect();

        if normalized != self.session.short_code {
            return None;
        }

        let status = *self.status.lock().await;
        Some(GetSessionResponse {
            session_id: self.session.session_id.clone(),
            status,
            ttl_seconds: 300,
            token: Some(self.session.clone()),
            response: None,
        })
    }

    /// Get the session by ID. Returns `None` if the ID doesn't match.
    pub async fn get_session(&self, id: &str) -> Option<GetSessionResponse> {
        if id != self.session.session_id {
            return None;
        }

        let status = *self.status.lock().await;
        Some(GetSessionResponse {
            session_id: self.session.session_id.clone(),
            status,
            ttl_seconds: 300,
            token: Some(self.session.clone()),
            response: None,
        })
    }

    /// Submit a pairing response. Transitions status from Pending to Responded.
    pub async fn submit_response(
        &self,
        id: &str,
        request: SubmitResponseRequest,
    ) -> Result<SuccessResponse, SessionError> {
        if id != self.session.session_id {
            return Err(SessionError::Conflict("session ID mismatch"));
        }

        {
            let status = *self.status.lock().await;
            if status != SessionStatus::Pending {
                return Err(SessionError::Conflict("session not in pending state"));
            }
        }

        *self.status.lock().await = SessionStatus::Responded;

        let mut tx_guard = self.response_tx.lock().await;
        if let Some(tx) = tx_guard.take() {
            let _ = tx.send(request);
        }

        Ok(SuccessResponse {
            success: true,
            message: "Response submitted".to_string(),
        })
    }

    /// Submit a confirmation (SAS verified or aborted).
    pub async fn submit_confirmation(
        &self,
        id: &str,
        request: SubmitConfirmationRequest,
    ) -> Result<SuccessResponse, SessionError> {
        if id != self.session.session_id {
            return Err(SessionError::Conflict("session ID mismatch"));
        }

        let mut confirmation = self.confirmation.lock().await;
        if confirmation.is_some() {
            return Err(SessionError::Conflict("confirmation already submitted"));
        }

        let new_status = if request.aborted {
            SessionStatus::Aborted
        } else {
            SessionStatus::Confirmed
        };
        *self.status.lock().await = new_status;
        *confirmation = Some(request);
        drop(confirmation);

        self.confirmation_notify.notify_waiters();

        Ok(SuccessResponse {
            success: true,
            message: "Confirmation submitted".to_string(),
        })
    }

    /// Get the current confirmation state.
    pub async fn get_confirmation(&self, id: &str) -> Option<GetConfirmationResponse> {
        if id != self.session.session_id {
            return None;
        }

        let confirmation = self.confirmation.lock().await;
        Some(match &*confirmation {
            Some(req) => GetConfirmationResponse {
                encrypted_attestation: req.encrypted_attestation.clone(),
                aborted: req.aborted,
            },
            None => GetConfirmationResponse {
                encrypted_attestation: None,
                aborted: false,
            },
        })
    }
}
