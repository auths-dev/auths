use std::future::Future;
use std::time::Duration;

use crate::pairing::{
    CreateSessionRequest, CreateSessionResponse, GetConfirmationResponse, GetSessionResponse,
    SubmitConfirmationRequest, SubmitResponseRequest,
};
use crate::ports::network::NetworkError;

/// Port trait for communicating with a pairing relay server.
///
/// Implementations handle transport details (HTTP, WebSocket, etc.).
/// SDK orchestrators depend only on this abstraction.
///
/// Usage:
/// ```ignore
/// use auths_core::ports::pairing::PairingRelayClient;
///
/// async fn run(relay: &impl PairingRelayClient, registry: &str) {
///     let resp = relay.create_session(registry, &request).await?;
/// }
/// ```
pub trait PairingRelayClient: Send + Sync {
    /// Creates a new pairing session on the relay server.
    ///
    /// Args:
    /// * `registry_url`: Base URL of the pairing relay server.
    /// * `request`: Session creation parameters including controller DID and capabilities.
    ///
    /// Usage:
    /// ```ignore
    /// let resp = relay.create_session("https://registry.example.com", &request).await?;
    /// ```
    fn create_session(
        &self,
        registry_url: &str,
        request: &CreateSessionRequest,
    ) -> impl Future<Output = Result<CreateSessionResponse, NetworkError>> + Send;

    /// Fetches the current state of a pairing session.
    ///
    /// Args:
    /// * `registry_url`: Base URL of the pairing relay server.
    /// * `session_id`: The session identifier returned by `create_session`.
    ///
    /// Usage:
    /// ```ignore
    /// let session = relay.get_session("https://registry.example.com", &session_id).await?;
    /// ```
    fn get_session(
        &self,
        registry_url: &str,
        session_id: &str,
    ) -> impl Future<Output = Result<GetSessionResponse, NetworkError>> + Send;

    /// Looks up a session by its short human-readable code.
    ///
    /// Args:
    /// * `registry_url`: Base URL of the pairing relay server.
    /// * `code`: The normalised short code (e.g. `"abc123"`).
    ///
    /// Usage:
    /// ```ignore
    /// let session = relay.lookup_by_code("https://registry.example.com", "abc123").await?;
    /// ```
    fn lookup_by_code(
        &self,
        registry_url: &str,
        code: &str,
    ) -> impl Future<Output = Result<GetSessionResponse, NetworkError>> + Send;

    /// Submits a device pairing response to a session.
    ///
    /// Args:
    /// * `registry_url`: Base URL of the pairing relay server.
    /// * `session_id`: The session to respond to.
    /// * `response`: The pairing response payload (device keys, DID, signature).
    ///
    /// Usage:
    /// ```ignore
    /// relay.submit_response("https://registry.example.com", &session_id, &response).await?;
    /// ```
    fn submit_response(
        &self,
        registry_url: &str,
        session_id: &str,
        response: &SubmitResponseRequest,
    ) -> impl Future<Output = Result<(), NetworkError>> + Send;

    /// Waits for a session to reach a terminal state, using WebSocket with HTTP polling fallback.
    ///
    /// Returns `None` if `timeout` elapses before any terminal state is reached.
    ///
    /// Args:
    /// * `registry_url`: Base URL of the pairing relay server.
    /// * `session_id`: The session to watch.
    /// * `timeout`: Maximum time to wait before returning `None`.
    ///
    /// Usage:
    /// ```ignore
    /// let result = relay.wait_for_update(registry, &session_id, Duration::from_secs(60)).await?;
    /// ```
    fn wait_for_update(
        &self,
        registry_url: &str,
        session_id: &str,
        timeout: Duration,
    ) -> impl Future<Output = Result<Option<GetSessionResponse>, NetworkError>> + Send;

    /// Submits a SAS confirmation (encrypted attestation or abort signal).
    ///
    /// Args:
    /// * `url`: Base URL of the pairing server.
    /// * `session_id`: The session to confirm.
    /// * `request`: The confirmation payload.
    fn submit_confirmation(
        &self,
        url: &str,
        session_id: &str,
        request: &SubmitConfirmationRequest,
    ) -> impl Future<Output = Result<(), NetworkError>> + Send;

    /// Polls for a SAS confirmation from the initiator.
    ///
    /// Args:
    /// * `url`: Base URL of the pairing server.
    /// * `session_id`: The session to check.
    fn get_confirmation(
        &self,
        url: &str,
        session_id: &str,
    ) -> impl Future<Output = Result<GetConfirmationResponse, NetworkError>> + Send;
}
