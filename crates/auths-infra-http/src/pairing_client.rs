use std::future::Future;
use std::time::Duration;

use auths_core::pairing::{
    CreateSessionRequest, CreateSessionResponse, GetSessionResponse, SessionStatus,
    SubmitResponseRequest,
};
use auths_core::ports::network::NetworkError;
use auths_core::ports::pairing::PairingRelayClient;

use crate::default_http_client;
use crate::error::{map_reqwest_error, map_status_error};

const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// HTTP-backed implementation of [`PairingRelayClient`].
///
/// Uses WebSocket for real-time session updates with HTTP polling as a fallback
/// when WebSocket is unavailable.
///
/// Usage:
/// ```ignore
/// use auths_infra_http::HttpPairingRelayClient;
///
/// let relay = HttpPairingRelayClient::new();
/// let response = relay.create_session("https://registry.example.com", &request).await?;
/// ```
pub struct HttpPairingRelayClient {
    client: reqwest::Client,
}

impl HttpPairingRelayClient {
    /// Creates a new client with a default reqwest client.
    pub fn new() -> Self {
        Self {
            client: default_http_client(),
        }
    }
}

impl Default for HttpPairingRelayClient {
    fn default() -> Self {
        Self::new()
    }
}

impl PairingRelayClient for HttpPairingRelayClient {
    fn create_session(
        &self,
        registry_url: &str,
        request: &CreateSessionRequest,
    ) -> impl Future<Output = Result<CreateSessionResponse, NetworkError>> + Send {
        let url = format!("{}/v1/pairing/sessions", registry_url.trim_end_matches('/'));
        let endpoint = registry_url.to_string();
        // Serialize JSON at call time so the future owns the request bytes.
        let req = self.client.post(&url).json(request);

        async move {
            let resp = req
                .send()
                .await
                .map_err(|e| map_reqwest_error(e, &endpoint))?;
            if !resp.status().is_success() {
                return Err(map_status_error(resp.status().as_u16(), &url));
            }
            resp.json::<CreateSessionResponse>()
                .await
                .map_err(|e| NetworkError::InvalidResponse {
                    detail: e.to_string(),
                })
        }
    }

    fn get_session(
        &self,
        registry_url: &str,
        session_id: &str,
    ) -> impl Future<Output = Result<GetSessionResponse, NetworkError>> + Send {
        let url = format!(
            "{}/v1/pairing/sessions/{}",
            registry_url.trim_end_matches('/'),
            session_id
        );
        let endpoint = registry_url.to_string();
        let req = self.client.get(&url);

        async move {
            let resp = req
                .send()
                .await
                .map_err(|e| map_reqwest_error(e, &endpoint))?;
            if !resp.status().is_success() {
                return Err(map_status_error(resp.status().as_u16(), &url));
            }
            resp.json::<GetSessionResponse>()
                .await
                .map_err(|e| NetworkError::InvalidResponse {
                    detail: e.to_string(),
                })
        }
    }

    fn lookup_by_code(
        &self,
        registry_url: &str,
        code: &str,
    ) -> impl Future<Output = Result<GetSessionResponse, NetworkError>> + Send {
        let url = format!(
            "{}/v1/pairing/sessions/by-code/{}",
            registry_url.trim_end_matches('/'),
            code
        );
        let endpoint = registry_url.to_string();
        let req = self.client.get(&url);

        async move {
            let resp = req
                .send()
                .await
                .map_err(|e| map_reqwest_error(e, &endpoint))?;
            if !resp.status().is_success() {
                return Err(map_status_error(resp.status().as_u16(), &url));
            }
            resp.json::<GetSessionResponse>()
                .await
                .map_err(|e| NetworkError::InvalidResponse {
                    detail: e.to_string(),
                })
        }
    }

    fn submit_response(
        &self,
        registry_url: &str,
        session_id: &str,
        response: &SubmitResponseRequest,
    ) -> impl Future<Output = Result<(), NetworkError>> + Send {
        let url = format!(
            "{}/v1/pairing/sessions/{}/response",
            registry_url.trim_end_matches('/'),
            session_id
        );
        let endpoint = registry_url.to_string();
        let req = self.client.post(&url).json(response);

        async move {
            let resp = req
                .send()
                .await
                .map_err(|e| map_reqwest_error(e, &endpoint))?;
            if !resp.status().is_success() {
                return Err(map_status_error(resp.status().as_u16(), &url));
            }
            Ok(())
        }
    }

    fn wait_for_update(
        &self,
        registry_url: &str,
        session_id: &str,
        timeout: Duration,
    ) -> impl Future<Output = Result<Option<GetSessionResponse>, NetworkError>> + Send {
        let session_url = format!(
            "{}/v1/pairing/sessions/{}",
            registry_url.trim_end_matches('/'),
            session_id
        );
        let ws_url = format!(
            "{}/v1/pairing/sessions/{}/ws",
            registry_url
                .replace("http://", "ws://")
                .replace("https://", "wss://")
                .trim_end_matches('/'),
            session_id
        );
        let endpoint = registry_url.to_string();
        // Clone the client so the future owns it without borrowing &self.
        let client = self.client.clone();

        async move {
            let deadline = tokio::time::Instant::now() + timeout;

            if let Ok((ws_stream, _)) = tokio_tungstenite::connect_async(&ws_url).await {
                use futures_util::StreamExt;
                let (_, mut read) = ws_stream.split();
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep_until(deadline) => return Ok(None),
                        msg = read.next() => match msg {
                            Some(Ok(tokio_tungstenite::tungstenite::Message::Text(text))) => {
                                if text.contains("\"responded\"")
                                    || text.contains("\"cancelled\"")
                                    || text.contains("\"expired\"")
                                {
                                    let resp = client
                                        .get(&session_url)
                                        .send()
                                        .await
                                        .map_err(|e| map_reqwest_error(e, &endpoint))?;
                                    return resp
                                        .json::<GetSessionResponse>()
                                        .await
                                        .map(Some)
                                        .map_err(|e| NetworkError::InvalidResponse {
                                            detail: e.to_string(),
                                        });
                                }
                            }
                            None | Some(Err(_)) => break,
                            _ => {}
                        },
                    }
                }
            }

            // Fallback: HTTP polling
            let start = std::time::Instant::now();
            loop {
                if start.elapsed() >= timeout {
                    return Ok(None);
                }
                if let Ok(resp) = client.get(&session_url).send().await
                    && resp.status().is_success()
                    && let Ok(state) = resp.json::<GetSessionResponse>().await
                {
                    match state.status {
                        SessionStatus::Responded
                        | SessionStatus::Cancelled
                        | SessionStatus::Expired => return Ok(Some(state)),
                        _ => {}
                    }
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        }
    }
}
