use std::future::Future;
use std::time::Duration;

use auths_core::pairing::{
    CreateSessionRequest, CreateSessionResponse, GetConfirmationResponse, GetSessionResponse,
    SessionStatus, SubmitConfirmationRequest, SubmitResponseRequest,
};
use auths_core::ports::network::NetworkError;
use auths_core::ports::pairing::PairingRelayClient;

use crate::default_http_client;
use crate::error::{map_reqwest_error, map_status_error};
use crate::ssrf::{SsrfBlocked, guard_registry_url};

const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Translate a refused registry URL into a `NetworkError` for the network port.
fn map_ssrf_error(err: SsrfBlocked) -> NetworkError {
    NetworkError::InvalidResponse {
        detail: err.to_string(),
    }
}

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
        let guard = guard_registry_url(registry_url).map_err(map_ssrf_error);
        let url = format!("{}/v1/pairing/sessions", registry_url.trim_end_matches('/'));
        let endpoint = registry_url.to_string();
        // Serialize JSON at call time so the future owns the request bytes.
        let req = self.client.post(&url).json(request);

        async move {
            guard?;
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
        let guard = guard_registry_url(registry_url).map_err(map_ssrf_error);
        let url = format!(
            "{}/v1/pairing/sessions/{}",
            registry_url.trim_end_matches('/'),
            session_id
        );
        let endpoint = registry_url.to_string();
        let req = self.client.get(&url);

        async move {
            guard?;
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
        use auths_pairing_protocol::lookup_auth::{LOOKUP_PATH, build_lookup_authorization};
        let guard = guard_registry_url(registry_url).map_err(map_ssrf_error);
        let url = format!("{}{}", registry_url.trim_end_matches('/'), LOOKUP_PATH);
        let endpoint = registry_url.to_string();

        // Prove knowledge of the short code without sending it in the clear: HMAC
        // a canonical GET with a key derived from the code. The timestamp and a
        // fresh random nonce bind the request against replay.
        #[allow(clippy::disallowed_methods)]
        // wire boundary: no clock is injected into the relay client
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let mut nonce = [0u8; 16];
        {
            use rand::RngCore;
            let mut rng = rand::rngs::OsRng;
            rng.fill_bytes(&mut nonce);
        }
        let req = self.client.get(&url).header(
            "Authorization",
            build_lookup_authorization(code, ts, &nonce),
        );

        async move {
            guard?;
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
        let guard = guard_registry_url(registry_url).map_err(map_ssrf_error);
        let url = format!(
            "{}/v1/pairing/sessions/{}/response",
            registry_url.trim_end_matches('/'),
            session_id
        );
        let endpoint = registry_url.to_string();
        let req = self.client.post(&url).json(response);

        async move {
            guard?;
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

    fn submit_confirmation(
        &self,
        registry_url: &str,
        session_id: &str,
        request: &SubmitConfirmationRequest,
    ) -> impl Future<Output = Result<(), NetworkError>> + Send {
        let guard = guard_registry_url(registry_url).map_err(map_ssrf_error);
        let url = format!(
            "{}/v1/pairing/sessions/{}/confirm",
            registry_url.trim_end_matches('/'),
            session_id
        );
        let endpoint = registry_url.to_string();
        let req = self.client.post(&url).json(request);

        async move {
            guard?;
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

    fn get_confirmation(
        &self,
        registry_url: &str,
        session_id: &str,
    ) -> impl Future<Output = Result<GetConfirmationResponse, NetworkError>> + Send {
        let guard = guard_registry_url(registry_url).map_err(map_ssrf_error);
        let url = format!(
            "{}/v1/pairing/sessions/{}/confirmation",
            registry_url.trim_end_matches('/'),
            session_id
        );
        let endpoint = registry_url.to_string();
        let req = self.client.get(&url);

        async move {
            guard?;
            let resp = req
                .send()
                .await
                .map_err(|e| map_reqwest_error(e, &endpoint))?;
            if !resp.status().is_success() {
                return Err(map_status_error(resp.status().as_u16(), &url));
            }
            resp.json::<GetConfirmationResponse>().await.map_err(|e| {
                NetworkError::InvalidResponse {
                    detail: e.to_string(),
                }
            })
        }
    }

    fn wait_for_confirmation(
        &self,
        registry_url: &str,
        session_id: &str,
        timeout: Duration,
    ) -> impl Future<Output = Result<Option<GetConfirmationResponse>, NetworkError>> + Send {
        let guard = guard_registry_url(registry_url).map_err(map_ssrf_error);
        let url = format!(
            "{}/v1/pairing/sessions/{}/confirmation",
            registry_url.trim_end_matches('/'),
            session_id
        );
        let endpoint = registry_url.to_string();
        let client = self.client.clone();

        async move {
            guard?;
            let deadline = tokio::time::Instant::now() + timeout;
            loop {
                let resp = client
                    .get(&url)
                    .send()
                    .await
                    .map_err(|e| map_reqwest_error(e, &endpoint))?;
                if resp.status().is_success() {
                    let confirmation =
                        resp.json::<GetConfirmationResponse>().await.map_err(|e| {
                            NetworkError::InvalidResponse {
                                detail: e.to_string(),
                            }
                        })?;
                    if confirmation.aborted || confirmation.encrypted_attestation.is_some() {
                        return Ok(Some(confirmation));
                    }
                }
                if tokio::time::Instant::now() >= deadline {
                    return Ok(None);
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
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
        let guard = guard_registry_url(registry_url).map_err(map_ssrf_error);
        // Clone the client so the future owns it without borrowing &self.
        let client = self.client.clone();

        async move {
            guard?;
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
